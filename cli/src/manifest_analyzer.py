import xml.etree.ElementTree as ET
import os
from pathlib import Path
from typing import List, Optional
from dataclasses import dataclass

from models import Vulnerability

ANDROID_NS = "{http://schemas.android.com/apk/res/android}"

class AndroidManifestAnalyzer:
    """
    Анализирует AndroidManifest.xml на уязвимости сетевой безопасности.
    
    Учитывает Android XML namespace при чтении атрибутов.
    """

    def analyze(self, project_path: str) -> List[Vulnerability]:
        """Точка входа: анализирует манифест проекта."""
        project_path = os.path.normpath(project_path)
        manifest_path = Path(project_path) / "app" / "src" / "main" / "AndroidManifest.xml"
        
        if not manifest_path.exists():
            return [Vulnerability(
                id="MANIFEST_MISSING_001",
                severity="HIGH",
                cvss_score=7.0,
                category="Configuration",
                description="Файл AndroidManifest.xml не найден.",
                location=str(manifest_path),
                recommendation="Убедитесь, что проект имеет стандартную структуру Gradle."
            )]
        
        try:
            tree = ET.parse(str(manifest_path))
            root = tree.getroot()
        except ET.ParseError as e:
            return [Vulnerability(
                id="MANIFEST_PARSE_ERROR_001",
                severity="HIGH",
                cvss_score=7.0,
                category="Parse Error",
                description=f"Не удалось разобрать AndroidManifest.xml: {e}",
                location=str(manifest_path),
                recommendation="Исправьте синтаксические ошибки в манифесте."
            )]
        
        results = []
        results += self._check_cleartext_traffic(root, manifest_path)
        results += self._check_network_security_config_ref(root, manifest_path, project_path)
        results += self._check_permissions(root, manifest_path)
        
        return results

    def _check_cleartext_traffic(self, root: ET.Element, manifest_path: Path) -> List[Vulnerability]:
        """
        Проверяет android:usesCleartextTraffic в <application>.
        
        """
        results = []
        application = root.find("application")
        
        if application is None:
            return results
        
        cleartext = application.get(f"{ANDROID_NS}usesCleartextTraffic", "false").lower()
        
        if cleartext == "true":
            # Находим номер строки через поиск в исходном тексте
            lineno = self._find_element_line(manifest_path, "application")
            
            results.append(Vulnerability(
                id="MANIFEST_CLEARTEXT_001",
                severity="CRITICAL",
                cvss_score=9.8,
                category="Insecure Communication",
                description="android:usesCleartextTraffic=\"true\" в AndroidManifest.xml разрешает HTTP для всего приложения, переопределяя network_security_config.xml.",
                location=f"{manifest_path}:{lineno}",
                recommendation="Установите android:usesCleartextTraffic=\"false\" и используйте HTTPS. Настройте exceptions через network_security_config.xml при необходимости."
            ))
        
        return results

    def _check_network_security_config_ref(self, root: ET.Element, manifest_path: Path, project_path: str) -> List[Vulnerability]:
        """
        Проверяет, что android:networkSecurityConfig ссылается на существующий файл.
        
        """
        results = []
        application = root.find("application")
        
        if application is None:
            return results
        
        nsc_ref = application.get(f"{ANDROID_NS}networkSecurityConfig")
        
        if nsc_ref:
            # Ожидаемый путь: @xml/network_security_config → res/xml/network_security_config.xml
            expected_path = Path(project_path) / "app" / "src" / "main" / "res" / "xml" / "network_security_config.xml"
            if not expected_path.exists():
                lineno = self._find_element_line(manifest_path, "application")
                results.append(Vulnerability(
                    id="MANIFEST_NSC_BROKEN_REF_001",
                    severity="HIGH",
                    cvss_score=7.5,
                    category="Configuration",
                    description=f"android:networkSecurityConfig=\"{nsc_ref}\" указан в манифесте, но файл не найден по пути: {expected_path}",
                    location=f"{manifest_path}:{lineno}",
                    recommendation="Создайте файл network_security_config.xml или исправьте ссылку в android:networkSecurityConfig."
                ))
        else:
            # Предупреждение: манифест не ссылается на конфигурацию безопасности
            lineno = self._find_element_line(manifest_path, "application")
            results.append(Vulnerability(
                id="MANIFEST_NSC_MISSING_REF_002",
                severity="MEDIUM",
                cvss_score=5.3,
                category="Configuration",
                description="Атрибут android:networkSecurityConfig не указан в <application>. Приложение может использовать настройки по умолчанию.",
                location=f"{manifest_path}:{lineno}",
                recommendation="Добавьте android:networkSecurityConfig=\"@xml/network_security_config\" в <application> и создайте соответствующий файл."
            ))
        
        return results

    def _check_permissions(self, root: ET.Element, manifest_path: Path) -> List[Vulnerability]:
        """
        Проверяет наличие необходимых сетевых permissions.
        
        """
        results = []
        
        permissions = []
        for perm_elem in root.findall("uses-permission"):
            name = perm_elem.get(f"{ANDROID_NS}name")
            if name:
                permissions.append(name)
        
        # INTERNET permission обязателен для сетевых операций
        if "android.permission.INTERNET" not in permissions:
            lineno = self._find_element_line(manifest_path, "manifest")
            results.append(Vulnerability(
                id="MANIFEST_PERM_INTERNET_001",
                severity="LOW",
                cvss_score=3.1,
                category="Configuration",
                description="Отсутствует разрешение android.permission.INTERNET. Приложение не сможет выполнять сетевые запросы.",
                location=f"{manifest_path}:{lineno}",
                recommendation="Добавьте <uses-permission android:name=\"android.permission.INTERNET\" /> в манифест."
            ))
        
        # Опасные permissions (информационное предупреждение)
        dangerous_perms = {
            "android.permission.ACCESS_NETWORK_STATE": "Позволяет отслеживать состояние сети. Убедитесь, что это необходимо.",
            "android.permission.ACCESS_WIFI_STATE": "Позволяет получать информацию о Wi-Fi. Проверьте необходимость.",
        }
        
        for perm, warning in dangerous_perms.items():
            if perm in permissions:
                # Находим строку для конкретного permission
                lineno = self._find_permission_line(manifest_path, perm)
                results.append(Vulnerability(
                    id=f"MANIFEST_PERM_INFO_{perm.split('.')[-1].upper()}",
                    severity="LOW",
                    cvss_score=2.0,
                    category="Privacy",
                    description=f"Используется разрешение: {perm}. {warning}",
                    location=f"{manifest_path}:{lineno}",
                    recommendation="Убедитесь, что разрешение действительно необходимо и задокументировано в политике конфиденциальности."
                ))
        
        return results

    def _find_element_line(self, manifest_path: Path, tag: str) -> int:
        """
        Находит номер строки для тега в исходном файле (эвристика).
        
        Args:
            manifest_path: Путь к AndroidManifest.xml
            tag: Имя тега для поиска
        
        Returns:
            Номер строки (1-based) или 1 если не найдено
        """
        try:
            with open(manifest_path, "r", encoding="utf-8") as f:
                for i, line in enumerate(f, start=1):
                    if f"<{tag}" in line or f"<{tag}>" in line or f"<{tag} " in line:
                        return i
        except (OSError, UnicodeDecodeError):
            pass
        return 1

    def _find_permission_line(self, manifest_path: Path, permission_name: str) -> int:
        """
        Находит номер строки для конкретного uses-permission.
        
        Args:
            manifest_path: Путь к AndroidManifest.xml
            permission_name: Полное имя разрешения (напр. "android.permission.INTERNET")
        
        Returns:
            Номер строки (1-based) или 1 если не найдено
        """
        try:
            with open(manifest_path, "r", encoding="utf-8") as f:
                for i, line in enumerate(f, start=1):
                    if "uses-permission" in line and permission_name in line:
                        return i
        except (OSError, UnicodeDecodeError):
            pass
        return 1