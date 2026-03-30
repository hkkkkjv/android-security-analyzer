import xml.etree.ElementTree as ET
import os
import re
from dataclasses import dataclass
from typing import List
from pathlib import Path


@dataclass
class Vulnerability:
    id: str
    severity: str
    cvss_score: float
    category: str
    description: str
    location: str
    recommendation: str


class NetworkSecurityConfigAnalyzer:

    SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}

    def analyze(self, project_path: str) -> List[Vulnerability]:
        project_path = os.path.normpath(project_path)
        config_path = os.path.join(
            project_path, "app", "src", "main", "res", "xml", "network_security_config.xml"
        )

        if not os.path.exists(config_path):
            return [Vulnerability(
                id="MISSING_NSC_001",
                severity="MEDIUM",
                cvss_score=5.3,
                category="Network Security Config",
                description="Файл network_security_config.xml не найден. Приложение использует настройки Android по умолчанию.",
                location=config_path,
                recommendation="Создайте network_security_config.xml и укажите его в AndroidManifest.xml через android:networkSecurityConfig."
            )]

        try:
            tree = ET.parse(config_path)
            root = tree.getroot()
        except ET.ParseError as e:
            return [Vulnerability(
                id="PARSE_ERROR_001",
                severity="HIGH",
                cvss_score=0.0,
                category="Parse Error",
                description=f"Не удалось разобрать XML: {e}",
                location=config_path,
                recommendation="Исправьте синтаксические ошибки в XML файле."
            )]

        results = []
        results += self._check_base_config(root, config_path)
        results += self._check_domain_configs(root, config_path)
        results.sort(key=lambda v: self.SEVERITY_ORDER.get(v.severity, 99))
        return results

    def _check_base_config(self, root: ET.Element, config_path: str) -> List[Vulnerability]:
        results = []
        base_config = root.find("base-config")

        if base_config is None:
            return results

        if base_config.get("cleartextTrafficPermitted", "false").lower() == "true":
            results.append(Vulnerability(
                id="CLEARTEXT_BASE_001",
                severity="CRITICAL",
                cvss_score=9.8,
                category="Insecure Communication",
                description="cleartextTrafficPermitted=\"true\" в base-config разрешает незашифрованный HTTP для всего приложения.",
                location=config_path,
                recommendation="Установите cleartextTrafficPermitted=\"false\" и используйте HTTPS для всех соединений."
            ))

        trust_anchors = base_config.find("trust-anchors")
        if trust_anchors is not None:
            for cert in trust_anchors.findall("certificates"):
                if cert.get("src") == "user":
                    results.append(Vulnerability(
                        id="USER_CERTS_001",
                        severity="MEDIUM",
                        cvss_score=5.9,
                        category="Insecure Configuration",
                        description="base-config доверяет пользовательским сертификатам (src=\"user\"). Позволяет перехватывать HTTPS-трафик.",
                        location=config_path,
                        recommendation="Удалите <certificates src=\"user\"/> из base-config. Используйте только системные сертификаты или certificate pinning."
                    ))

        return results

    def _check_domain_configs(self, root: ET.Element, config_path: str) -> List[Vulnerability]:
        results = []

        for domain_config in root.findall("domain-config"):
            domains = [d.text.strip() for d in domain_config.findall("domain") if d.text]
            domain_str = ", ".join(domains) if domains else "неизвестный домен"

            if domain_config.get("cleartextTrafficPermitted", "false").lower() == "true":
                results.append(Vulnerability(
                    id="CLEARTEXT_DOMAIN_001",
                    severity="HIGH",
                    cvss_score=7.5,
                    category="Insecure Communication",
                    description=f"cleartextTrafficPermitted=\"true\" разрешён для домена: {domain_str}.",
                    location=config_path,
                    recommendation=f"Уберите cleartextTrafficPermitted=\"true\" для {domain_str} и переведите API на HTTPS."
                ))

            # Проверка user-сертификатов на уровне domain-config
            trust_anchors = domain_config.find("trust-anchors")
            if trust_anchors is not None:
                for cert in trust_anchors.findall("certificates"):
                    if cert.get("src") == "user":
                        results.append(Vulnerability(
                            id="USER_CERTS_DOMAIN_001",
                            severity="HIGH",
                            cvss_score=7.4,
                            category="Insecure Configuration",
                            description=f"domain-config доверяет пользовательским сертификатам для домена: {domain_str}.",
                            location=config_path,
                            recommendation=f"Удалите <certificates src=\"user\"/> из domain-config для {domain_str}."
                        ))

            pin_set = domain_config.find("pin-set")

            if pin_set is None:
                results.append(Vulnerability(
                    id="MISSING_PINNING_001",
                    severity="HIGH",
                    cvss_score=7.4,
                    category="Certificate Pinning",
                    description=f"Отсутствует <pin-set> для домена: {domain_str}. Уязвимость к Man-in-the-Middle атакам.",
                    location=config_path,
                    recommendation=f"Добавьте <pin-set> с SHA-256 хэшами сертификата для {domain_str}. Укажите резервный пин для ротации."
                ))
            else:
                pins = pin_set.findall("pin")

                if len(pins) == 0:
                    results.append(Vulnerability(
                        id="EMPTY_PINNING_001",
                        severity="HIGH",
                        cvss_score=7.4,
                        category="Certificate Pinning",
                        description=f"Тег <pin-set> присутствует, но не содержит ни одного <pin> для домена: {domain_str}.",
                        location=config_path,
                        recommendation=f"Добавьте хотя бы два <pin digest=\"SHA-256\"> в pin-set для {domain_str}: основной и резервный."
                    ))
                elif len(pins) == 1:
                    # Только один пин — риск при ротации сертификата
                    results.append(Vulnerability(
                        id="SINGLE_PIN_001",
                        severity="MEDIUM",
                        cvss_score=5.3,
                        category="Certificate Pinning",
                        description=f"В pin-set для домена {domain_str} указан только один пин. При ротации сертификата приложение перестанет работать.",
                        location=config_path,
                        recommendation=f"Добавьте резервный пин в pin-set для {domain_str} на случай замены сертификата."
                    ))

        return results


class InsecureHttpAnalyzer:
    """
    Ищет небезопасные http:// ссылки в исходном коде и ресурсах Android-проекта.
    Проверяет: strings.xml, Kotlin/Java файлы, аннотации Retrofit, вызовы WebView.
    """

    _HTTP_IN_STRING    = re.compile(r'["\']http://[^\s"\']+["\']')
    _RETROFIT_ANNOTATION = re.compile(
        r'@(?:GET|POST|PUT|DELETE|PATCH|HEAD)\s*\(\s*["\']http://[^\s"\']+["\']'
    )
    _WEBVIEW_LOAD_URL  = re.compile(r'\.loadUrl\s*\(\s*["\']http://[^\s"\']+["\']')

    def analyze(self, project_path: str) -> List[Vulnerability]:
        project_path = os.path.normpath(project_path)
        results = []
        results += self._check_strings_xml(project_path)
        results += self._check_source_files(project_path)
        return results

    def _check_strings_xml(self, project_path: str) -> List[Vulnerability]:
        results = []
        # Ищем все папки values* — values, values-v21, values-night и т.д.
        res_path = Path(project_path) / "app" / "src" / "main" / "res"
        if not res_path.exists():
            return results

        for values_dir in res_path.glob("values*"):
            strings_file = values_dir / "strings.xml"
            if not strings_file.exists():
                continue
            results += self._parse_strings_file(str(strings_file))

        return results

    def _parse_strings_file(self, strings_path: str) -> List[Vulnerability]:
        results = []
        try:
            tree = ET.parse(strings_path)
            root = tree.getroot()
        except ET.ParseError:
            return results

        for i, string_el in enumerate(root.findall("string"), start=1):
            value = string_el.text or ""
            if value.startswith("http://"):
                name = string_el.get("name", "unknown")
                results.append(Vulnerability(
                    id="HTTP_IN_STRINGS_001",
                    severity="MEDIUM",
                    cvss_score=5.3,
                    category="Insecure Communication",
                    description=f"Небезопасный HTTP URL в строковом ресурсе \"{name}\": {value}",
                    location=f"{strings_path}:{i}",
                    recommendation=f"Замените http:// на https:// в строковом ресурсе \"{name}\"."
                ))

        return results

    def _check_source_files(self, project_path: str) -> List[Vulnerability]:
        results = []
        # Проверяем и java/ и kotlin/ — оба встречаются в реальных проектах
        for src_dir_name in ("java", "kotlin"):
            src_root = Path(project_path) / "app" / "src" / "main" / src_dir_name
            if not src_root.exists():
                continue
            # Используем фильтр по суффиксу — rglob("*.{kt,java}") в Python не работает
            for filepath in src_root.rglob("*"):
                if filepath.suffix in (".kt", ".java"):
                    results += self._check_source_file(str(filepath))

        return results

    def _check_source_file(self, filepath: str) -> List[Vulnerability]:
        results = []

        try:
            with open(filepath, encoding="utf-8") as f:
                lines = f.readlines()
        except (OSError, UnicodeDecodeError):
            return []

        for line_num, line in enumerate(lines, start=1):
            stripped = line.strip()

            # Пропускаем строки-комментарии
            if stripped.startswith("//") or stripped.startswith("*"):
                continue

            if self._RETROFIT_ANNOTATION.search(line):
                url = self._extract_url(line)
                results.append(Vulnerability(
                    id="HTTP_IN_RETROFIT_001",
                    severity="HIGH",
                    cvss_score=7.5,
                    category="Insecure Communication",
                    description=f"Retrofit-аннотация содержит небезопасный HTTP URL: {url}",
                    location=f"{filepath}:{line_num}",
                    recommendation="Замените http:// на https:// в Retrofit-аннотации или используйте относительный путь с безопасным baseUrl."
                ))
                continue

            if self._WEBVIEW_LOAD_URL.search(line):
                url = self._extract_url(line)
                results.append(Vulnerability(
                    id="HTTP_IN_WEBVIEW_001",
                    severity="HIGH",
                    cvss_score=7.5,
                    category="Insecure Communication",
                    description=f"WebView.loadUrl() загружает страницу по незашифрованному HTTP: {url}",
                    location=f"{filepath}:{line_num}",
                    recommendation="Замените http:// на https:// в вызове WebView.loadUrl()."
                ))
                continue

            if self._HTTP_IN_STRING.search(line):
                url = self._extract_url(line)
                results.append(Vulnerability(
                    id="HTTP_IN_CODE_001",
                    severity="HIGH",
                    cvss_score=7.5,
                    category="Insecure Communication",
                    description=f"Небезопасный HTTP URL в исходном коде: {url}",
                    location=f"{filepath}:{line_num}",
                    recommendation="Замените http:// на https://. Для baseUrl Retrofit используйте строку начинающуюся с https://."
                ))

        return results

    def _extract_url(self, line: str) -> str:
        match = re.search(r'http://[^\s"\')\]]+', line)
        return match.group(0) if match else "http://..."
