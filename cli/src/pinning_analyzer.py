"""
Анализатор certificate pinning в исходном коде Android-приложений.

Ищет уязвимости, связанные с проверкой сертификатов:
- Опасные реализации X509TrustManager (TrustAll)
- HostnameVerifier, всегда возвращающий true
- Отсутствие CertificatePinner для доменов из network_security_config.xml
- Кастомные SSL-конфигурации с ослабленной проверкой
- Несоответствие между конфигом и кодом (домен защищён в NSC, но не в коде)

Модуль использует контекстный анализ: извлекает baseUrl из Retrofit-интерфейсов,
сопоставляет домены из конфигурации с их использованием в коде.
"""

import re
import os
from pathlib import Path
from typing import List, Set, Optional, Dict, Tuple
from dataclasses import dataclass

# Импорт констант и утилит
from constants import (
    PinningPatterns,
    HttpPatterns,
    VulnerabilityTemplates,
    format_location,
    extract_domain_from_url
)
from xml_utils import parse_xml_with_linenumbers, get_element_line_number


from models import Vulnerability

class CertificatePinningCodeAnalyzer:
    """
    Статический анализатор проверок сертификатов в исходном коде.
    
    Attributes:
        pinned_domains: Домены с настроенным pinning из network_security_config.xml
        retrofit_base_urls: Найденные baseUrl в Retrofit-конфигурациях
    """
    
    def __init__(self):
        """Инициализирует анализатор."""
        self.pinned_domains: Set[str] = set()
        self.retrofit_base_urls: Dict[str, str] = {}  # filepath -> base_url
    
    def analyze(self, project_path: str) -> List[Vulnerability]:
        """
        Точка входа: анализирует исходный код на уязвимости certificate pinning.
        
        Args:
            project_path: Путь к директории Android-проекта
        
        Returns:
            Список найденных уязвимостей, отсортированный по критичности
        """
        project_path = os.path.normpath(project_path)
        results: List[Vulnerability] = []
        
        # Шаг 1: Извлекаем домены с pinning из network_security_config.xml
        self.pinned_domains = self._extract_pinned_domains_from_config(project_path)
        
        # Шаг 2: Предварительный проход: собираем все baseUrl из Retrofit
        self._collect_retrofit_base_urls(project_path)
        
        # Шаг 3: Основной анализ исходных файлов
        for src_dir_name in ("java", "kotlin"):
            src_root = Path(project_path) / "app" / "src" / "main" / src_dir_name
            if not src_root.exists():
                continue
            for filepath in src_root.rglob("*"):
                if filepath.suffix in (".kt", ".java"):
                    results += self._analyze_file(str(filepath))
        
        # Сортировка по критичности
        from constants import SEVERITY_ORDER
        results.sort(key=lambda v: SEVERITY_ORDER.get(v.severity, 99))
        
        return results
    
    def _extract_pinned_domains_from_config(self, project_path: str) -> Set[str]:
        """
        Извлекает домены, для которых настроен <pin-set> в network_security_config.xml.
        
        Args:
            project_path: Путь к проекту
        
        Returns:
            Множество доменов с настроенным pinning
        """
        import xml.etree.ElementTree as ET
        
        config_path = Path(project_path) / "app" / "src" / "main" / "res" / "xml" / "network_security_config.xml"
        pinned_domains: Set[str] = set()
        
        if not config_path.exists():
            return pinned_domains
        
        try:
            tree, line_mapping = parse_xml_with_linenumbers(str(config_path))
            root = tree.getroot()
            
            for domain_config in root.findall(".//domain-config"):
                pin_set = domain_config.find("pin-set")
                if pin_set is not None:
                    domains = [d.text.strip() for d in domain_config.findall("domain") if d.text]
                    pinned_domains.update(domains)
                    
        except (ET.ParseError, OSError):
            pass  # Игнорируем ошибки — это задача другого анализатора
            
        return pinned_domains
    
    def _collect_retrofit_base_urls(self, project_path: str) -> None:
        """
        Предварительный сбор всех baseUrl из Retrofit-конфигураций.
        
        Позволяет сопоставлять домены из network_security_config.xml
        с их использованием в коде даже если URL задан через переменную.
        
        Args:
            project_path: Путь к проекту
        """
        for src_dir_name in ("java", "kotlin"):
            src_root = Path(project_path) / "app" / "src" / "main" / src_dir_name
            if not src_root.exists():
                continue
            for filepath in src_root.rglob("*"):
                if filepath.suffix in (".kt", ".java"):
                    self._extract_base_url_from_file(str(filepath))
    
    def _extract_base_url_from_file(self, filepath: str) -> None:
        """
        Извлекает baseUrl из файла с кодом.
        
        Args:
            filepath: Путь к исходному файлу
        """
        try:
            with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()
        except (OSError, UnicodeDecodeError):
            return
        
        # Ищем baseUrl в стиле Retrofit
        match = HttpPatterns.BASE_URL_PATTERN.search(content)
        if match:
            url = match.group(1)
            domain = extract_domain_from_url(url)
            if domain:
                self.retrofit_base_urls[filepath] = domain
    
    def _analyze_file(self, filepath: str) -> List[Vulnerability]:
        """
        Анализирует отдельный файл на уязвимости pinning.
        
        Args:
            filepath: Путь к исходному файлу
        
        Returns:
            Список уязвимостей в этом файле
        """
        results: List[Vulnerability] = []
        
        try:
            with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()
                lines = content.splitlines(keepends=True)
        except (OSError, UnicodeDecodeError):
            return results
        
        # 1. Проверка на TrustAll Manager
        results += self._check_trust_all(filepath, content, lines)
        
        # 2. Проверка на HostnameVerifier bypass
        results += self._check_hostname_bypass(filepath, content, lines)
        
        # 3. Проверка на кастомный sslSocketFactory
        results += self._check_custom_ssl_factory(filepath, content, lines)
        
        # 4. Проверка на CertificatePinner и количество пинов
        results += self._check_certificate_pinner(filepath, content, lines)
        results += self._check_missing_pinning_any(filepath, content, lines)

        # 5. Контекстный анализ: missing pinning для доменов из конфига
        results += self._check_missing_pinning_contextual(filepath, content, lines)
        
        return results
    
    def _check_trust_all(self, filepath: str, content: str, lines: List[str]) -> List[Vulnerability]:
        """
        Ищет опасные реализации X509TrustManager (TrustAll).
        
        Args:
            filepath: Путь к файлу
            content: Содержимое файла
            lines: Список строк файла
        
        Returns:
            Список уязвимостей типа TrustAll
        """
        results = []
        
        if not PinningPatterns.TRUST_MANAGER_CLASS.search(content):
            return results
        
        for match in PinningPatterns.EMPTY_TRUST_CHECK.finditer(content):
            method_content = match.group(0)
            # Если метод пустой или содержит только возврат без проверки
            if re.search(r'\{\s*\}', method_content) or re.search(r'return\s+[^;]*;?\s*\}', method_content):
                line_num = content[:match.start()].count('\n') + 1
                snippet = lines[line_num - 1].strip() if line_num <= len(lines) else ""
                
                results.append(Vulnerability(
                    id=VulnerabilityTemplates.PINNING_TRUST_ALL["id"],
                    severity=VulnerabilityTemplates.PINNING_TRUST_ALL["severity"],
                    cvss_score=VulnerabilityTemplates.PINNING_TRUST_ALL["cvss_score"],
                    category=VulnerabilityTemplates.PINNING_TRUST_ALL["category"],
                    description=VulnerabilityTemplates.PINNING_TRUST_ALL["description"],
                    location=format_location(filepath, line_num),
                    recommendation=VulnerabilityTemplates.PINNING_TRUST_ALL["recommendation"],
                    code_snippet=snippet
                ))
                break  # Одна уязвимость на файл достаточно
        
        return results

    def _check_missing_pinning_any(self, filepath: str, content: str, lines: List[str]) -> List[Vulnerability]:
	    """
	    Детектит использование доменов без ANY pinning (ни в конфиге, ни в коде).
	    
	    """
	    results = []
	    
	    # 1. Находим все домены с их позициями
	    domain_matches: Dict[str, re.Match] = {}
	    for match in HttpPatterns.HARDCODED_DOMAIN.finditer(content):
	        domain = match.group(1)
	        if domain and not domain.startswith("localhost") and not domain.startswith("127.0.0.1"):
	            if domain not in domain_matches:
	                domain_matches[domain] = match
	    
	    if not domain_matches:
	        return results
	    
	    # 2. Для КАЖДОГО домена проверяем, есть ли его pinning в этом файле
	    for domain, match in domain_matches.items():
	        # Ищем .add("этот_домен", ...) в содержимом файла
	        domain_pinner_pattern = rf'\.add\s*\(\s*["\']{re.escape(domain)}["\']\s*,\s*["\'](?:sha256/)?[A-Za-z0-9+/=]+["\']'
	        has_pinning_for_domain = bool(re.search(domain_pinner_pattern, content, re.IGNORECASE))
	        
	        if not has_pinning_for_domain:
	            line_num = content[:match.start()].count('\n') + 1
	            snippet = lines[line_num - 1].strip() if line_num <= len(lines) else ""
	            
	            results.append(Vulnerability(
	                id=VulnerabilityTemplates.PINNING_MISSING_ANY["id"],
	                severity=VulnerabilityTemplates.PINNING_MISSING_ANY["severity"],
	                cvss_score=VulnerabilityTemplates.PINNING_MISSING_ANY["cvss_score"],
	                category=VulnerabilityTemplates.PINNING_MISSING_ANY["category"],
	                description=VulnerabilityTemplates.PINNING_MISSING_ANY["description"].format(domain=domain),
	                location=format_location(filepath, line_num),
	                recommendation=VulnerabilityTemplates.PINNING_MISSING_ANY["recommendation"].format(domain=domain),
	                code_snippet=snippet
	            ))
	    
	    return results
    

    def _check_hostname_bypass(self, filepath: str, content: str, lines: List[str]) -> List[Vulnerability]:
        """
        Ищет HostnameVerifier, который всегда возвращает true.
        
        Args:
            filepath: Путь к файлу
            content: Содержимое файла
            lines: Список строк файла
        
        Returns:
            Список уязвимостей типа hostname bypass
        """
        results = []
        
        pattern = (PinningPatterns.HOSTNAME_VERIFIER_TRUE_KOTLIN.search(content) or 
                   PinningPatterns.HOSTNAME_VERIFIER_TRUE_JAVA.search(content))
        
        if pattern:
            line_num = content[:pattern.start()].count('\n') + 1
            snippet = lines[line_num - 1].strip() if line_num <= len(lines) else ""
            
            results.append(Vulnerability(
                id=VulnerabilityTemplates.PINNING_HOSTNAME_BYPASS["id"],
                severity=VulnerabilityTemplates.PINNING_HOSTNAME_BYPASS["severity"],
                cvss_score=VulnerabilityTemplates.PINNING_HOSTNAME_BYPASS["cvss_score"],
                category=VulnerabilityTemplates.PINNING_HOSTNAME_BYPASS["category"],
                description=VulnerabilityTemplates.PINNING_HOSTNAME_BYPASS["description"],
                location=format_location(filepath, line_num),
                recommendation=VulnerabilityTemplates.PINNING_HOSTNAME_BYPASS["recommendation"],
                code_snippet=snippet
            ))
        
        return results
    
    def _check_custom_ssl_factory(self, filepath: str, content: str, lines: List[str]) -> List[Vulnerability]:
        """
        Обнаруживает кастомный sslSocketFactory без явного CertificatePinner.
        
        Args:
            filepath: Путь к файлу
            content: Содержимое файла
            lines: Список строк файла
        
        Returns:
            Список уязвимостей типа custom SSL factory
        """
        results = []
        
        if PinningPatterns.CUSTOM_SSL_FACTORY.search(content):
            # Проверяем, есть ли при этом CertificatePinner
            if not PinningPatterns.CERT_PINNER_ADD_PIN.search(content):
                match = PinningPatterns.CUSTOM_SSL_FACTORY.search(content)
                line_num = content[:match.start()].count('\n') + 1 if match else 1
                snippet = lines[line_num - 1].strip() if line_num <= len(lines) else ""
                
                results.append(Vulnerability(
                    id=VulnerabilityTemplates.PINNING_CUSTOM_SSL["id"],
                    severity=VulnerabilityTemplates.PINNING_CUSTOM_SSL["severity"],
                    cvss_score=VulnerabilityTemplates.PINNING_CUSTOM_SSL["cvss_score"],
                    category=VulnerabilityTemplates.PINNING_CUSTOM_SSL["category"],
                    description=VulnerabilityTemplates.PINNING_CUSTOM_SSL["description"],
                    location=format_location(filepath, line_num),
                    recommendation=VulnerabilityTemplates.PINNING_CUSTOM_SSL["recommendation"],
                    code_snippet=snippet
                ))
        
        return results
    
    def _check_certificate_pinner(self, filepath: str, content: str, lines: List[str]) -> List[Vulnerability]:
        """
        Проверяет использование CertificatePinner и количество пинов.
        """
        results = []
        
        if not PinningPatterns.CERT_PINNER_ADD_PIN.search(content):
            return results
        
        pin_matches = PinningPatterns.PIN_HASH_PATTERN.findall(content)
        
        # Считаем общее количество пинов (каждый кортеж — один пин)
        pin_count = len(pin_matches)
        
        # Если только один пин — предупреждение о риске ротации
        if pin_count == 1:
            # Извлекаем домен из первого совпадения
            domain, pin_hash = pin_matches[0]
            
            match = PinningPatterns.CERT_PINNER_ADD_PIN.search(content)
            line_num = content[:match.start()].count('\n') + 1 if match else 1
            snippet = lines[line_num - 1].strip() if line_num <= len(lines) else ""
            
            results.append(Vulnerability(
                id=VulnerabilityTemplates.PINNING_SINGLE["id"],
                severity=VulnerabilityTemplates.PINNING_SINGLE["severity"],
                cvss_score=VulnerabilityTemplates.PINNING_SINGLE["cvss_score"],
                category=VulnerabilityTemplates.PINNING_SINGLE["category"],
                description=VulnerabilityTemplates.PINNING_SINGLE["description"].format(domain=domain),
                location=format_location(filepath, line_num),
                recommendation=VulnerabilityTemplates.PINNING_SINGLE["recommendation"].format(domain=domain),
                code_snippet=snippet
            ))
        
        return results
    
    def _check_missing_pinning_contextual(self, filepath: str, content: str, lines: List[str]) -> List[Vulnerability]:
        """
        Контекстный анализ: проверяет, используются ли в коде домены,
        которые должны иметь pinning согласно network_security_config.xml,
        но при этом не используется CertificatePinner.
        
        Учитывает:
        - Прямые упоминания доменов в строках
        - baseUrl из Retrofit-конфигураций
        - Хардкод-URL в коде
        
        Args:
            filepath: Путь к файлу
            content: Содержимое файла
            lines: Список строк файла
        
        Returns:
            Список уязвимостей типа missing pinning in code
        """
        results = []
        
        if not self.pinned_domains:
            return results
        
        # Проверяем, есть ли CertificatePinner в этом файле
        has_pinning = bool(PinningPatterns.CERT_PINNER_ADD_PIN.search(content))
        if has_pinning:
            return results  # Pinning уже реализован
        
        # Собираем домены, упомянутые в этом файле
        found_domains: Set[str] = set()
        
        # 1. Проверка через собранные baseUrl
        if filepath in self.retrofit_base_urls:
            base_domain = self.retrofit_base_urls[filepath]
            if base_domain in self.pinned_domains:
                found_domains.add(base_domain)
        
        # 2. Поиск прямых упоминаний доменов из конфига
        for domain in self.pinned_domains:
            domain_pattern = re.escape(domain)
            if re.search(rf'["\']https?://{domain_pattern}[/\s"\']', content, re.IGNORECASE):
                found_domains.add(domain)
        
        # Генерируем уязвимости для найденных доменов без pinning
        for domain in found_domains:
            # Находим строку с упоминанием домена для точного location
            match = re.search(rf'["\']https?://{re.escape(domain)}', content, re.IGNORECASE)
            line_num = content[:match.start()].count('\n') + 1 if match else 1
            snippet = lines[line_num - 1].strip() if line_num <= len(lines) else ""
            
            results.append(Vulnerability(
                id=VulnerabilityTemplates.PINNING_MISSING_CODE["id"],
                severity=VulnerabilityTemplates.PINNING_MISSING_CODE["severity"],
                cvss_score=VulnerabilityTemplates.PINNING_MISSING_CODE["cvss_score"],
                category=VulnerabilityTemplates.PINNING_MISSING_CODE["category"],
                description=VulnerabilityTemplates.PINNING_MISSING_CODE["description"].format(domain=domain),
                location=format_location(filepath, line_num),
                recommendation=VulnerabilityTemplates.PINNING_MISSING_CODE["recommendation"].format(domain=domain),
                code_snippet=snippet
            ))
        
        return results