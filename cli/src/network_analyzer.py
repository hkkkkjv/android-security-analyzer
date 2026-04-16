"""
Анализатор конфигурационного файла network_security_config.xml и поиск insecure HTTP.

Проверяет:
- cleartextTrafficPermitted="true" (CRITICAL)
- certificates src="user" в trust-anchors (HIGH/MEDIUM)
- Отсутствие или некорректный pin-set для доменов (HIGH/MEDIUM)
- HTTP URL в коде, ресурсах, Retrofit, WebView (HIGH/MEDIUM)
- Ошибки парсинга XML (HIGH)
- Отсутствие файла конфигурации (MEDIUM)

Использует xml_utils для точного определения номеров строк уязвимостей.
"""

import xml.etree.ElementTree as ET
import os
import re
from typing import List, Dict, Optional
from pathlib import Path

from constants import (
    VulnerabilityTemplates,
    HttpPatterns,
    format_location,
    SEVERITY_ORDER
)
from xml_utils import parse_xml_with_linenumbers, get_element_line_number
from models import Vulnerability


# =============================================================================
# NetworkSecurityConfigAnalyzer
# =============================================================================

class NetworkSecurityConfigAnalyzer:
    """
    Статический анализатор network_security_config.xml.
    """
    
    def analyze(self, project_path: str) -> List[Vulnerability]:
        """Анализирует network_security_config.xml на уязвимости."""
        project_path = os.path.normpath(project_path)
        config_path = os.path.join(
            project_path, "app", "src", "main", "res", "xml", "network_security_config.xml"
        )
        
        if not os.path.exists(config_path):
            return [Vulnerability(
                id=VulnerabilityTemplates.MISSING_NSC["id"],
                severity=VulnerabilityTemplates.MISSING_NSC["severity"],
                cvss_score=VulnerabilityTemplates.MISSING_NSC["cvss_score"],
                category=VulnerabilityTemplates.MISSING_NSC["category"],
                description=VulnerabilityTemplates.MISSING_NSC["description"],
                location=config_path,
                recommendation=VulnerabilityTemplates.MISSING_NSC["recommendation"]
            )]
        
        try:
            tree, line_mapping = parse_xml_with_linenumbers(config_path)
            root = tree.getroot()
        except ET.ParseError as e:
            return [Vulnerability(
                id=VulnerabilityTemplates.PARSE_ERROR_NSC["id"].format(error=str(e)),
                severity=VulnerabilityTemplates.PARSE_ERROR_NSC["severity"],
                cvss_score=VulnerabilityTemplates.PARSE_ERROR_NSC["cvss_score"],
                category=VulnerabilityTemplates.PARSE_ERROR_NSC["category"],
                description=VulnerabilityTemplates.PARSE_ERROR_NSC["description"].format(error=str(e)),
                location=config_path,
                recommendation=VulnerabilityTemplates.PARSE_ERROR_NSC["recommendation"]
            )]
        
        results = []
        results += self._check_base_config(root, config_path, line_mapping)
        results += self._check_domain_configs(root, config_path, line_mapping)
        results.sort(key=lambda v: SEVERITY_ORDER.get(v.severity, 99))
        return results
    
    def _check_base_config(self, root: ET.Element, config_path: str, 
                          line_mapping: Dict[ET.Element, int]) -> List[Vulnerability]:
        """Проверяет base-config на уязвимости."""
        results = []
        base_config = root.find("base-config")
        
        if base_config is None:
            return results
        
        base_lineno = get_element_line_number(base_config, line_mapping)
        
        if base_config.get("cleartextTrafficPermitted", "false").lower() == "true":
            results.append(Vulnerability(
                id=VulnerabilityTemplates.CLEARTEXT_BASE["id"],
                severity=VulnerabilityTemplates.CLEARTEXT_BASE["severity"],
                cvss_score=VulnerabilityTemplates.CLEARTEXT_BASE["cvss_score"],
                category=VulnerabilityTemplates.CLEARTEXT_BASE["category"],
                description=VulnerabilityTemplates.CLEARTEXT_BASE["description"],
                location=format_location(config_path, base_lineno),
                recommendation=VulnerabilityTemplates.CLEARTEXT_BASE["recommendation"]
            ))
        
        trust_anchors = base_config.find("trust-anchors")
        if trust_anchors is not None:
            trust_lineno = get_element_line_number(trust_anchors, line_mapping)
            for cert in trust_anchors.findall("certificates"):
                if cert.get("src") == "user":
                    cert_lineno = get_element_line_number(cert, line_mapping, default=trust_lineno)
                    results.append(Vulnerability(
                        id=VulnerabilityTemplates.USER_CERTS_BASE["id"],
                        severity=VulnerabilityTemplates.USER_CERTS_BASE["severity"],
                        cvss_score=VulnerabilityTemplates.USER_CERTS_BASE["cvss_score"],
                        category=VulnerabilityTemplates.USER_CERTS_BASE["category"],
                        description=VulnerabilityTemplates.USER_CERTS_BASE["description"],
                        location=format_location(config_path, cert_lineno),
                        recommendation=VulnerabilityTemplates.USER_CERTS_BASE["recommendation"]
                    ))
        
        return results
    
    def _check_domain_configs(self, root: ET.Element, config_path: str,
                             line_mapping: Dict[ET.Element, int]) -> List[Vulnerability]:
        """Проверяет domain-config элементы на уязвимости."""
        results = []
        
        for domain_config in root.findall("domain-config"):
            domains = [d.text.strip() for d in domain_config.findall("domain") if d.text]
            domain_str = ", ".join(domains) if domains else "неизвестный домен"
            config_lineno = get_element_line_number(domain_config, line_mapping)
            
            if domain_config.get("cleartextTrafficPermitted", "false").lower() == "true":
                results.append(Vulnerability(
                    id=VulnerabilityTemplates.CLEARTEXT_DOMAIN["id"],
                    severity=VulnerabilityTemplates.CLEARTEXT_DOMAIN["severity"],
                    cvss_score=VulnerabilityTemplates.CLEARTEXT_DOMAIN["cvss_score"],
                    category=VulnerabilityTemplates.CLEARTEXT_DOMAIN["category"],
                    description=VulnerabilityTemplates.CLEARTEXT_DOMAIN["description"].format(domain=domain_str),
                    location=format_location(config_path, config_lineno),
                    recommendation=VulnerabilityTemplates.CLEARTEXT_DOMAIN["recommendation"].format(domain=domain_str)
                ))
            
            trust_anchors = domain_config.find("trust-anchors")
            if trust_anchors is not None:
                for cert in trust_anchors.findall("certificates"):
                    if cert.get("src") == "user":
                        cert_lineno = get_element_line_number(cert, line_mapping, default=config_lineno)
                        results.append(Vulnerability(
                            id=VulnerabilityTemplates.USER_CERTS_DOMAIN["id"],
                            severity=VulnerabilityTemplates.USER_CERTS_DOMAIN["severity"],
                            cvss_score=VulnerabilityTemplates.USER_CERTS_DOMAIN["cvss_score"],
                            category=VulnerabilityTemplates.USER_CERTS_DOMAIN["category"],
                            description=VulnerabilityTemplates.USER_CERTS_DOMAIN["description"].format(domain=domain_str),
                            location=format_location(config_path, cert_lineno),
                            recommendation=VulnerabilityTemplates.USER_CERTS_DOMAIN["recommendation"].format(domain=domain_str)
                        ))
            
            pin_set = domain_config.find("pin-set")
            pin_lineno = get_element_line_number(pin_set, line_mapping, default=config_lineno) if pin_set is not None else config_lineno
            
            if pin_set is None:
                results.append(Vulnerability(
                    id=VulnerabilityTemplates.MISSING_PINNING["id"],
                    severity=VulnerabilityTemplates.MISSING_PINNING["severity"],
                    cvss_score=VulnerabilityTemplates.MISSING_PINNING["cvss_score"],
                    category=VulnerabilityTemplates.MISSING_PINNING["category"],
                    description=VulnerabilityTemplates.MISSING_PINNING["description"].format(domain=domain_str),
                    location=format_location(config_path, pin_lineno),
                    recommendation=VulnerabilityTemplates.MISSING_PINNING["recommendation"].format(domain=domain_str)
                ))
            else:
                pins = pin_set.findall("pin")
                
                if len(pins) == 0:
                    results.append(Vulnerability(
                        id=VulnerabilityTemplates.EMPTY_PINNING["id"],
                        severity=VulnerabilityTemplates.EMPTY_PINNING["severity"],
                        cvss_score=VulnerabilityTemplates.EMPTY_PINNING["cvss_score"],
                        category=VulnerabilityTemplates.EMPTY_PINNING["category"],
                        description=VulnerabilityTemplates.EMPTY_PINNING["description"].format(domain=domain_str),
                        location=format_location(config_path, pin_lineno),
                        recommendation=VulnerabilityTemplates.EMPTY_PINNING["recommendation"].format(domain=domain_str)
                    ))
                elif len(pins) == 1:
                    pin_lineno = get_element_line_number(pins[0], line_mapping, default=pin_lineno)
                    results.append(Vulnerability(
                        id=VulnerabilityTemplates.SINGLE_PIN["id"],
                        severity=VulnerabilityTemplates.SINGLE_PIN["severity"],
                        cvss_score=VulnerabilityTemplates.SINGLE_PIN["cvss_score"],
                        category=VulnerabilityTemplates.SINGLE_PIN["category"],
                        description=VulnerabilityTemplates.SINGLE_PIN["description"].format(domain=domain_str),
                        location=format_location(config_path, pin_lineno),
                        recommendation=VulnerabilityTemplates.SINGLE_PIN["recommendation"].format(domain=domain_str)
                    ))
        
        return results


# =============================================================================
# InsecureHttpAnalyzer
# =============================================================================

class InsecureHttpAnalyzer:
    """
    Ищет небезопасные http:// ссылки в исходном коде и ресурсах Android-проекта.
    
    Проверяет:
    - strings.xml (все values*)
    - Kotlin/Java исходные файлы
    - Retrofit @GET/@POST аннотации
    - WebView.loadUrl() вызовы
    """
    
    def analyze(self, project_path: str) -> List[Vulnerability]:
        """Анализирует проект на наличие insecure HTTP URL."""
        project_path = os.path.normpath(project_path)
        results: List[Vulnerability] = []
        
        results += self._check_strings_xml(project_path)
        results += self._check_source_files(project_path)
        
        results.sort(key=lambda v: SEVERITY_ORDER.get(v.severity, 99))
        return results
    
    def _check_strings_xml(self, project_path: str) -> List[Vulnerability]:
        """Проверяет strings.xml на наличие HTTP URL."""
        results = []
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
        """Парсит отдельный strings.xml файл."""
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
                    id=VulnerabilityTemplates.HTTP_IN_STRINGS["id"],
                    severity=VulnerabilityTemplates.HTTP_IN_STRINGS["severity"],
                    cvss_score=VulnerabilityTemplates.HTTP_IN_STRINGS["cvss_score"],
                    category=VulnerabilityTemplates.HTTP_IN_STRINGS["category"],
                    description=VulnerabilityTemplates.HTTP_IN_STRINGS["description"].format(name=name, url=value),
                    location=format_location(strings_path, i),
                    recommendation=VulnerabilityTemplates.HTTP_IN_STRINGS["recommendation"].format(name=name)
                ))
        
        return results
    
    def _check_source_files(self, project_path: str) -> List[Vulnerability]:
        """Проверяет исходные файлы .kt/.java на HTTP URL."""
        results = []
        
        for src_dir_name in ("java", "kotlin"):
            src_root = Path(project_path) / "app" / "src" / "main" / src_dir_name
            if not src_root.exists():
                continue
            for filepath in src_root.rglob("*"):
                if filepath.suffix in (".kt", ".java"):
                    results += self._check_source_file(str(filepath))
        
        return results
    
    def _check_source_file(self, filepath: str) -> List[Vulnerability]:
        """Анализирует отдельный исходный файл."""
        results = []
        
        try:
            with open(filepath, encoding="utf-8") as f:
                lines = f.readlines()
        except (OSError, UnicodeDecodeError):
            return []
        
        for line_num, line in enumerate(lines, start=1):
            stripped = line.strip()
            
            # Пропускаем комментарии
            if stripped.startswith("//") or stripped.startswith("*"):
                continue
            
            # Retrofit аннотации
            if HttpPatterns.RETROFIT_ANNOTATION.search(line):
                url = self._extract_url(line)
                results.append(Vulnerability(
                    id=VulnerabilityTemplates.HTTP_IN_RETROFIT["id"],
                    severity=VulnerabilityTemplates.HTTP_IN_RETROFIT["severity"],
                    cvss_score=VulnerabilityTemplates.HTTP_IN_RETROFIT["cvss_score"],
                    category=VulnerabilityTemplates.HTTP_IN_RETROFIT["category"],
                    description=VulnerabilityTemplates.HTTP_IN_RETROFIT["description"].format(url=url),
                    location=format_location(filepath, line_num),
                    recommendation=VulnerabilityTemplates.HTTP_IN_RETROFIT["recommendation"],
                    code_snippet=stripped
                ))
                continue
            
            # WebView.loadUrl
            if HttpPatterns.WEBVIEW_LOAD_URL.search(line):
                url = self._extract_url(line)
                results.append(Vulnerability(
                    id=VulnerabilityTemplates.HTTP_IN_WEBVIEW["id"],
                    severity=VulnerabilityTemplates.HTTP_IN_WEBVIEW["severity"],
                    cvss_score=VulnerabilityTemplates.HTTP_IN_WEBVIEW["cvss_score"],
                    category=VulnerabilityTemplates.HTTP_IN_WEBVIEW["category"],
                    description=VulnerabilityTemplates.HTTP_IN_WEBVIEW["description"].format(url=url),
                    location=format_location(filepath, line_num),
                    recommendation=VulnerabilityTemplates.HTTP_IN_WEBVIEW["recommendation"],
                    code_snippet=stripped
                ))
                continue
            
            # Обычные строки с HTTP
            if HttpPatterns.HTTP_IN_STRING.search(line):
                url = self._extract_url(line)
                results.append(Vulnerability(
                    id=VulnerabilityTemplates.HTTP_IN_CODE["id"],
                    severity=VulnerabilityTemplates.HTTP_IN_CODE["severity"],
                    cvss_score=VulnerabilityTemplates.HTTP_IN_CODE["cvss_score"],
                    category=VulnerabilityTemplates.HTTP_IN_CODE["category"],
                    description=VulnerabilityTemplates.HTTP_IN_CODE["description"].format(url=url),
                    location=format_location(filepath, line_num),
                    recommendation=VulnerabilityTemplates.HTTP_IN_CODE["recommendation"],
                    code_snippet=stripped
                ))
        
        return results
    
    def _extract_url(self, line: str) -> str:
        """Извлекает URL из строки кода."""
        match = HttpPatterns.URL_EXTRACTOR.search(line)
        return match.group(0) if match else "http://..."