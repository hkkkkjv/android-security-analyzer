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
        
        # 1. Проверка на TrustAll Manager (именованные классы)
        results += self._check_trust_all(filepath, content, lines)
        
        # 2. Проверка на анонимные TrustManager
        results += self._check_anonymous_trust_all(filepath, content, lines)
        
        # 3. Проверка на HostnameVerifier bypass
        results += self._check_hostname_bypass(filepath, content, lines)
        
        # 4. Проверка на кастомный sslSocketFactory
        results += self._check_custom_ssl_factory(filepath, content, lines)
        
        # 5. Проверка на CertificatePinner и количество пинов
        results += self._check_certificate_pinner(filepath, content, lines)
        
        # 6. НОВОЕ: Проверка на OkHttpClient без certificatePinner
        results += self._check_missing_pinning_in_client(filepath, content, lines)
        
        # 7. Проверка на отсутствие pinning для доменов
        results += self._check_missing_pinning_any(filepath, content, lines)

        # 8. Контекстный анализ
        results += self._check_missing_pinning_contextual(filepath, content, lines)
        
        return results
    
    def _check_trust_all(self, filepath: str, content: str, lines: List[str]) -> List[Vulnerability]:
        """
        Ищет опасные реализации X509TrustManager (TrustAll).
        Создаёт отдельную уязвимость для каждого пустого метода.
        """
        results = []
        
        # Проверяем, что класс реализует X509TrustManager
        if not re.search(r'class\s+\w+\s+implements\s+[^{]*X509TrustManager', content):
            return results
        
        # Ищем пустые методы checkServerTrusted и checkClientTrusted
        method_pattern = re.compile(
            r'(?:public\s+)?void\s+(checkServerTrusted|checkClientTrusted)\s*\([^)]*\)'
            r'(?:\s*throws\s+CertificateException)?\s*\{([^}]*)\}',
            re.DOTALL
        )
        
        for match in method_pattern.finditer(content):
            method_name = match.group(1)
            body = match.group(2).strip()
            
            # Пустое тело или только комментарии
            if not body or re.match(r'^\s*(?://[^\n]*\s*)*$', body):
                line_num = content[:match.start()].count('\n') + 1
                snippet = lines[line_num - 1].strip() if line_num <= len(lines) else ""
                
                results.append(Vulnerability(
                    id=VulnerabilityTemplates.PINNING_TRUST_ALL["id"],
                    severity=VulnerabilityTemplates.PINNING_TRUST_ALL["severity"],
                    cvss_score=VulnerabilityTemplates.PINNING_TRUST_ALL["cvss_score"],
                    category=VulnerabilityTemplates.PINNING_TRUST_ALL["category"],
                    description=f"Метод {method_name}() в X509TrustManager имеет пустую реализацию. Это отключает проверку {'клиентских' if 'Client' in method_name else 'серверных'} сертификатов и делает приложение уязвимым к MITM-атакам.",
                    location=format_location(filepath, line_num),
                    recommendation=f"Реализуйте корректную проверку {'клиентских' if 'Client' in method_name else 'серверных'} сертификатов в {method_name}() или используйте стандартный TrustManager.",
                    code_snippet=snippet
                ))
        
        return results

    def _check_anonymous_trust_all(self, filepath: str, content: str, lines: List[str]) -> List[Vulnerability]:
        """
        Ищет анонимные реализации X509TrustManager с пустыми методами проверки.
        
        Поддерживает:
        - Kotlin: object : X509TrustManager { ... }
        - Java: new X509TrustManager() { ... }
        - Kotlin: object : X509TrustManager внутри sslSocketFactory()
        """
        results = []
        
        # Паттерн 1: Kotlin анонимный объект
        # Ищет: object : X509TrustManager { ... }
        kotlin_pattern = re.compile(
            r'object\s*:\s*X509TrustManager\s*\{',
            re.IGNORECASE
        )
        
        # Паттерн 2: Java анонимный класс
        # Ищет: new X509TrustManager() { ... }
        java_pattern = re.compile(
            r'new\s+X509TrustManager\s*\(\s*\)\s*\{',
            re.IGNORECASE
        )
        
        # Ищем любое из двух совпадений
        match = kotlin_pattern.search(content) or java_pattern.search(content)
        if not match:
            return results
        
        # Находим позицию начала анонимного класса
        start_pos = match.start()
        line_num = content[:start_pos].count('\n') + 1
        
        # Извлекаем тело анонимного класса (до соответствующей закрывающей скобки)
        # Ищем все методы checkClientTrusted и checkServerTrusted
        body_start = match.end()
        brace_count = 1
        body_end = body_start
        
        while body_end < len(content) and brace_count > 0:
            if content[body_end] == '{':
                brace_count += 1
            elif content[body_end] == '}':
                brace_count -= 1
            body_end += 1
        
        body = content[body_start:body_end]
        
        # Проверяем, есть ли пустые методы проверки
        method_pattern = re.compile(
            r'(?:override\s+)?fun\s+(?:checkServerTrusted|checkClientTrusted)\s*\([^)]*\)[^{]*\{([^}]*)\}',
            re.DOTALL
        )
        
        empty_methods = []
        for method_match in method_pattern.finditer(body):
            method_body = method_match.group(1).strip()
            # Пустое тело или только комментарии
            if not method_body or re.match(r'^\s*(?://[^\n]*\s*)*$', method_body):
                method_name = "checkServerTrusted" if "checkServerTrusted" in method_match.group(0) else "checkClientTrusted"
                empty_methods.append(method_name)
        
        # Также проверяем Java-синтаксис методов
        java_method_pattern = re.compile(
            r'(?:public\s+)?void\s+(?:checkServerTrusted|checkClientTrusted)\s*\([^)]*\)[^{]*\{([^}]*)\}',
            re.DOTALL
        )
        
        for method_match in java_method_pattern.finditer(body):
            method_body = method_match.group(1).strip()
            if not method_body or re.match(r'^\s*(?://[^\n]*\s*)*$', method_body):
                method_name = "checkServerTrusted" if "checkServerTrusted" in method_match.group(0) else "checkClientTrusted"
                if method_name not in empty_methods:
                    empty_methods.append(method_name)
        
        if empty_methods:
            snippet = lines[line_num - 1].strip() if line_num <= len(lines) else ""
            
            results.append(Vulnerability(
                id=VulnerabilityTemplates.PINNING_TRUST_ALL["id"],
                severity=VulnerabilityTemplates.PINNING_TRUST_ALL["severity"],
                cvss_score=VulnerabilityTemplates.PINNING_TRUST_ALL["cvss_score"],
                category=VulnerabilityTemplates.PINNING_TRUST_ALL["category"],
                description=f"Анонимная реализация X509TrustManager с пустыми методами проверки сертификатов ({', '.join(empty_methods)}). Это полностью отключает валидацию SSL/TLS и делает приложение уязвимым к MITM-атакам.",
                location=format_location(filepath, line_num),
                recommendation=VulnerabilityTemplates.PINNING_TRUST_ALL["recommendation"],
                code_snippet=snippet
            ))
        
        return results

    def _check_missing_pinning_any(self, filepath: str, content: str, lines: List[str]) -> List[Vulnerability]:
        """
        Детектит использование доменов без ANY pinning (ни в конфиге, ни в коде).
        """
        results = []
        
        # 1. Находим ВСЕ домены с их позициями (группируем по домену)
        domain_matches: Dict[str, List[re.Match]] = {}  # ← ИЗМЕНЕНО: List[re.Match]
        for match in HttpPatterns.HARDCODED_DOMAIN.finditer(content):
            domain = match.group(1)
            if domain and not domain.startswith("localhost") and not domain.startswith("127.0.0.1"):
                # ИСПРАВЛЕНИЕ: добавляем ВСЕ вхождения, а не только первое
                if domain not in domain_matches:
                    domain_matches[domain] = []
                domain_matches[domain].append(match)
        
        if not domain_matches:
            return results
        
        # 2. Для КАЖДОГО домена проверяем, есть ли его pinning в этом файле
        for domain, matches in domain_matches.items():  # ← ИЗМЕНЕНО: итерируемся по matches
            # Ищем .add("этот_домен", ...) в содержимом файла
            domain_pinner_pattern = rf'\.add\s*\(\s*["\']{re.escape(domain)}["\']\s*,\s*["\'](?:sha256/)?[A-Za-z0-9+/=]+["\']'
            has_pinning_for_domain = bool(re.search(domain_pinner_pattern, content, re.IGNORECASE))
            
            if not has_pinning_for_domain:
                # ИСПРАВЛЕНИЕ: создаём уязвимость для КАЖДОГО вхождения домена
                for match in matches:
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
        ИСПРАВЛЕНО: теперь анализирует каждый CertificatePinner.Builder() отдельно.
        """
        results = []
        
        # Паттерн для поиска CertificatePinner.Builder()
        builder_pattern = re.compile(r'CertificatePinner\.Builder\(\)', re.IGNORECASE)
        
        # Находим все CertificatePinner.Builder() в файле
        builders = list(builder_pattern.finditer(content))
        
        if not builders:
            return results
        
        # Паттерн для поиска .add("domain", "sha256/hash")
        add_pattern = re.compile(
            r'\.add\s*\(\s*["\']([^"\']+)["\']\s*,\s*["\'](?:sha256/)?([A-Za-z0-9+/=]+)["\']',
            re.IGNORECASE
        )
        
        # Для каждого CertificatePinner.Builder() считаем количество пинов
        for builder_match in builders:
            builder_start = builder_match.start()
            builder_line = content[:builder_start].count('\n') + 1
            
            # Ищем .build() после этого Builder()
            build_match = re.search(r'\.build\(\)', content[builder_start:])
            if not build_match:
                continue
            
            builder_end = builder_start + build_match.end()
            builder_block = content[builder_start:builder_end]
            
            # Считаем количество .add() в этом блоке
            pins = add_pattern.findall(builder_block)
            pin_count = len(pins)
            
            # Если только один пин — предупреждение о риске ротации
            if pin_count == 1:
                domain, pin_hash = pins[0]
                snippet = lines[builder_line - 1].strip() if builder_line <= len(lines) else ""
                
                results.append(Vulnerability(
                    id=VulnerabilityTemplates.PINNING_SINGLE["id"],
                    severity=VulnerabilityTemplates.PINNING_SINGLE["severity"],
                    cvss_score=VulnerabilityTemplates.PINNING_SINGLE["cvss_score"],
                    category=VulnerabilityTemplates.PINNING_SINGLE["category"],
                    description=VulnerabilityTemplates.PINNING_SINGLE["description"].format(domain=domain),
                    location=format_location(filepath, builder_line),
                    recommendation=VulnerabilityTemplates.PINNING_SINGLE["recommendation"].format(domain=domain),
                    code_snippet=snippet
                ))
        
        return results
    
    def _check_missing_pinning_in_client(self, filepath: str, content: str, lines: List[str]) -> List[Vulnerability]:
        """
        Ищет OkHttpClient.Builder().build() без .certificatePinner() в том же блоке.
        ИСПРАВЛЕНО: теперь привязывает уязвимость к строке с .build(), а не с Builder().
        """
        results = []
        
        # Паттерн для поиска OkHttpClient.Builder()
        builder_pattern = re.compile(
            r'OkHttpClient\.Builder\(\)',
            re.IGNORECASE
        )
        
        # Находим все OkHttpClient.Builder() в файле
        builders = list(builder_pattern.finditer(content))
        
        if not builders:
            return results
        
        # Для каждого Builder проверяем, есть ли .certificatePinner() перед .build()
        for builder_match in builders:
            builder_start = builder_match.start()
            
            # Ищем .build() после этого Builder()
            build_match = re.search(r'\.build\(\)', content[builder_start:])
            if not build_match:
                continue
            
            # ИСПРАВЛЕНИЕ: Вычисляем строку с .build(), а не с Builder()
            build_absolute_pos = builder_start + build_match.start()
            build_line = content[:build_absolute_pos].count('\n') + 1
            
            builder_end = builder_start + build_match.end()
            builder_block = content[builder_start:builder_end]
            
            # Проверяем, есть ли .certificatePinner() в этом блоке
            if not re.search(r'\.certificatePinner\(', builder_block, re.IGNORECASE):
                # Также проверяем, есть ли .sslSocketFactory() (кастомная SSL конфигурация)
                has_custom_ssl = bool(re.search(r'\.sslSocketFactory\(', builder_block, re.IGNORECASE))
                
                if not has_custom_ssl:
                    # ИСПРАВЛЕНИЕ: Используем build_line вместо builder_line
                    snippet = lines[build_line - 1].strip() if build_line <= len(lines) else ""
                    
                    results.append(Vulnerability(
                        id="PINNING_MISSING_CLIENT_008",
                        severity="MEDIUM",
                        cvss_score=5.3,
                        category="Certificate Pinning",
                        description=f"OkHttpClient создан без certificate pinning. Это делает приложение уязвимым к MITM-атакам даже при использовании HTTPS.",
                        location=format_location(filepath, build_line),  # ← ИСПРАВЛЕНО
                        recommendation="Добавьте .certificatePinner(CertificatePinner.Builder().add(\"domain.com\", \"sha256/HASH=\").build()) в цепочку вызовов OkHttpClient.Builder().",
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