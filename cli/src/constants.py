"""
Константы, регулярные выражения и шаблоны уязвимостей для Android Security Analyzer.

Этот модуль централизует все конфигурируемые параметры, что упрощает:
- Добавление новых типов уязвимостей
- Настройку правил анализа
- Поддержку и тестирование
"""

import re
from typing import Dict, Any

# =============================================================================
# СЕВЕРИТИ И ПОРЯДОК СОРТИРОВКИ
# =============================================================================

SEVERITY_ORDER: Dict[str, int] = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}

CVSS_RANGES: Dict[str, tuple] = {
    "CRITICAL": (9.0, 10.0),
    "HIGH": (7.0, 8.9),
    "MEDIUM": (4.0, 6.9),
    "LOW": (0.0, 3.9),
}

COLORS = {
    "CRITICAL": "\033[91m",
    "HIGH":     "\033[93m",
    "MEDIUM":   "\033[33m",
    "LOW":      "\033[92m",
    "RESET":    "\033[0m",
    "BOLD":     "\033[1m",
}


# =============================================================================
# РЕГУЛЯРНЫЕ ВЫРАЖЕНИЯ ДЛЯ АНАЛИЗА ИСХОДНОГО КОДА
# =============================================================================

# Поиск небезопасных HTTP-URL
class HttpPatterns:
    """Регулярные выражения для обнаружения небезопасных HTTP-ссылок."""
    
    # HTTP в строковых литералах: "http://..." или 'http://...'
    HTTP_IN_STRING = re.compile(r'["\']http://[^\s"\']+["\']')
    
    # Retrofit-аннотации с HTTP: @GET("http://...")
    RETROFIT_ANNOTATION = re.compile(
        r'@(?:GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\s*\(\s*["\']http://[^\s"\']+["\']',
        re.IGNORECASE
    )
    
    # WebView.loadUrl() с HTTP
    WEBVIEW_LOAD_URL = re.compile(r'\.loadUrl\s*\(\s*["\']http://[^\s"\']+["\']')
    
    # Извлечение чистого URL из строки
    URL_EXTRACTOR = re.compile(r'http://[^\s"\')\]]+', re.IGNORECASE)
    
    # Поиск baseUrl в коде (Retrofit, OkHttpClient)
    BASE_URL_PATTERN = re.compile(
        r'(?:baseUrl|\.baseUrl)\s*[\(=]\s*["\']([^"\']+)["\']',
        re.IGNORECASE
    )
    
    # Поиск доменов в хардкод-строках
    HARDCODED_DOMAIN = re.compile(
        r'["\']https?://([a-zA-Z0-9.-]+)(?:[:/][^\s"\']*)?["\']',
        re.IGNORECASE
    )


# =============================================================================
# РЕГУЛЯРНЫЕ ВЫРАЖЕНИЯ ДЛЯ ANALYSIS CERTIFICATE PINNING
# =============================================================================

class PinningPatterns:
    """Регулярные выражения для анализа certificate pinning."""
    
    # Класс, реализующий X509TrustManager
    TRUST_MANAGER_CLASS = re.compile(
        r'class\s+(\w+).*?(:|\s+implements\s+)\s*X509TrustManager',
        re.MULTILINE | re.IGNORECASE
    )
    
    # Пустая реализация checkServerTrusted / checkClientTrusted
    EMPTY_TRUST_CHECK = re.compile(
        r'check(Server|Client)Trusted\s*\([^)]*\)\s*\{[^}]*\}',
        re.MULTILINE | re.DOTALL
    )
    
    # TrustManager, который не проверяет цепочку (возвращает без исключений)
    TRUST_ALL_PATTERN = re.compile(
        r'(check(Server|Client)Trusted|getAcceptedIssuers)\s*\([^)]*\)\s*\{[^}]*?return\s+[^;]*;?\s*\}',
        re.MULTILINE | re.DOTALL | re.IGNORECASE
    )
    
    # HostnameVerifier, всегда возвращающий true (Kotlin)
    HOSTNAME_VERIFIER_TRUE_KOTLIN = re.compile(
        r'override\s+fun\s+verify\s*\([^)]*\)\s*(?::\s*Boolean)?\s*(?:=\s*true|\{[^}]*?\breturn\s+true\b[^}]*\})',
        re.MULTILINE | re.DOTALL | re.IGNORECASE
    )
    
    # HostnameVerifier, всегда возвращающий true (Java)
    HOSTNAME_VERIFIER_TRUE_JAVA = re.compile(
        r'public\s+boolean\s+verify\s*\([^)]*\)\s*(?:\{[^}]*?\breturn\s+true\b[^}]*\}|=\s*true)',
        re.MULTILINE | re.DOTALL | re.IGNORECASE
    )

    EMPTY_TRUST_CHECK = re.compile(
        r'check(Server|Client)Trusted\s*\([^)]*\)\s*\{[^}]*?\}',
        re.MULTILINE | re.DOTALL | re.IGNORECASE
    )
    
    # CertificatePinner.Builder().addPin() — корректное использование
    CERT_PINNER_ADD_PIN = re.compile(
        r'CertificatePinner\s*\.\s*Builder\s*\(\s*\)[^;]*?\.add\s*\(',
        re.MULTILINE | re.DOTALL | re.IGNORECASE
    )
    
    # Вызов addPin с хэшем
    PIN_HASH_PATTERN = re.compile(
        r'\.add\s*\(\s*["\']([^"\']+)["\']\s*,\s*["\'](?:sha256/)?([A-Za-z0-9+/=]+)["\']\s*\)',
        re.IGNORECASE
    )
    
    # OkHttp с кастомным sslSocketFactory
    CUSTOM_SSL_FACTORY = re.compile(
        r'\.sslSocketFactory\s*\(\s*[^,]+,\s*[^)]+\)',
        re.MULTILINE
    )


# =============================================================================
# ШАБЛОНЫ УЯЗВИМОСТЕЙ (VULNERABILITY TEMPLATES)
# =============================================================================

class VulnerabilityTemplates:
    """Шаблоны для генерации объектов Vulnerability."""
    
    # --- Network Security Config ---
    
    MISSING_NSC = {
        "id": "MISSING_NSC_001",
        "severity": "MEDIUM",
        "cvss_score": 5.3,
        "category": "Network Security Config",
        "description": "Файл network_security_config.xml не найден. Приложение использует настройки Android по умолчанию.",
        "recommendation": "Создайте network_security_config.xml и укажите его в AndroidManifest.xml через android:networkSecurityConfig."
    }
    
    PARSE_ERROR_NSC = {
        "id": "PARSE_ERROR_001",
        "severity": "HIGH",
        "cvss_score": 0.0,
        "category": "Parse Error",
        "description": "Не удалось разобрать XML: {error}",
        "recommendation": "Исправьте синтаксические ошибки в XML файле."
    }
    
    CLEARTEXT_BASE = {
        "id": "CLEARTEXT_BASE_001",
        "severity": "CRITICAL",
        "cvss_score": 9.8,
        "category": "Insecure Communication",
        "description": "cleartextTrafficPermitted=\"true\" в base-config разрешает незашифрованный HTTP для всего приложения.",
        "recommendation": "Установите cleartextTrafficPermitted=\"false\" и используйте HTTPS для всех соединений."
    }
    
    USER_CERTS_BASE = {
        "id": "USER_CERTS_001",
        "severity": "MEDIUM",
        "cvss_score": 5.9,
        "category": "Insecure Configuration",
        "description": "base-config доверяет пользовательским сертификатам (src=\"user\"). Позволяет перехватывать HTTPS-трафик.",
        "recommendation": "Удалите <certificates src=\"user\"/> из base-config. Используйте только системные сертификаты или certificate pinning."
    }
    
    CLEARTEXT_DOMAIN = {
        "id": "CLEARTEXT_DOMAIN_001",
        "severity": "HIGH",
        "cvss_score": 7.5,
        "category": "Insecure Communication",
        "description": "cleartextTrafficPermitted=\"true\" разрешён для домена: {domain}.",
        "recommendation": "Уберите cleartextTrafficPermitted=\"true\" для {domain} и переведите API на HTTPS."
    }
    
    USER_CERTS_DOMAIN = {
        "id": "USER_CERTS_DOMAIN_001",
        "severity": "HIGH",
        "cvss_score": 7.4,
        "category": "Insecure Configuration",
        "description": "domain-config доверяет пользовательским сертификатам для домена: {domain}.",
        "recommendation": "Удалите <certificates src=\"user\"/> из domain-config для {domain}."
    }
    
    MISSING_PINNING = {
        "id": "MISSING_PINNING_001",
        "severity": "HIGH",
        "cvss_score": 7.4,
        "category": "Certificate Pinning",
        "description": "Отсутствует <pin-set> для домена: {domain}. Уязвимость к Man-in-the-Middle атакам.",
        "recommendation": "Добавьте <pin-set> с SHA-256 хэшами сертификата для {domain}. Укажите резервный пин для ротации."
    }
    
    EMPTY_PINNING = {
        "id": "EMPTY_PINNING_001",
        "severity": "HIGH",
        "cvss_score": 7.4,
        "category": "Certificate Pinning",
        "description": "Тег <pin-set> присутствует, но не содержит ни одного <pin> для домена: {domain}.",
        "recommendation": "Добавьте хотя бы два <pin digest=\"SHA-256\"> в pin-set для {domain}: основной и резервный."
    }
    
    SINGLE_PIN = {
        "id": "SINGLE_PIN_001",
        "severity": "MEDIUM",
        "cvss_score": 5.3,
        "category": "Certificate Pinning",
        "description": "В pin-set для домена {domain} указан только один пин. При ротации сертификата приложение перестанет работать.",
        "recommendation": "Добавьте резервный пин в pin-set для {domain} на случай замены сертификата."
    }
    
    # --- Insecure HTTP ---
    
    HTTP_IN_STRINGS = {
        "id": "HTTP_IN_STRINGS_001",
        "severity": "MEDIUM",
        "cvss_score": 5.3,
        "category": "Insecure Communication",
        "description": "Небезопасный HTTP URL в строковом ресурсе \"{name}\": {url}",
        "recommendation": "Замените http:// на https:// в строковом ресурсе \"{name}\"."
    }
    
    HTTP_IN_RETROFIT = {
        "id": "HTTP_IN_RETROFIT_001",
        "severity": "HIGH",
        "cvss_score": 7.5,
        "category": "Insecure Communication",
        "description": "Retrofit-аннотация содержит небезопасный HTTP URL: {url}",
        "recommendation": "Замените http:// на https:// в Retrofit-аннотации или используйте относительный путь с безопасным baseUrl."
    }
    
    HTTP_IN_WEBVIEW = {
        "id": "HTTP_IN_WEBVIEW_001",
        "severity": "HIGH",
        "cvss_score": 7.5,
        "category": "Insecure Communication",
        "description": "WebView.loadUrl() загружает страницу по незашифрованному HTTP: {url}",
        "recommendation": "Замените http:// на https:// в вызове WebView.loadUrl()."
    }
    
    HTTP_IN_CODE = {
        "id": "HTTP_IN_CODE_001",
        "severity": "HIGH",
        "cvss_score": 7.5,
        "category": "Insecure Communication",
        "description": "Небезопасный HTTP URL в исходном коде: {url}",
        "recommendation": "Замените http:// на https://. Для baseUrl Retrofit используйте строку начинающуюся с https://."
    }
    
    # --- Certificate Pinning in Code ---
    
    PINNING_TRUST_ALL = {
        "id": "PINNING_TRUST_ALL_001",
        "severity": "CRITICAL",
        "cvss_score": 9.1,
        "category": "Certificate Pinning",
        "description": "Обнаружен TrustManager, который не проверяет сертификаты сервера (TrustAll). Позволяет любую подмену сертификата.",
        "recommendation": "Реализуйте корректную проверку цепочки сертификатов в checkServerTrusted() или используйте стандартный TrustManager."
    }
    
    PINNING_HOSTNAME_BYPASS = {
        "id": "PINNING_HOSTNAME_BYPASS_002",
        "severity": "CRITICAL",
        "cvss_score": 9.1,
        "category": "Certificate Pinning",
        "description": "HostnameVerifier всегда возвращает true, отключая проверку соответствия имени хоста сертификату.",
        "recommendation": "Реализуйте корректную проверку hostname или используйте OkHttp's default verifier."
    }
    
    PINNING_MISSING_CODE = {
        "id": "PINNING_MISSING_CODE_003",
        "severity": "HIGH",
        "cvss_score": 7.4,
        "category": "Certificate Pinning",
        "description": "Домен '{domain}' защищён pinning в network_security_config.xml, но не используется CertificatePinner в коде.",
        "recommendation": "Добавьте CertificatePinner.Builder().addPin() для домена '{domain}' или убедитесь, что конфигурация применяется через OkHttp."
    }
   

    PINNING_CUSTOM_SSL = {
        "id": "PINNING_CUSTOM_SSL_004",
        "severity": "HIGH",
        "cvss_score": 7.5,
        "category": "Certificate Pinning",
        "description": "Используется кастомный sslSocketFactory без явного CertificatePinner. Возможна ослабленная проверка TLS.",
        "recommendation": "Проверьте, что кастомный SSLSocketFactory не отключает проверку сертификатов. Добавьте CertificatePinner для критичных доменов."
    }
    
    PINNING_SINGLE = {
        "id": "PINNING_SINGLE_005",
        "severity": "MEDIUM",
        "cvss_score": 5.3,
        "category": "Certificate Pinning",
        "description": "CertificatePinner содержит только один пин для домена '{domain}'. При ротации сертификата приложение перестанет работать.",
        "recommendation": "Добавьте резервный пин через .addPin() для обеспечения бесперебойной работы при обновлении сертификата."
    }
    
    PINNING_MISSING_ANY = {
	    "id": "PINNING_MISSING_ANY_006",
	    "severity": "MEDIUM",
	    "cvss_score": 5.3,
	    "category": "Certificate Pinning",
	    "description": "Домен '{domain}' используется в коде, но не защищён certificate pinning ни в network_security_config.xml, ни через CertificatePinner.",
	    "recommendation": "Добавьте certificate pinning для '{domain}' через network_security_config.xml или CertificatePinner в коде."
	}

    # --- Android Manifest ---
    
    MANIFEST_CLEARTEXT = {
        "id": "MANIFEST_CLEARTEXT_001",
        "severity": "CRITICAL",
        "cvss_score": 9.8,
        "category": "Insecure Communication",
        "description": "android:usesCleartextTraffic=\"true\" в AndroidManifest.xml разрешает HTTP для всего приложения, переопределяя network_security_config.xml.",
        "recommendation": "Установите android:usesCleartextTraffic=\"false\" и используйте HTTPS. Настройте exceptions через network_security_config.xml при необходимости."
    }
    
    MANIFEST_NSC_BROKEN_REF = {
        "id": "MANIFEST_NSC_BROKEN_REF_001",
        "severity": "HIGH",
        "cvss_score": 7.5,
        "category": "Configuration",
        "description": "android:networkSecurityConfig=\"{ref}\" указан в манифесте, но файл не найден по пути: {path}",
        "recommendation": "Создайте файл network_security_config.xml или исправьте ссылку в android:networkSecurityConfig."
    }
    
    MANIFEST_NSC_MISSING_REF = {
        "id": "MANIFEST_NSC_MISSING_REF_002",
        "severity": "MEDIUM",
        "cvss_score": 5.3,
        "category": "Configuration",
        "description": "Атрибут android:networkSecurityConfig не указан в <application>. Приложение может использовать настройки по умолчанию.",
        "recommendation": "Добавьте android:networkSecurityConfig=\"@xml/network_security_config\" в <application> и создайте соответствующий файл."
    }


# =============================================================================
# ВСПОМОГАТЕЛЬНЫЕ ФУНКЦИИ
# =============================================================================

def format_location(filepath: str, line: int, column: int = None) -> str:
    """
    Форматирует расположение уязвимости в едином стиле.
    
    Args:
        filepath: Путь к файлу
        line: Номер строки (1-based)
        column: Номер колонки (опционально, 1-based)
    
    Returns:
        Строка в формате "path/to/file.ext:line" или "path/to/file.ext:line:column"
    """
    if column is not None:
        return f"{filepath}:{line}:{column}"
    return f"{filepath}:{line}"


def extract_domain_from_url(url: str) -> str:
    """
    Извлекает домен из URL.
    
    Args:
        url: Полный URL (например, "https://api.example.com/v1/users")
    
    Returns:
        Домен (например, "api.example.com")
    """
    import re
    match = re.match(r'https?://([^/:]+)', url)
    return match.group(1) if match else ""