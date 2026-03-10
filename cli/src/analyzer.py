import xml.etree.ElementTree as ET
import os
from dataclasses import dataclass
from typing import List


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

        for cert in base_config.findall("./trust-anchors/certificates"):
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
            elif len(pin_set.findall("pin")) == 0:
                results.append(Vulnerability(
                    id="EMPTY_PINNING_001",
                    severity="HIGH",
                    cvss_score=7.4,
                    category="Certificate Pinning",
                    description=f"Тег <pin-set> присутствует, но не содержит ни одного <pin> для домена: {domain_str}.",
                    location=config_path,
                    recommendation=f"Добавьте хотя бы два <pin digest=\"SHA-256\"> в pin-set для {domain_str}: основной и резервный."
                ))

        return results
