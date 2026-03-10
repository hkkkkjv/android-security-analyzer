# Android Security Analyzer

Статический анализатор сетевой безопасности Android-приложений. Находит уязвимости в конфигурационных файлах без запуска приложения.

## Запуск

```bash
python3 cli/src/main.py --project /путь/к/проекту
python3 cli/src/main.py --project /путь/к/проекту --output report.json
```

## Что проверяется

`network_security_config.xml`:

- `cleartextTrafficPermitted="true"` — CRITICAL
- Отсутствует или пустой `<pin-set>` для домена — HIGH
- Доверие пользовательским сертификатам `src="user"` — MEDIUM
- Файл конфигурации отсутствует — MEDIUM

## Тестовые проекты

```
test-projects/
├── 01-cleartext-base       # CRITICAL: cleartext в base-config
├── 02-user-certs           # MEDIUM: доверие user-сертификатам
├── 03-cleartext-domain     # HIGH: cleartext для домена
├── 04-missing-pinning      # HIGH: нет pin-set
├── 05-empty-pinset         # HIGH: пустой pin-set
├── 06-multiple-domains     # один домен без pinning
├── 07-secure               # безопасный конфиг — 0 уязвимостей
├── 08-broken-xml           # сломанный XML
├── 09-no-config            # файл отсутствует
└── 10-all-issues           # все проблемы сразу
```

## Exit code

`0` — нет CRITICAL/HIGH, `1` — есть. Позволяет использовать в CI/CD.
