
# Android Security Analyzer

Статический анализатор сетевой безопасности Android-приложений. Находит уязвимости в конфигурационных файлах и коде без запуска приложения.

## Запуск

```bash
python3 cli/src/main.py --project /путь/к/проекту
python3 cli/src/main.py --project /путь/к/проекту --output report.json
```

## Что проверяется

**`network_security_config.xml`:**
- `cleartextTrafficPermitted="true"` — **CRITICAL**
- `certificates src="user"` в base-config/domain-config — **HIGH/MEDIUM**  
- Отсутствует/пустой/single `<pin-set>` для домена — **HIGH/MEDIUM**
- Отсутствует файл — **MEDIUM**
- Ошибки парсинга XML — **HIGH**

**Исходный код + ресурсы:**
- HTTP URL в Retrofit аннотациях — **HIGH**
- `WebView.loadUrl("http://...")` — **HIGH**
- `http://` строки в Kotlin/Java — **HIGH**
- HTTP в `strings.xml` (все values*) — **MEDIUM**

## Тестовые проекты

```
test-projects/
├── 01-cleartext-base         # CRITICAL: cleartext в base-config
├── 02-user-certs             # MEDIUM: src="user"  
├── 03-cleartext-domain       # HIGH: cleartext для домена
├── 04-missing-pinning        # HIGH: нет pin-set
├── 05-empty-pinset           # HIGH: пустой pin-set
├── 06-multiple-domains       # HIGH: один домен без pinning
├── 07-secure                 # 0 уязвимостей
├── 08-broken-xml             # Parse error
├── 09-no-config              # MEDIUM: файл отсутствует
└── 10-all-issues             # 15 уязвимостей (1C + 11H + 3M)
```

## Выходные данные

- **Консоль**: цветной отчёт с location:filename:line
- **JSON**: полный отчёт с metadata и summary
- **Exit code**: `0` (OK) / `1` (CRITICAL/HIGH найдены)

## CI/CD интеграция

```yaml
# .github/workflows/security.yml
- name: Security scan
  run: python3 cli/src/main.py --project . 
  continue-on-error: false
```
