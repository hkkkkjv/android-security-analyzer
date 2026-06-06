
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

###  Функции Плагина для Android Studio
- **Inline подсветка**: Цветные волнистые линии под уязвимым кодом (красный/orange/yellow/green).
- **Детальные тултипы**: Описание, CVSS Score и рекомендация при наведении.

Вот обновленный `README.md`, который отражает архитектуру проекта (CLI + Plugin), инструкции по установке плагина и примеры использования обоих компонентов.


## Установка и Запуск

### 1. CLI (для CI/CD и локального сканирования)

Требования: Python 3.8+

```bash
# Запуск анализа
python3 cli/src/main.py --project /путь/к/android/project

# Сохранение отчета в JSON
python3 cli/src/main.py --project /путь/к/android/project --output report.json
```

**Exit codes:**
- `0`: Уязвимостей уровня CRITICAL/HIGH не найдено.
- `1`: Найдены критические или высокие уязвимости (удобно для блокировки пайплайна).

### 2. Плагин для Android Studio

**Установка:**
1. Скачайте файл плагина `.zip` из раздела [Releases](ссылка_на_релиз) или соберите его через `./gradlew buildPlugin`.
2. В Android Studio перейдите в **Settings/Preferences → Plugins**.
3. Нажмите → **Install Plugin from Disk...** и выберите скачанный `.zip`.
4. Перезагрузите IDE.

**Настройка:**
Плагину необходимо знать путь к Python-скрипту анализатора.
1. Создайте файл `local.properties` в корне вашего Android-проекта (если нет).
2. Добавьте путь к скрипту:
   ```properties
   analyzer.path=/absolute/path/to/android-security-analyzer/cli/src/main.py
   ```
   *(Замените путь на реальный путь к файлу `main.py` на вашем компьютере)*.

**Использование:**
- Откройте любой Kotlin, Java или XML файл в проекте.
- Плагин автоматически запустит анализ (результаты кэшируются на 5 минут).
- Уязвимости будут подсвечены в редакторе.
- Нажмите `Alt+Enter` на подсветке для применения исправления.

---

## Тестовые проекты

В репозитории присутствуют примеры проектов для проверки работы анализатора:

```
test-projects/
├── 01-cleartext-base         # CRITICAL: cleartext в base-config
├── 02-user-certs             # MEDIUM: src="user"  
├── 03-cleartext-domain       # HIGH: cleartext для домена
├── 04-missing-pinning        # HIGH: нет pin-set
├── 05-empty-pinset           # HIGH: пустой pin-set
├── 06-multiple-domains       # HIGH: один домен без pinning
├── 07-secure                 # 0 уязвимостей (Clean)
├── 08-broken-xml             # Parse error handling
├── 09-no-config              # MEDIUM: файл отсутствует
└── 10-all-issues             # Комбо: 15 уязвимостей (1C + 11H + 3M)
```

Для проверки плагина откройте любую папку из `test-projects` как проект в Android Studio.

---

## Выходные данные CLI

Пример JSON-отчета:

```json
{
  "scan_metadata": {
    "scan_date": "2025-05-20T12:00:00Z",
    "project_path": "/home/user/MyApp",
    "scan_duration_ms": 1250
  },
  "vulnerabilities": [
    {
      "id": "CLEARTEXT_BASE_001",
      "severity": "CRITICAL",
      "cvss_score": 9.8,
      "category": "Insecure Communication",
      "description": "cleartextTrafficPermitted=\"true\" разрешает незашифрованный трафик.",
      "location": "app/src/main/res/xml/network_security_config.xml:3",
      "recommendation": "Установите cleartextTrafficPermitted=\"false\"."
    }
  ],
  "summary": {
    "total_issues": 1,
    "critical": 1,
    "high": 0,
    "medium": 0,
    "low": 0
  }
}
```

---

## Архитектура

Проект разделен на два независимых модуля:

1. **`cli/` (Python)**:
   - Парсинг XML (`network_security_config.xml`, `Manifest`).
   - Regex-анализ исходного кода (Kotlin/Java).
   - Генерация машиночитаемого JSON.

2. **`plugin/` (Kotlin/IntelliJ Platform)**:
   - `SecurityAnalyzerService`: Асинхронный запуск CLI и парсинг JSON.
   - `ExternalAnnotator`: Визуализация проблем в редакторе.
   - `PsiLocationMapper`: Связь строк из отчета с PSI-элементами IDE.

---
