# Отчет по уязвимостям сетевой безопасности

Ниже указаны только реальные или потенциально эксплуатируемые проблемы, влияющие на безопасность сетевого взаимодействия.

---

# 1. HTTP в WebView

### Файл: WebViewActivity.java

### Строка 15

```java
webView.loadUrl("http://m.shopapp.example.com/catalog");
```

### Критичность

**HIGH**

### CVSS

**8.6**

### Риск

Используется незашифрованный HTTP.

Возможны:

* MITM-атаки;
* подмена контента;
* внедрение вредоносного JavaScript;
* кража сессионных данных.

### Исправление

Использовать HTTPS.

```java
webView.loadUrl("https://m.shopapp.example.com/catalog");
```

---

# 2. HTTP в WebView

### Файл: WebViewActivity.java

### Строка 17

```java
webView.loadUrl("http://help.shopapp.example.com/faq");
```

### Критичность

**HIGH**

### CVSS

**8.6**

### Исправление

```java
webView.loadUrl("https://help.shopapp.example.com/faq");
```

---

# 3. TrustManager отключает проверку клиентских сертификатов

### Файл: UnsafeTrustManager.java

### Строки 11-12

```java
public void checkClientTrusted(X509Certificate[] chain, String authType) {
}
```

### Критичность

**HIGH**

### CVSS

**8.1**

### Риск

При использовании mTLS любой клиентский сертификат считается валидным.

### Исправление

```java
defaultTrustManager.checkClientTrusted(chain, authType);
```

---

# 4. TrustManager отключает проверку серверных сертификатов

### Файл: UnsafeTrustManager.java

### Строки 15-16

```java
public void checkServerTrusted(X509Certificate[] chain, String authType) {
}
```

### Критичность

**CRITICAL**

### CVSS

**9.8**

### Риск

Любой сертификат принимается как доверенный.

Полный обход TLS.

### Исправление

```java
defaultTrustManager.checkServerTrusted(chain, authType);
```

---

# 5. Некорректный список доверенных CA

### Файл: UnsafeTrustManager.java

### Строка 20

```java
return new X509Certificate[0];
```

### Критичность

**MEDIUM**

### CVSS

**5.3**

### Исправление

```java
return defaultTrustManager.getAcceptedIssuers();
```

---

# 6. Небезопасный TrustManager внутри OkHttp

### Файл: NetworkConfig.kt

### Строки 18-20

```kotlin
override fun checkClientTrusted(...) {
}
```

### Критичность

**HIGH**

### CVSS

**8.1**

### Исправление

Использовать системный TrustManager.

```kotlin
trustManager.checkClientTrusted(chain, authType)
```

---

# 7. Небезопасный TrustManager внутри OkHttp

### Файл: NetworkConfig.kt

### Строки 22-24

```kotlin
override fun checkServerTrusted(...) {
}
```

### Критичность

**CRITICAL**

### CVSS

**9.8**

### Риск

Полный обход проверки TLS-сертификатов.

### Исправление

```kotlin
trustManager.checkServerTrusted(chain, authType)
```

---

# 8. Пустой список доверенных издателей

### Файл: NetworkConfig.kt

### Строка 27

```kotlin
override fun getAcceptedIssuers(): Array<X509Certificate> = arrayOf()
```

### Критичность

**MEDIUM**

### CVSS

**5.3**

### Исправление

```kotlin
override fun getAcceptedIssuers() =
    trustManager.acceptedIssuers
```

---

# 9. SSLContext инициализируется небезопасным образом

### Файл: NetworkConfig.kt

### Строка 46

```kotlin
sslContext.init(null, null, null)
```

### Критичность

**HIGH**

### CVSS

**8.8**

### Риск

Используются дефолтные настройки, а выше подключается TrustManager, принимающий любые сертификаты.

Итог — TLS фактически отключен.

### Исправление

```kotlin
sslContext.init(null, arrayOf(trustManager), SecureRandom())
```

---

# 10. Только один certificate pin

### Файл: NetworkConfig.kt

### Строки 34-37

```kotlin
.add(
    "api.shopapp.example.com",
    "sha256/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
)
```

### Критичность

**MEDIUM**

### CVSS

**5.9**

### Риск

Используется только один pin.

При ротации сертификата приложение перестанет работать.

Также отсутствует backup pin.

### Исправление

```kotlin
.add("api.shopapp.example.com", PRIMARY_PIN)
.add("api.shopapp.example.com", BACKUP_PIN)
```

---

# 11. Полный обход проверки hostname

### Файл: HostnameBypass.java

### Строки 10-12

```java
public boolean verify(String hostname, SSLSession session) {
    return true;
}
```

### Критичность

**CRITICAL**

### CVSS

**9.8**

### Риск

Сертификат может быть выдан для любого домена.

MITM становится возможен даже при валидном сертификате злоумышленника.

### Исправление

```java
HostnameVerifier verifier =
        HttpsURLConnection.getDefaultHostnameVerifier();

return verifier.verify(hostname, session);
```

---

# 12. HTTP URL для staging

### Файл: Config.kt

### Строка 6

```kotlin
const val STAGING_URL = "http://staging.shopapp.example.com/api"
```

### Критичность

**MEDIUM**

### CVSS

**6.5**

### Исправление

```kotlin
const val STAGING_URL =
    "https://staging.shopapp.example.com/api"
```

---

# 13. HTTP API endpoint

### Файл: ApiService.kt

### Строка 16

```kotlin
@GET("http://api.shopapp.example.com/products")
```

### Критичность

**HIGH**

### CVSS

**8.6**

### Исправление

```kotlin
@GET("products")
```

и использовать HTTPS base URL.

---

# 14. HTTP endpoint авторизации

### Файл: ApiService.kt

### Строка 19

```kotlin
@POST("http://api.shopapp.example.com/auth/login")
```

### Критичность

**CRITICAL**

### CVSS

**9.4**

### Риск

Логин и пароль передаются по HTTP.

Возможна кража учетных данных.

### Исправление

```kotlin
@POST("auth/login")
```

с HTTPS base URL.

---

# 15. HTTP Base URL

### Файл: ApiClient.kt

### Строка 8

```kotlin
private const val BASE_URL =
    "http://api.shopapp.example.com/v2/"
```

### Критичность

**HIGH**

### CVSS

**8.6**

### Исправление

```kotlin
private const val BASE_URL =
    "https://api.shopapp.example.com/v2/"
```

---

# 16. Разрешен Cleartext Traffic

### Файл: AndroidManifest.xml

### Строка 15

```xml
android:usesCleartextTraffic="true"
```

### Критичность

**HIGH**

### CVSS

**8.0**

### Риск

Приложение разрешает HTTP-соединения.

Это позволяет всем найденным HTTP URL реально работать.

### Исправление

```xml
android:usesCleartextTraffic="false"
```

---

# 17. Доверие пользовательским сертификатам глобально

### Файл: network_security_config.xml

### Строка 8

```xml
<certificates src="user" />
```

### Критичность

**HIGH**

### CVSS

**8.1**

### Риск

Любой сертификат, установленный пользователем на устройство, становится доверенным.

На корпоративных или скомпрометированных устройствах это позволяет MITM.

### Исправление

```xml
<trust-anchors>
    <certificates src="system"/>
</trust-anchors>
```

---

# 18. Доверие пользовательским сертификатам для домена

### Файл: network_security_config.xml

### Строка 15

```xml
<certificates src="user" />
```

### Критичность

**HIGH**

### CVSS

**8.1**

### Исправление

```xml
<certificates src="system" />
```

---

# 19. Pinning с одним pin

### Файл: network_security_config.xml

### Строки 29-31

```xml
<pin-set expiration="2026-12-31">
    <pin digest="SHA-256">AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=</pin>
</pin-set>
```

### Критичность

**MEDIUM**

### CVSS

**5.9**

### Исправление

Добавить резервный pin.

```xml
<pin-set expiration="2028-12-31">
    <pin digest="SHA-256">PRIMARY_PIN</pin>
    <pin digest="SHA-256">BACKUP_PIN</pin>
</pin-set>
```

---

# 20. Некорректный hash pin

### Файл: network_security_config.xml

### Строка 40

```xml
<pin digest="SHA-256">invalid_hash_not_base64</pin>
```

### Критичность

**MEDIUM**

### CVSS

**4.8**

### Риск

Конфигурация pinning невалидна и может привести к отказу приложения или отключению pinning.

### Исправление

Использовать корректный Base64 SHA-256 SPKI hash.

```xml
<pin digest="SHA-256">
W6ph5Mm5Pz8GgiULbPgzG37mj9g=
</pin>
```

---

# 21. Пустой pin-set

### Файл: network_security_config.xml

### Строка 49

```xml
<pin-set expiration="2026-12-31"></pin-set>
```

### Критичность

**MEDIUM**

### CVSS

**5.0**

### Риск

Pinning фактически отсутствует.

### Исправление

```xml
<pin-set expiration="2028-12-31">
    <pin digest="SHA-256">PRIMARY_PIN</pin>
    <pin digest="SHA-256">BACKUP_PIN</pin>
</pin-set>
```

---

# Сводка

| Критичность | Количество |
| ----------- | ---------- |
| CRITICAL    | 4          |
| HIGH        | 11         |
| MEDIUM      | 6          |
| LOW         | 0          |

### Наиболее опасные проблемы

1. Строки 15-16 (`UnsafeTrustManager.checkServerTrusted`) — CVSS 9.8
2. Строки 22-24 (`NetworkConfig.checkServerTrusted`) — CVSS 9.8
3. Строки 10-12 (`HostnameBypass.verify`) — CVSS 9.8
4. Строка 19 (`ApiService.login`) — передача логина и пароля по HTTP — CVSS 9.4

Эти четыре дефекта позволяют выполнять полноценные MITM-атаки и перехватывать учетные данные пользователей.
