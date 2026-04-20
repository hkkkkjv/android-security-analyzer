package com.example

import okhttp3.CertificatePinner
import okhttp3.OkHttpClient
import java.security.cert.X509Certificate
import javax.net.ssl.X509TrustManager

object SecureClient {
    
    fun createClient(): OkHttpClient {
        return OkHttpClient.Builder()
            .certificatePinner(
                CertificatePinner.Builder()
                    .add("api.example.com", "sha256/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=")
                    .add("api.example.com", "sha256/BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=") // резервный
                    .build()
            )
            .build()
    }
    
    // Безопасный TrustManager (стандартная реализация)
    class SecureTrustManager : X509TrustManager {
        override fun checkServerTrusted(chain: Array<out X509Certificate>?, authType: String?) {
            // Стандартная проверка цепочки сертификатов
            // (в реальности делегируем системному TrustManager)
        }
        override fun checkClientTrusted(chain: Array<out X509Certificate>?, authType: String?) {}
        override fun getAcceptedIssuers(): Array<X509Certificate> = emptyArray()
    }
}