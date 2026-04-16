package com.example

import okhttp3.OkHttpClient
import javax.net.ssl.SSLContext
import javax.net.ssl.TrustManager

object UnsafeSslClient {
    fun createClient(): OkHttpClient {
        val trustAllCerts = arrayOf<TrustManager>() // упрощённо
        val sslContext = SSLContext.getInstance("TLS")
        sslContext.init(null, trustAllCerts, java.security.SecureRandom())
        
        return OkHttpClient.Builder()
            .sslSocketFactory(sslContext.socketFactory, trustAllCerts[0] as javax.net.ssl.X509TrustManager)
            // ❌ Кастомный SSL без CertificatePinner
            .build()
    }
}
