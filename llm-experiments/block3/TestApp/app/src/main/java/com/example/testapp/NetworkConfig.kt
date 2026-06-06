package com.example.testapp

import okhttp3.CertificatePinner
import okhttp3.OkHttpClient
import okhttp3.OkHttpClient.*
import javax.net.ssl.SSLContext
import javax.net.ssl.X509TrustManager
import java.security.cert.X509Certificate

object NetworkConfig {

    val unsafeClient: OkHttpClient = Builder()
        .sslSocketFactory(
            createInsecureSslContext().socketFactory,
            object : X509TrustManager {
                override fun checkClientTrusted(
                    chain: Array<out X509Certificate?>?,
                    authType: String?
                ) {
                    TODO("Not yet implemented")
                }

                override fun checkServerTrusted(
                    chain: Array<out X509Certificate?>?,
                    authType: String?
                ) {
                    TODO("Not yet implemented")
                }

                override fun getAcceptedIssuers(): Array<X509Certificate> = arrayOf()
            }
        )
        .build()

    // MEDIUM: только один пин
    val singlePinClient: OkHttpClient = Builder()
        .certificatePinner(
            CertificatePinner.Builder()
                .add("api.singlepin.com", "sha256/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=")
                .build()
        )
        .build()

    private fun createInsecureSslContext(): SSLContext {
        val sslContext = SSLContext.getInstance("TLS")
        sslContext.init(null, null, null)
        return sslContext
    }
}