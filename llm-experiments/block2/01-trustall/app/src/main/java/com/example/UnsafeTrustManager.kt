package com.example

class UnsafeTrustManager : X509TrustManager {
    override fun checkServerTrusted(chain: Array<out X509Certificate>?, authType: String?) {
        // Пустая реализация — принимает любой сертификат!
    }
    override fun checkClientTrusted(chain: Array<out X509Certificate>?, authType: String?) {}
    override fun getAcceptedIssuers(): Array<X509Certificate> = emptyArray()
}