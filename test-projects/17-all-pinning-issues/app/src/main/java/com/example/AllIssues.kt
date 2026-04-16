package com.example

import okhttp3.CertificatePinner
import okhttp3.OkHttpClient
import javax.net.ssl.*

// 1. TrustAll Manager
class UnsafeTrustManager : X509TrustManager {
    override fun checkServerTrusted(chain: Array<out java.security.cert.X509Certificate>?, authType: String?) {
        // пусто — уязвимость!
    }
    override fun checkClientTrusted(chain: Array<out java.security.cert.X509Certificate>?, authType: String?) {}
    override fun getAcceptedIssuers(): Array<java.security.cert.X509Certificate> = emptyArray()
}

// 2. HostnameVerifier bypass
class BypassVerifier : HostnameVerifier {
    override fun verify(hostname: String?, session: SSLSession?) = true
}

// 3. Single pin without backup
fun createClientWithSinglePin(): OkHttpClient {
    return OkHttpClient.Builder()
        .certificatePinner(
            CertificatePinner.Builder()
                .add("api.example.com", "sha256/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=")
                .build()
        )
        .build()
}

// 4. Domain used without any pinning
interface ApiService {
    @GET("https://unprotected.example.com/data")  // нет ни в конфиге, ни в коде
    suspend fun getData(): retrofit2.Response<String>
}
