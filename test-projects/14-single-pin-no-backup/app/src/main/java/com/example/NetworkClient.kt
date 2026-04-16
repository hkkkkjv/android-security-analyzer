package com.example

import okhttp3.CertificatePinner
import okhttp3.OkHttpClient

object NetworkClient {
    fun createClient(): OkHttpClient {
        return OkHttpClient.Builder()
            .certificatePinner(
                CertificatePinner.Builder()
                    .add("api.example.com", "sha256/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=")
                    // ❌ Только один пин — нет резервного!
                    .build()
            )
            .build()
    }
}
