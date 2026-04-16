package com.example

import retrofit2.http.GET
import retrofit2.Response

interface ApiService {
    @GET("https://api.example.com/data")  // домен НЕ в конфиге и нет CertificatePinner
    suspend fun getData(): Response<Data>
}
