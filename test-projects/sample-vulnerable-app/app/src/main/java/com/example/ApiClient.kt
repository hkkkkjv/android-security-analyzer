package com.example

import okhttp3.OkHttpClient
import retrofit2.Retrofit
import retrofit2.http.GET
import retrofit2.http.POST

interface ApiService {
    @GET("http://api.example.com/users")
    suspend fun getUsers()

    @POST("http://api.example.com/login")
    suspend fun login()

    @GET("/profile")
    suspend fun getProfile()
}

class ApiClient {
    fun buildRetrofit(): Retrofit {
        val client = OkHttpClient.Builder().build()
        return Retrofit.Builder()
            .baseUrl("http://api.example.com")
            .client(client)
            .build()
    }

    fun loadWebPage(webView: android.webkit.WebView) {
        webView.loadUrl("http://legacy.example.com/page")
        webView.loadUrl("https://secure.example.com/page")
    }
}
