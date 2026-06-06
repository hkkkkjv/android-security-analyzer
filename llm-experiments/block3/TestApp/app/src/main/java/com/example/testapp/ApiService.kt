package com.example.testapp

import okhttp3.OkHttpClient
import retrofit2.Retrofit
import retrofit2.converter.gson.GsonConverterFactory
import retrofit2.http.GET
import retrofit2.http.POST

interface ApiService {
    @GET("http://api.retrofit-example.com/users")
    suspend fun getUsers(): List<User>

    @POST("http://api.retrofit-example.com/login")
    suspend fun login(): Response
}

object ApiClient {
    private const val BASE_URL = "http://api.production.com/v2/"

    val client: OkHttpClient = OkHttpClient.Builder()
        .build()

    val retrofit: Retrofit = Retrofit.Builder()
        .baseUrl(BASE_URL)
        .client(client)
        .addConverterFactory(GsonConverterFactory.create())
        .build()

    val service: ApiService = retrofit.create(ApiService::class.java)
}

class Config {
    companion object {
        const val DEV_API_URL = "http://dev.api.example.com/test"
        const val STAGING_URL = "http://staging.example.com/api"
    }
}

data class User(val id: Int, val name: String)
data class Response(val success: Boolean)