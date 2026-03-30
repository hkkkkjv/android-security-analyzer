package com.example

import okhttp3.OkHttpClient
import retrofit2.Retrofit
import retrofit2.http.GET
import retrofit2.http.POST
import retrofit2.http.DELETE

interface UserService {
    @GET("http://users.example.com/list")
    suspend fun getUsers()

    @POST("http://users.example.com/create")
    suspend fun createUser()

    @DELETE("/user")
    suspend fun deleteUser()

    @GET("https://users.example.com/admin")
    suspend fun getAdminUsers()
}

object NetworkConfig {
    fun provideRetrofit(): Retrofit {
        return Retrofit.Builder()
            .baseUrl("http://users.example.com")
            .client(OkHttpClient())
            .build()
    }
}
