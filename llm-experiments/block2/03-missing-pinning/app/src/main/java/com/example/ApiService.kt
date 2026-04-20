package com.example

interface ApiService {
    @GET("https://api.example.com/data") 
    suspend fun getData(): Response<Data>
}