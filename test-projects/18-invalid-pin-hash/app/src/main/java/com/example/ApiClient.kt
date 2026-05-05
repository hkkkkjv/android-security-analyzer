package com.example

import okhttp3.OkHttpClient

object ApiClient {
    fun createClient(): OkHttpClient {
        return OkHttpClient.Builder().build()
    }
}