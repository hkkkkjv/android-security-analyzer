package com.example

import retrofit2.http.GET
import retrofit2.http.POST

interface AnalyticsService {
    @GET("https://analytics.example.com/events")
    suspend fun getEvents()

    @POST("https://analytics.example.com/track")
    suspend fun trackEvent()
}

class AnalyticsManager {
    // Все запросы идут только по HTTPS
    private val baseUrl = "https://analytics.example.com"

    fun buildUrl(path: String): String {
        return "$baseUrl/$path"
    }
}
