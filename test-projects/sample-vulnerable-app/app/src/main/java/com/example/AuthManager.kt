package com.example

import android.webkit.WebView

class AuthManager {

    private val loginUrl = "http://auth.example.com/login"
    private val tokenUrl = "http://auth.example.com/token"
    private val secureUrl = "https://secure.example.com/logout"

    fun openLoginPage(webView: WebView) {
        webView.loadUrl("http://auth.example.com/login")
    }

    fun openSecurePage(webView: WebView) {
        webView.loadUrl("https://secure.example.com/profile")
    }

    fun buildAuthHeader(): String {
        return "Bearer token123"
    }
}
