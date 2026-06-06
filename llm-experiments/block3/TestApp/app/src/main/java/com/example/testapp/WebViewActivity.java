package com.example.testapp;

import android.app.Activity;
import android.os.Bundle;
import android.webkit.WebView;

public class WebViewActivity extends Activity {

    private WebView webView;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        webView = new WebView(this);

        // HIGH: WebView.loadUrl с HTTP
        webView.loadUrl("http://m.example.com/mobile");
        webView.loadUrl("http://help.example.com/faq");

        // Безопасный вызов
        webView.loadUrl("https://secure.example.com");

        setContentView(webView);
    }
}