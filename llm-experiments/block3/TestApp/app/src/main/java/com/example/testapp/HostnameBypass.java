package com.example.testapp;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.SSLSession;

// CRITICAL: HostnameVerifier, всегда возвращающий true
public class HostnameBypass implements HostnameVerifier {

    @Override
    public boolean verify(String hostname, SSLSession session) {
        // Всегда возвращает true — отключает проверку hostname
        return true;
    }
}

// Альтернативная реализация через лямбду
class HostnameBypassLambda {
    HostnameVerifier verifier = (hostname, session) -> true;
}
