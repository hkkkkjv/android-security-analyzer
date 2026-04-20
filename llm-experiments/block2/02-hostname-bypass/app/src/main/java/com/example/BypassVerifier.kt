package com.example

public class BypassVerifier implements HostnameVerifier {
    @Override
    public boolean verify(String hostname, SSLSession session) {
        return true; // Отключает проверку имени хоста!
    }
}