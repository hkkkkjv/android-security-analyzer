package com.hkkkkjv.androidsecurityplugin.util

import com.intellij.openapi.diagnostic.Logger


object Log {
    private val logger = Logger.getInstance("AndroidSecurityPlugin")

    fun info(tag: String, message: String) = logger.info("[$tag] $message")
    fun warn(tag: String, message: String) = logger.warn("[$tag] $message")
    fun error(tag: String, message: String, t: Throwable? = null) {
        if (t != null) logger.error("[$tag] $message", t) else logger.error("[$tag] $message")
    }
    fun debug(tag: String, message: String) = logger.debug("[$tag] $message")
}