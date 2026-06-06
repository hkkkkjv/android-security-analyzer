package com.hkkkkjv.androidsecurityplugin.inspection.fixes

import com.hkkkkjv.androidsecurityplugin.model.Vulnerability
import com.intellij.codeInspection.LocalQuickFix

fun createQuickFixes(vulnerability: Vulnerability): List<LocalQuickFix> {
    val id = vulnerability.id.uppercase()

    return buildList {
        when {
            id.contains("CLEARTEXT") || id.contains("MANIFEST_CLEARTEXT") -> add(DisableCleartextFix())
            id.contains("HTTP_IN_") -> add(ReplaceHttpWithHttpsFix())
            id.contains("MISSING_PINNING") || id.contains("EMPTY_PINNING") ||
                    id.contains("INVALID_PIN_HASH") || id.contains("SINGLE_PIN") ||
                    id.contains("PINNING_SINGLE") || id.contains("PINNING_MISSING") -> add(AddCertificatePinningFix())
            id.contains("USER_CERTS") -> add(ChangeUserCertsToSystemFix())
            id.contains("HOSTNAME_BYPASS") -> add(FixHostnameVerifierFix())
            id.contains("TRUST_ALL") || id.contains("CUSTOM_SSL") -> add(FixTrustManagerMethodFix())
        }
    }
}