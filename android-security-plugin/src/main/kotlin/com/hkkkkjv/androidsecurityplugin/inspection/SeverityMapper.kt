package com.hkkkkjv.androidsecurityplugin.inspection

import com.hkkkkjv.androidsecurityplugin.inspection.fixes.AddCertificatePinningFix
import com.hkkkkjv.androidsecurityplugin.inspection.fixes.DisableCleartextFix
import com.hkkkkjv.androidsecurityplugin.inspection.fixes.ReplaceHttpWithHttpsFix
import com.hkkkkjv.androidsecurityplugin.model.Vulnerability
import com.intellij.codeInspection.ProblemHighlightType

object SeverityMapper {
    fun mapToProblemHighlightType(severity: String): ProblemHighlightType {
        return when (severity.uppercase()) {
            "CRITICAL" -> ProblemHighlightType.GENERIC_ERROR
            "HIGH" -> ProblemHighlightType.WARNING
            "MEDIUM" -> ProblemHighlightType.WEAK_WARNING
            "LOW" -> ProblemHighlightType.WEAK_WARNING
            else -> ProblemHighlightType.WARNING
        }
    }
}

fun createQuickFixes(vulnerability: Vulnerability): List<com.intellij.codeInspection.LocalQuickFix> {
    val fixes = mutableListOf<com.intellij.codeInspection.LocalQuickFix>()
    when (vulnerability.id) {
        "CLEARTEXT_BASE_001", "CLEARTEXT_TRAFFIC_001", "MANIFEST_CLEARTEXT_001" ->
            fixes.add(DisableCleartextFix())

        "HTTP_IN_STRINGS_001", "HTTP_IN_CODE_001", "HTTP_IN_RETROFIT_001", "HTTP_IN_WEBVIEW_001" ->
            fixes.add(ReplaceHttpWithHttpsFix())

        "MISSING_PINNING_001", "INVALID_PIN_HASH_007", "SINGLE_PIN_001" ->
            fixes.add(AddCertificatePinningFix())
    }
    return fixes
}