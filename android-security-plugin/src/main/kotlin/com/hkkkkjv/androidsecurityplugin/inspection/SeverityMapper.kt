package com.hkkkkjv.androidsecurityplugin.inspection

import com.intellij.codeInspection.ProblemHighlightType
import com.intellij.lang.annotation.HighlightSeverity

object SeverityMapper {

    fun mapToProblemHighlightType(severity: String): ProblemHighlightType = when (severity.uppercase()) {
        "CRITICAL" -> ProblemHighlightType.GENERIC_ERROR
        "HIGH" -> ProblemHighlightType.WARNING
        "MEDIUM" -> ProblemHighlightType.WEAK_WARNING
        "LOW" -> ProblemHighlightType.WEAK_WARNING
        else -> ProblemHighlightType.WARNING
    }

    fun mapToHighlightSeverity(severity: String): HighlightSeverity = when (severity.uppercase()) {
        "CRITICAL" -> HighlightSeverity.ERROR
        "HIGH" -> HighlightSeverity.WARNING
        "MEDIUM" -> HighlightSeverity.WEAK_WARNING
        "LOW" -> HighlightSeverity.INFORMATION
        else -> HighlightSeverity.WARNING
    }
}
