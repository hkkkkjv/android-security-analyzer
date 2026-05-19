package com.hkkkkjv.androidsecurityplugin.annotation

import com.hkkkkjv.androidsecurityplugin.model.Vulnerability
import com.hkkkkjv.androidsecurityplugin.psi.PsiLocationMapper
import com.hkkkkjv.androidsecurityplugin.service.SecurityAnalyzerService
import com.intellij.lang.annotation.AnnotationHolder
import com.intellij.lang.annotation.ExternalAnnotator
import com.intellij.lang.annotation.HighlightSeverity
import com.intellij.openapi.application.ApplicationManager
import com.intellij.openapi.diagnostic.thisLogger
import com.intellij.openapi.util.TextRange
import com.intellij.psi.PsiFile
import kotlinx.coroutines.runBlocking
import java.io.File

class SecurityAnnotator : ExternalAnnotator<SecurityAnnotator.FileInfo, List<Vulnerability>>() {
    private val logger = thisLogger()

    data class FileInfo(
        val psiFile: PsiFile,
        val projectPath: String,
        val filePath: String
    )

    override fun collectInformation(file: PsiFile): FileInfo? {
        logger.info("[ANNOTATOR] collectInformation() called for: ${file.name}")

        val projectPath = file.project.basePath
        logger.debug("[ANNOTATOR] Project path: $projectPath")

        val virtualFile = file.virtualFile
        logger.debug("[ANNOTATOR] Virtual file: ${virtualFile?.path}")

        if (projectPath == null || virtualFile == null) {
            logger.warn("[ANNOTATOR] collectInformation returning null (projectPath=$projectPath, virtualFile=$virtualFile)")
            return null
        }

        val result = FileInfo(
            psiFile = file,
            projectPath = projectPath,
            filePath = virtualFile.path
        )
        logger.info("[ANNOTATOR] collectInformation returning: ${result.filePath}")
        return result
    }

    override fun doAnnotate(collectedInfo: FileInfo): List<Vulnerability>? {
        logger.info("[ANNOTATOR] doAnnotate() called for: ${collectedInfo.filePath}")

        if (ApplicationManager.getApplication().isDispatchThread) {
            logger.warn("[ANNOTATOR] doAnnotate called on EDT — skipping to avoid deadlock")
            return null
        }

        val service = collectedInfo.psiFile.project
            .getService(SecurityAnalyzerService::class.java)

        if (service == null) {
            logger.warn("[ANNOTATOR] SecurityAnalyzerService NOT FOUND")
            return null
        }
        logger.info("[ANNOTATOR] Got SecurityAnalyzerService instance")

        return try {
            logger.info("[ANNOTATOR] Calling analyzeProjectAsync...")
            val result = runBlocking {
                service.analyzeProjectAsync(collectedInfo.projectPath)
            }
            logger.info("[ANNOTATOR] analyzeProjectAsync returned ${result.size} vulnerabilities")
            result
        } catch (e: Exception) {
            logger.error("[ANNOTATOR] Analysis failed: ${e.message}", e)
            emptyList()
        }
    }

    override fun apply(
        file: PsiFile,
        annotationResult: List<Vulnerability>?,
        holder: AnnotationHolder
    ) {
        logger.info("[ANNOTATOR] apply() called for: ${file.name}")

        if (annotationResult.isNullOrEmpty()) {
            logger.info("[ANNOTATOR] No vulnerabilities to annotate (result is null or empty)")
            return
        }
        logger.info("[ANNOTATOR] Got ${annotationResult.size} vulnerabilities to apply")

        val projectPath = file.project.basePath
        val virtualFile = file.virtualFile

        if (projectPath == null || virtualFile == null) {
            logger.warn("[ANNOTATOR] Cannot apply: projectPath=$projectPath or virtualFile=$virtualFile is null")
            return
        }

        val currentFilePath = File(virtualFile.path).canonicalPath
        logger.info("[ANNOTATOR] Current file canonical path: $currentFilePath")

        val mapper = PsiLocationMapper(file.project)
        logger.info("[ANNOTATOR] Created PsiLocationMapper")

        // Фильтрация уязвимостей для текущего файла
        val fileVulnerabilities = annotationResult.filter { vuln ->
            val matches = matchesFile(vuln.location, projectPath, currentFilePath)
            if (matches) {
                logger.debug("[MATCH] Vulnerability ${vuln.id} matches this file: ${vuln.location}")
            }
            matches
        }

        logger.info("[ANNOTATOR] Filtered to ${fileVulnerabilities.size} vulnerabilities for this file")

        if (fileVulnerabilities.isEmpty()) {
            logger.info("[ANNOTATOR] No vulnerabilities match this file, skipping annotation")
            return
        }

        // Применение аннотаций
        var annotatedCount = 0
        for (vuln in fileVulnerabilities) {
            logger.info("[ANNOTATOR] Processing vulnerability: ${vuln.id} at ${vuln.location}")
            val psiElement = mapper.mapToPsiElement(vuln.location, projectPath)
            if (psiElement == null) {
                logger.warn("[ANNOTATOR] Could not map location to PSI element: ${vuln.location}")
                continue
            }
            if (!psiElement.isValid) {
                logger.warn("[ANNOTATOR] PSI element is invalid: ${vuln.location}")
                continue
            }
            logger.info("[ANNOTATOR] Mapped to PSI element: ${psiElement.text.take(50)}...")

            val severity = mapHighlightSeverity(vuln.severity)
            val message = buildTooltipHtml(vuln)
            val range = psiElement.textRange

            if (range == null || range.isEmpty) {
                logger.warn("[ANNOTATOR] TextRange is null or empty for ${vuln.location}")
                continue
            }
            logger.info("[ANNOTATOR] TextRange: ${range.startOffset}-${range.endOffset}")

            // Создание аннотации
            try {
                holder.newAnnotation(severity, "[Security] ${vuln.id}")
                    .range(TextRange(range.startOffset, range.endOffset))
                    .tooltip(message)
                    .create()
                annotatedCount++
                logger.info("[ANNOTATOR] Created annotation for ${vuln.id}")
            } catch (e: Exception) {
                logger.error("[ANNOTATOR] Failed to create annotation for ${vuln.id}: ${e.message}", e)
            }
        }

        logger.info("[ANNOTATOR] apply() DONE. Created $annotatedCount annotations out of ${fileVulnerabilities.size} vulnerabilities")
    }

    private fun matchesFile(location: String, projectPath: String, currentCanonicalPath: String): Boolean {
        logger.debug("[MATCH] Checking if '$location' matches '$currentCanonicalPath'")

        val relativePath = location.substringBeforeLast(":").replace("\\", "/")
        logger.debug("[MATCH] Extracted relative path: $relativePath")

        // Проверка как абсолютного пути
        val asAbsolute = File(relativePath).canonicalPath
        logger.debug("[MATCH] As absolute: $asAbsolute")
        if (asAbsolute == currentCanonicalPath) {
            logger.debug("[MATCH] Matched as absolute path")
            return true
        }

        // Проверка как относительного пути
        val asRelative = File(projectPath, relativePath).canonicalPath
        logger.debug("[MATCH] As relative to project: $asRelative")
        if (asRelative == currentCanonicalPath) {
            logger.debug("[MATCH] Matched as relative path")
            return true
        }

        logger.debug("[MATCH] No match")
        return false
    }

    private fun mapHighlightSeverity(severity: String): HighlightSeverity {
        return when (severity.uppercase()) {
            "CRITICAL" -> HighlightSeverity.ERROR
            "HIGH" -> HighlightSeverity.WARNING
            "MEDIUM" -> HighlightSeverity.WEAK_WARNING
            "LOW" -> HighlightSeverity.INFORMATION
            else -> HighlightSeverity.WARNING
        }.also { logger.debug("[SEVERITY] Mapped '$severity' -> $it") }
    }

    private fun buildTooltipHtml(vuln: Vulnerability): String {
        return buildString {
            append("<html><body>")
            append("<b style='font-size:1.1em;'>${escapeHtml(vuln.id)}</b><br>")
            append("Severity: ${escapeHtml(vuln.severity)} | CVSS: ${vuln.cvssScore}<br><br>")
            append("<b>Description:</b><br>")
            append("${escapeHtml(vuln.description)}<br><br>")
            append("<b>Recommendation:</b><br>")
            append(escapeHtml(vuln.recommendation))
            append("</body></html>")
        }
    }

    private fun escapeHtml(text: String): String {
        return text.replace("&", "&amp;")
            .replace("<", "&lt;")
            .replace(">", "&gt;")
            .replace("\"", "&quot;")
    }
}