package com.hkkkkjv.androidsecurityplugin.annotation

import com.hkkkkjv.androidsecurityplugin.inspection.SeverityMapper
import com.hkkkkjv.androidsecurityplugin.inspection.fixes.createQuickFixes
import com.hkkkkjv.androidsecurityplugin.model.Vulnerability
import com.hkkkkjv.androidsecurityplugin.psi.PsiLocationMapper
import com.hkkkkjv.androidsecurityplugin.service.SecurityAnalyzerService
import com.hkkkkjv.androidsecurityplugin.util.Log
import com.intellij.lang.annotation.AnnotationHolder
import com.intellij.lang.annotation.ExternalAnnotator
import com.intellij.openapi.application.ApplicationManager
import com.intellij.openapi.util.TextRange
import com.intellij.psi.PsiFile
import kotlinx.coroutines.runBlocking
import java.io.File

class SecurityAnnotator : ExternalAnnotator<SecurityAnnotator.FileInfo, List<Vulnerability>>() {

    companion object {
        private const val TAG = "ANNOTATOR"
    }

    data class FileInfo(
        val psiFile: PsiFile,
        val projectPath: String,
        val filePath: String
    )

    override fun collectInformation(file: PsiFile): FileInfo? {
        val projectPath = file.project.basePath
        val virtualFile = file.virtualFile

        if (projectPath == null || virtualFile == null) {
            Log.warn(TAG, "collectInformation returning null")
            return null
        }

        Log.info(TAG, "collectInformation: ${virtualFile.path}")
        return FileInfo(file, projectPath, virtualFile.path)
    }

    override fun doAnnotate(collectedInfo: FileInfo): List<Vulnerability>? {
        Log.info(TAG, "doAnnotate: ${collectedInfo.filePath}")

        if (ApplicationManager.getApplication().isDispatchThread) {
            Log.warn(TAG, "doAnnotate called on EDT — skipping")
            return null
        }

        val service = collectedInfo.psiFile.project.getService(SecurityAnalyzerService::class.java)
            ?: return null.also { Log.warn(TAG, "SecurityAnalyzerService NOT FOUND") }

        return try {
            runBlocking { service.analyzeProjectAsync(collectedInfo.projectPath) }
        } catch (e: Exception) {
            Log.error(TAG, "Analysis failed: ${e.message}", e)
            emptyList()
        }
    }

    override fun apply(file: PsiFile, annotationResult: List<Vulnerability>?, holder: AnnotationHolder) {
        if (annotationResult.isNullOrEmpty()) return

        val projectPath = file.project.basePath ?: return
        val virtualFile = file.virtualFile ?: return
        val currentFilePath = File(virtualFile.path).canonicalPath
        val mapper = PsiLocationMapper(file.project)

        val fileVulnerabilities = annotationResult.filter { matchesFile(it.location, projectPath, currentFilePath) }
        if (fileVulnerabilities.isEmpty()) return

        Log.info(TAG, "Applying ${fileVulnerabilities.size} annotations to ${file.name}")

        fileVulnerabilities.forEach { vuln -> applyAnnotation(vuln, mapper, projectPath, holder) }
    }

    private fun applyAnnotation(
        vuln: Vulnerability,
        mapper: PsiLocationMapper,
        projectPath: String,
        holder: AnnotationHolder
    ) {
        val psiElement = mapper.mapToPsiElement(vuln.location, projectPath)
        if (psiElement == null || !psiElement.isValid) {
            Log.warn(TAG, "Could not map location to PSI: ${vuln.location}")
            return
        }

        val range = psiElement.textRange
        if (range == null || range.isEmpty) return

        try {
            holder.newAnnotation(SeverityMapper.mapToHighlightSeverity(vuln.severity), "[Security] ${vuln.id}")
                .range(TextRange(range.startOffset, range.endOffset))
                .tooltip(buildTooltipHtml(vuln))
                .apply { createQuickFixes(vuln).filterIsInstance<com.intellij.codeInsight.intention.IntentionAction>().forEach { withFix(it) } }
                .create()
        } catch (e: Exception) {
            Log.error(TAG, "Failed to create annotation for ${vuln.id}", e)
        }
    }

    private fun matchesFile(location: String, projectPath: String, currentCanonicalPath: String): Boolean {
        val relativePath = location.substringBeforeLast(":").replace("\\", "/")
        val asAbsolute = File(relativePath).canonicalPath
        if (asAbsolute == currentCanonicalPath) return true
        return File(projectPath, relativePath).canonicalPath == currentCanonicalPath
    }

    private fun buildTooltipHtml(vuln: Vulnerability): String = buildString {
        append("<html><body>")
        append("<b style='font-size:1.1em;'>${escapeHtml(vuln.id)}</b><br>")
        append("Severity: ${escapeHtml(vuln.severity)} | CVSS: ${vuln.cvssScore}<br><br>")
        append("<b>Description:</b><br>${escapeHtml(vuln.description)}<br><br>")
        append("<b>Recommendation:</b><br>${escapeHtml(vuln.recommendation)}")
        append("</body></html>")
    }

    private fun escapeHtml(text: String): String = text
        .replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace("\"", "&quot;")
}