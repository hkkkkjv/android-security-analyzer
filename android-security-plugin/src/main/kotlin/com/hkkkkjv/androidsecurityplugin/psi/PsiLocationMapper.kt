package com.hkkkkjv.androidsecurityplugin.psi

import com.intellij.openapi.project.Project
import com.intellij.openapi.util.TextRange
import com.intellij.openapi.vfs.LocalFileSystem
import com.intellij.psi.PsiDocumentManager
import com.intellij.psi.PsiElement
import com.intellij.psi.PsiManager
import com.intellij.psi.xml.XmlAttribute
import com.intellij.psi.xml.XmlTag
import java.io.File

class PsiLocationMapper(private val project: Project) {

    companion object {
        private val KEYWORDS = listOf(
            "http://", "https://", "loadUrl", "setHostnameVerifier", "sslSocketFactory",
            "cleartextTrafficPermitted", "usesCleartextTraffic", "pin-set", "CertificatePinner",
            "networkSecurityConfig", "certificates", "digest", "src", "uses-permission",
            "android.permission", "domain-config", "base-config", "pin", "backup-pins",
            "trust-anchors", "application", "manifest", "X509TrustManager", "checkServerTrusted",
            "checkClientTrusted", "HostnameVerifier", "verify"
        )
    }

    fun mapToPsiElement(location: String, projectBasePath: String): PsiElement? {
        val (relativePath, targetLine) = parseLocation(location)
        if (targetLine < 1) return null

        val absolutePath = resolveAbsolutePath(relativePath, projectBasePath)
        val virtualFile = LocalFileSystem.getInstance().refreshAndFindFileByPath(absolutePath) ?: return null
        if (!virtualFile.isValid) return null

        val psiFile = PsiManager.getInstance(project).findFile(virtualFile) ?: return null
        val document = PsiDocumentManager.getInstance(project).getDocument(psiFile) ?: return null

        val lineIndex = targetLine - 1
        if (lineIndex < 0 || lineIndex >= document.lineCount) return null

        val lineStart = document.getLineStartOffset(lineIndex)
        val lineEnd = document.getLineEndOffset(lineIndex)
        val lineText = document.getText(TextRange(lineStart, lineEnd))
        val isXmlFile = relativePath.endsWith(".xml", ignoreCase = true)

        return findElementAtLine(psiFile, lineText, lineStart, lineEnd, isXmlFile)
            ?: psiFile.findElementAt(lineStart)
    }

    private fun resolveAbsolutePath(relativePath: String, projectBasePath: String): String {
        val file = File(relativePath)
        return if (file.isAbsolute) file.canonicalPath else File(projectBasePath, relativePath).canonicalPath
    }

    private fun findElementAtLine(
        psiFile: com.intellij.psi.PsiFile,
        lineText: String,
        lineStart: Int,
        lineEnd: Int,
        isXmlFile: Boolean
    ): PsiElement? {
        findElementByKeyword(lineText, "http://", lineStart, psiFile, isXmlFile)?.let { return it }

        for (keyword in KEYWORDS) {
            findElementByKeyword(lineText, keyword, lineStart, psiFile, isXmlFile)?.let { return it }
        }

        for (offset in lineStart..lineEnd) {
            val element = psiFile.findElementAt(offset)
            if (element != null && element.textRange.length > 0) {
                return if (isXmlFile) findXmlAttributeOrTagParent(element) ?: element else element
            }
        }
        return null
    }

    private fun findElementByKeyword(
        lineText: String,
        keyword: String,
        lineStart: Int,
        psiFile: com.intellij.psi.PsiFile,
        isXmlFile: Boolean
    ): PsiElement? {
        val index = lineText.indexOf(keyword, ignoreCase = true)
        if (index == -1) return null

        val element = psiFile.findElementAt(lineStart + index) ?: return null
        if (element.textRange.length == 0) return null

        return when {
            isXmlFile && keyword == "http://" -> findXmlAttributeParent(element) ?: element
            isXmlFile -> findXmlAttributeOrTagParent(element) ?: element
            keyword == "http://" -> findStringLiteralParent(element) ?: element
            else -> element
        }
    }

    private fun findStringLiteralParent(element: PsiElement): PsiElement? {
        var current: PsiElement? = element
        while (current != null) {
            val className = current.javaClass.simpleName
            if (className == "KtStringTemplateExpression" || className == "PsiLiteralExpression") return current
            if (className.contains("File") || className.contains("Class") || className.contains("Function")) break
            current = current.parent
        }
        return null
    }

    private fun findXmlAttributeOrTagParent(element: PsiElement): PsiElement? {
        var current: PsiElement? = element
        while (current != null) {
            if (current is XmlAttribute) return current
            if (current is XmlTag) return current
            val className = current.javaClass.simpleName
            if (className.contains("File") || className.contains("Document")) break
            current = current.parent
        }
        return null
    }

    private fun findXmlAttributeParent(element: PsiElement): PsiElement? {
        var current: PsiElement? = element
        while (current != null) {
            if (current is XmlAttribute) return current
            val className = current.javaClass.simpleName
            if (className.contains("File") || className.contains("Document")) break
            current = current.parent
        }
        return null
    }

    private fun parseLocation(location: String): Pair<String, Int> {
        val lastColon = location.lastIndexOf(':')
        if (lastColon <= 0 || lastColon == location.length - 1) return Pair(location, -1)
        val path = location.substring(0, lastColon)
        val line = location.substring(lastColon + 1).toIntOrNull() ?: return Pair(location, -1)
        return Pair(path, line)
    }
}