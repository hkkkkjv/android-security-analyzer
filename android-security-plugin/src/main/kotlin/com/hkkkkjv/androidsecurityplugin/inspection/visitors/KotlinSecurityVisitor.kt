package com.hkkkkjv.androidsecurityplugin.inspection.visitors

import com.hkkkkjv.androidsecurityplugin.inspection.SeverityMapper
import com.hkkkkjv.androidsecurityplugin.inspection.fixes.createQuickFixes
import com.hkkkkjv.androidsecurityplugin.model.Vulnerability
import com.hkkkkjv.androidsecurityplugin.util.PsiUtils
import com.intellij.codeInspection.ProblemsHolder
import com.intellij.openapi.util.TextRange
import com.intellij.psi.PsiElement
import com.intellij.psi.PsiElementVisitor
import com.intellij.psi.PsiFile

class KotlinSecurityVisitor(
    private val holder: ProblemsHolder,
    private val file: PsiFile,
    private val vulnerabilities: List<Vulnerability>
) : PsiElementVisitor() {

    companion object {
        private const val KT_STRING_TEMPLATE = "KtStringTemplateExpression"
        private const val KT_ANNOTATION_ENTRY = "KtAnnotationEntry"
        private const val KT_CALL_EXPRESSION = "KtCallExpression"
        private const val KT_NAME_REFERENCE = "KtNameReferenceExpression"
        private const val KT_IDENTIFIER = "KtIdentifier"

        private val RETROFIT_ANNOTATIONS = setOf("GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS")
        private val URL_STOP_CHARS = charArrayOf('"', '\'', ' ', '\n', '\r', ')', ']', '}')
    }

    private val registeredProblems = mutableSetOf<String>()
    private val vulnerabilitiesByLine: Map<Int, List<Vulnerability>> by lazy { buildVulnerabilitiesByLine() }

    private fun buildVulnerabilitiesByLine(): Map<Int, List<Vulnerability>> {
        val fileName = file.virtualFile?.name ?: return emptyMap()
        return vulnerabilities
            .filter { it.location.contains(fileName) }
            .groupBy { PsiUtils.extractLineNumber(it.location) }
            .filterKeys { it > 0 }
    }

    override fun visitElement(element: PsiElement) {
        when (element.javaClass.simpleName) {
            KT_ANNOTATION_ENTRY -> processAnnotation(element)
            KT_CALL_EXPRESSION -> processCallExpression(element)
            KT_STRING_TEMPLATE -> processStringTemplate(element)
            "KtClass", "KtObjectDeclaration" -> processClassDeclaration(element)
            "KtNamedFunction" -> processFunctionDeclaration(element)
        }
        element.acceptChildren(this)
    }

    private fun processStringTemplate(element: PsiElement) {
        val raw = element.text.removeSurrounding("\"\"\"").removeSurrounding("\"")
        if (!raw.contains("http://", ignoreCase = true)) return

        val lineNumber = PsiUtils.getLineNumber(element)
        vulnerabilitiesByLine[lineNumber]
            ?.filter { it.description.contains(raw, ignoreCase = true) }
            ?.forEach { registerProblemAtUrlPosition(element, it, raw) }
    }

    private fun processAnnotation(element: PsiElement) {
        val shortName = element.children.firstOrNull { it.javaClass.simpleName == KT_NAME_REFERENCE }?.text
            ?: return
        if (shortName !in RETROFIT_ANNOTATIONS) return

        val urlTemplate = findFirstStringTemplate(element) ?: return
        val urlString = extractStringText(urlTemplate)
        if (!urlString.startsWith("http://")) return

        val lineNumber = PsiUtils.getLineNumber(element)
        vulnerabilitiesByLine[lineNumber]
            ?.filter { it.id.contains("RETROFIT", ignoreCase = true) }
            ?.forEach { registerProblemAtUrlPosition(urlTemplate, it, urlString) }
    }

    private fun processCallExpression(element: PsiElement) {
        val calleeText = element.children.firstOrNull { it.javaClass.simpleName == KT_NAME_REFERENCE }?.text
            ?: return
        if (calleeText != "loadUrl") return

        val urlString = findFirstStringTemplate(element)?.let { extractStringText(it) } ?: return
        if (!urlString.startsWith("http://")) return

        val lineNumber = PsiUtils.getLineNumber(element)
        vulnerabilitiesByLine[lineNumber]
            ?.filter { it.id.contains("WEBVIEW", ignoreCase = true) }
            ?.forEach { registerProblemOnce(findFirstStringTemplate(element) ?: element, it) }
    }

    private fun processClassDeclaration(element: PsiElement) {
        val text = element.text
        val lineNumber = PsiUtils.getLineNumber(element)
        val nameElement = element.children.firstOrNull { it.javaClass.simpleName == KT_IDENTIFIER } ?: element

        when {
            text.contains("X509TrustManager") -> vulnerabilitiesByLine[lineNumber]
                ?.filter { it.id.contains("TRUST_ALL", ignoreCase = true) }
                ?.forEach { registerProblemOnce(nameElement, it) }

            text.contains("HostnameVerifier") -> vulnerabilitiesByLine[lineNumber]
                ?.filter { it.id.contains("HOSTNAME_BYPASS", ignoreCase = true) }
                ?.forEach { registerProblemOnce(nameElement, it) }
        }
    }

    private fun processFunctionDeclaration(element: PsiElement) {
        if (!element.text.startsWith("fun verify") && !element.text.startsWith("override fun verify")) return

        val parentText = element.parent?.text ?: return
        if (!parentText.contains("HostnameVerifier")) return

        val lineNumber = PsiUtils.getLineNumber(element)
        vulnerabilitiesByLine[lineNumber]
            ?.filter { it.id.contains("HOSTNAME_BYPASS", ignoreCase = true) }
            ?.forEach { registerProblemOnce(element, it) }
    }

    private fun findFirstStringTemplate(element: PsiElement): PsiElement? {
        if (element.javaClass.simpleName == KT_STRING_TEMPLATE) return element
        return element.children.firstNotNullOfOrNull { findFirstStringTemplate(it) }
    }

    private fun extractStringText(stringTemplate: PsiElement): String =
        stringTemplate.text.removeSurrounding("\"\"\"").removeSurrounding("\"")

    private fun registerProblemOnce(element: PsiElement, vuln: Vulnerability) {
        if (!element.isValid) return

        val literalElement = findActualStringLiteral(element) ?: element
        val range = literalElement.textRange
        if (range.isEmpty || range.startOffset < 0) return

        val key = "${vuln.id}:${range.startOffset}"
        if (!registeredProblems.add(key)) return

        holder.registerProblem(
            literalElement,
            "[Security] ${vuln.id}: ${vuln.description}",
            SeverityMapper.mapToProblemHighlightType(vuln.severity),
            *createQuickFixes(vuln).toTypedArray()
        )
    }

    private fun findActualStringLiteral(element: PsiElement): PsiElement? {
        if (element.javaClass.simpleName == KT_STRING_TEMPLATE) return element
        return element.children.firstNotNullOfOrNull { findActualStringLiteral(it) }
    }

    private fun registerProblemAtUrlPosition(stringTemplate: PsiElement, vuln: Vulnerability, urlString: String) {
        if (!stringTemplate.isValid) return

        val urlStartInText = stringTemplate.text.indexOf("http://", ignoreCase = true)
        if (urlStartInText == -1) {
            registerProblemOnce(stringTemplate, vuln)
            return
        }

        val templateStartOffset = stringTemplate.textRange.startOffset
        val urlStartOffset = templateStartOffset + urlStartInText
        val urlEndOffset = calculateUrlEndOffset(stringTemplate.text, urlStartInText, templateStartOffset)
        val urlRange = TextRange(urlStartOffset, urlEndOffset)

        val key = "${vuln.id}:${urlStartOffset}"
        if (!registeredProblems.add(key)) return

        try {
            holder.registerProblem(
                stringTemplate,
                "[Security] ${vuln.id}: ${vuln.description}",
                SeverityMapper.mapToProblemHighlightType(vuln.severity),
                urlRange,
                *createQuickFixes(vuln).toTypedArray()
            )
        } catch (e: Exception) {
            registerProblemOnce(stringTemplate, vuln)
        }
    }

    private fun calculateUrlEndOffset(text: String, urlStartInText: Int, templateStartOffset: Int): Int {
        val remainingText = text.substring(urlStartInText)
        val urlLength = remainingText.takeWhile { it !in URL_STOP_CHARS }.length
        return templateStartOffset + urlStartInText + urlLength
    }
}