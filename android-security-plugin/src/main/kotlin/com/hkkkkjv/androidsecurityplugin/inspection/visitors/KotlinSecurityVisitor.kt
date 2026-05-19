package com.hkkkkjv.androidsecurityplugin.inspection.visitors

import com.hkkkkjv.androidsecurityplugin.inspection.SeverityMapper
import com.hkkkkjv.androidsecurityplugin.inspection.createQuickFixes
import com.hkkkkjv.androidsecurityplugin.model.Vulnerability
import com.intellij.codeInspection.ProblemsHolder
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

        private val RETROFIT_ANNOTATIONS = setOf(
            "GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"
        )
    }

    override fun visitElement(element: PsiElement) {
        element.acceptChildren(this)

        when (element.javaClass.simpleName) {
            KT_STRING_TEMPLATE -> processStringTemplate(element)
            KT_ANNOTATION_ENTRY -> processAnnotation(element)
            KT_CALL_EXPRESSION -> processCallExpression(element)
        }
    }

    private fun processStringTemplate(element: PsiElement) {
        // text включает кавычки: "http://..." → убираем их
        val raw = element.text.removeSurrounding("\"").removeSurrounding("\"\"\"")
        if (!raw.contains("http://", ignoreCase = true)) return

        filterByDescription(raw).forEach { vuln ->
            registerProblem(element, vuln)
        }
    }

    private fun processAnnotation(element: PsiElement) {
        // Получаем короткое имя аннотации из первого дочернего элемента типа KtNameReferenceExpression
        val shortName = element.children
            .firstOrNull { it.javaClass.simpleName == "KtNameReferenceExpression" }
            ?.text ?: return

        if (shortName !in RETROFIT_ANNOTATIONS) return

        // Ищем первый строковый аргумент внутри аннотации
        val urlString = findFirstStringTemplate(element)?.let { extractStringText(it) } ?: return
        if (!urlString.startsWith("http://")) return

        filterById("RETROFIT").forEach { vuln ->
            registerProblem(element, vuln)
        }
    }

    private fun processCallExpression(element: PsiElement) {
        // KtCallExpression: calleeExpression + valueArgumentList
        val calleeText = element.children
            .firstOrNull { it.javaClass.simpleName == "KtNameReferenceExpression" }
            ?.text ?: return

        if (calleeText != "loadUrl") return

        // Ищем первый строковый аргумент
        val urlString = findFirstStringTemplate(element)?.let { extractStringText(it) } ?: return
        if (!urlString.startsWith("http://")) return

        filterById("WEBVIEW").forEach { vuln ->
            // Регистрируем проблему на самом строковом аргументе, а не на всём вызове
            val stringElement = findFirstStringTemplate(element) ?: element
            registerProblem(stringElement, vuln)
        }
    }

    // --- PSI tree helpers ---

    /** Ищет первый KtStringTemplateExpression в поддереве элемента */
    private fun findFirstStringTemplate(element: PsiElement): PsiElement? {
        if (element.javaClass.simpleName == KT_STRING_TEMPLATE) return element
        for (child in element.children) {
            val found = findFirstStringTemplate(child)
            if (found != null) return found
        }
        return null
    }

    /** Извлекает текст строки без кавычек */
    private fun extractStringText(stringTemplate: PsiElement): String {
        return stringTemplate.text
            .removeSurrounding("\"\"\"")
            .removeSurrounding("\"")
    }

    // --- filtering & reporting ---

    private fun filterByDescription(keyword: String): List<Vulnerability> {
        val fileName = file.virtualFile?.name ?: return emptyList()
        return vulnerabilities.filter { v ->
            v.location.contains(fileName) &&
                    v.description.contains(keyword, ignoreCase = true)
        }
    }

    private fun filterById(keyword: String): List<Vulnerability> {
        val fileName = file.virtualFile?.name ?: return emptyList()
        return vulnerabilities.filter { v ->
            v.location.contains(fileName) &&
                    v.id.contains(keyword, ignoreCase = true)
        }
    }

    private fun registerProblem(element: PsiElement, vuln: Vulnerability) {
        if (!element.isValid) return
        holder.registerProblem(
            element,
            "[Security] ${vuln.id}: ${vuln.description}",
            SeverityMapper.mapToProblemHighlightType(vuln.severity),
            *createQuickFixes(vuln).toTypedArray()
        )
    }
}