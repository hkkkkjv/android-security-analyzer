package com.hkkkkjv.androidsecurityplugin.inspection.visitors

import com.hkkkkjv.androidsecurityplugin.inspection.SeverityMapper
import com.hkkkkjv.androidsecurityplugin.inspection.createQuickFixes
import com.hkkkkjv.androidsecurityplugin.model.Vulnerability
import com.intellij.codeInspection.ProblemsHolder
import com.intellij.psi.JavaElementVisitor
import com.intellij.psi.PsiAnnotation
import com.intellij.psi.PsiJavaFile
import com.intellij.psi.PsiLiteralExpression
import com.intellij.psi.PsiMethodCallExpression

class JavaSecurityVisitor(
    private val holder: ProblemsHolder,
    private val file: PsiJavaFile,
    private val vulnerabilities: List<Vulnerability>
) : JavaElementVisitor() {

    override fun visitLiteralExpression(expression: PsiLiteralExpression) {
        super.visitLiteralExpression(expression)
        processStringLiteral(expression)
    }

    override fun visitAnnotation(annotation: PsiAnnotation) {
        super.visitAnnotation(annotation)
        processRetrofitAnnotation(annotation)
    }

    override fun visitMethodCallExpression(expression: PsiMethodCallExpression) {
        super.visitMethodCallExpression(expression)
        processWebViewCall(expression)
    }

    private fun processStringLiteral(expression: PsiLiteralExpression) {
        val value = expression.value as? String ?: return
        if (!value.startsWith("http://")) return

        val relevant = filterVulnerabilitiesByDescription(value)
        for (vuln in relevant) {
            registerProblem(expression, vuln)
        }
    }

    private fun processRetrofitAnnotation(annotation: PsiAnnotation) {
        val qualifiedName = annotation.qualifiedName ?: return
        if (!qualifiedName.startsWith("retrofit2.http.")) return

        val value = annotation.findAttributeValue("value") as? PsiLiteralExpression ?: return
        val url = value.value as? String ?: return
        if (!url.startsWith("http://")) return

        val relevant = filterVulnerabilitiesById("RETROFIT")
        for (vuln in relevant) {
            registerProblem(annotation, vuln)
        }
    }

    private fun processWebViewCall(expression: PsiMethodCallExpression) {
        val method = expression.methodExpression.referenceName ?: return
        if (method != "loadUrl") return

        val argument = expression.argumentList.expressions.firstOrNull() as? PsiLiteralExpression ?: return
        val url = argument.value as? String ?: return
        if (!url.startsWith("http://")) return

        val relevant = filterVulnerabilitiesById("WEBVIEW")
        for (vuln in relevant) {
            registerProblem(argument, vuln)
        }
    }

    private fun filterVulnerabilitiesByDescription(keyword: String): List<Vulnerability> {
        val fileName = file.virtualFile?.name ?: return emptyList()
        return vulnerabilities.filter { vuln ->
            vuln.location.contains(fileName) && vuln.description.contains(keyword, ignoreCase = true)
        }
    }

    private fun filterVulnerabilitiesById(keyword: String): List<Vulnerability> {
        val fileName = file.virtualFile?.name ?: return emptyList()
        return vulnerabilities.filter { vuln ->
            vuln.location.contains(fileName) && vuln.id.contains(keyword, ignoreCase = true)
        }
    }

    private fun registerProblem(element: com.intellij.psi.PsiElement, vuln: Vulnerability) {
        holder.registerProblem(
            element,
            "[Security] ${vuln.id}: ${vuln.description}",
            SeverityMapper.mapToProblemHighlightType(vuln.severity),
            *createQuickFixes(vuln).toTypedArray()
        )
    }
}