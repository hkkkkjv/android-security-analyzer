package com.hkkkkjv.androidsecurityplugin.inspection.visitors

import com.hkkkkjv.androidsecurityplugin.inspection.SeverityMapper
import com.hkkkkjv.androidsecurityplugin.inspection.fixes.createQuickFixes
import com.hkkkkjv.androidsecurityplugin.model.Vulnerability
import com.hkkkkjv.androidsecurityplugin.util.PsiUtils
import com.intellij.codeInspection.ProblemsHolder
import com.intellij.psi.JavaElementVisitor
import com.intellij.psi.PsiAnnotation
import com.intellij.psi.PsiClass
import com.intellij.psi.PsiElement
import com.intellij.psi.PsiJavaFile
import com.intellij.psi.PsiLiteralExpression
import com.intellij.psi.PsiMethod
import com.intellij.psi.PsiMethodCallExpression

class JavaSecurityVisitor(
    private val holder: ProblemsHolder,
    private val file: PsiJavaFile,
    private val vulnerabilities: List<Vulnerability>
) : JavaElementVisitor() {

    private val registeredProblems = mutableSetOf<String>()
    private val vulnerabilitiesByLine: Map<Int, List<Vulnerability>> by lazy { buildVulnerabilitiesByLine() }

    private fun buildVulnerabilitiesByLine(): Map<Int, List<Vulnerability>> {
        val fileName = file.virtualFile?.name ?: return emptyMap()
        return vulnerabilities
            .filter { it.location.contains(fileName) }
            .groupBy { PsiUtils.extractLineNumber(it.location) }
            .filterKeys { it > 0 }
    }

    override fun visitLiteralExpression(expression: PsiLiteralExpression) {
        super.visitLiteralExpression(expression)
        val value = expression.value as? String ?: return
        val lineNumber = PsiUtils.getLineNumber(expression)

        when {
            value.startsWith("http://") -> registerMatching(expression, lineNumber) { vuln ->
                vuln.description.contains(value, ignoreCase = true) || vuln.id.contains("HTTP_IN_", ignoreCase = true)
            }
            value.startsWith("https://") || value.startsWith("http://") -> registerMatching(expression, lineNumber) { vuln ->
                vuln.id.contains("PINNING_MISSING", ignoreCase = true) || vuln.id.contains("PINNING_SINGLE", ignoreCase = true)
            }
        }
    }

    override fun visitAnnotation(annotation: PsiAnnotation) {
        super.visitAnnotation(annotation)
        val qualifiedName = annotation.qualifiedName ?: return
        if (!qualifiedName.startsWith("retrofit2.http.")) return

        val value = annotation.findAttributeValue("value") as? PsiLiteralExpression ?: return
        val url = value.value as? String ?: return
        val lineNumber = PsiUtils.getLineNumber(annotation)

        when {
            url.startsWith("http://") -> registerMatching(annotation, lineNumber) { vuln ->
                vuln.id.contains("RETROFIT", ignoreCase = true) || vuln.id.contains("HTTP_IN_", ignoreCase = true)
            }
            url.startsWith("https://") || url.startsWith("http://") -> registerMatching(annotation, lineNumber) { vuln ->
                vuln.id.contains("PINNING_MISSING", ignoreCase = true)
            }
        }
    }

    override fun visitMethodCallExpression(expression: PsiMethodCallExpression) {
        super.visitMethodCallExpression(expression)
        val methodName = expression.methodExpression.referenceName ?: return
        val lineNumber = PsiUtils.getLineNumber(expression)

        when (methodName) {
            "loadUrl" -> handleLoadUrl(expression, lineNumber)
            "setHostnameVerifier" -> registerMatching(expression, lineNumber) { it.id.contains("HOSTNAME_BYPASS", ignoreCase = true) }
            "sslSocketFactory", "trustManager" -> registerMatching(expression, lineNumber) { vuln ->
                vuln.id.contains("TRUST_ALL", ignoreCase = true) || vuln.id.contains("CUSTOM_SSL", ignoreCase = true)
            }
        }
    }

    private fun handleLoadUrl(expression: PsiMethodCallExpression, lineNumber: Int) {
        val argument = expression.argumentList.expressions.firstOrNull() as? PsiLiteralExpression ?: return
        val url = argument.value as? String ?: return

        when {
            url.startsWith("http://") -> registerMatching(argument, lineNumber) { vuln ->
                vuln.id.contains("WEBVIEW", ignoreCase = true) || vuln.id.contains("HTTP_IN_", ignoreCase = true)
            }
            url.startsWith("https://") || url.startsWith("http://") -> registerMatching(argument, lineNumber) { vuln ->
                vuln.id.contains("PINNING_MISSING", ignoreCase = true)
            }
        }
    }

    override fun visitClass(aClass: PsiClass) {
        super.visitClass(aClass)
        val lineNumber = PsiUtils.getLineNumber(aClass.nameIdentifier ?: aClass)

        when {
            implementsInterface(aClass, "X509TrustManager") ->
                registerMatching(aClass.nameIdentifier ?: aClass, lineNumber) { it.id.contains("TRUST_ALL", ignoreCase = true) }
            implementsInterface(aClass, "HostnameVerifier") ->
                registerMatching(aClass.nameIdentifier ?: aClass, lineNumber) { it.id.contains("HOSTNAME_BYPASS", ignoreCase = true) }
        }
    }

    override fun visitMethod(method: PsiMethod) {
        super.visitMethod(method)
        val containingClass = method.containingClass ?: return
        val lineNumber = PsiUtils.getLineNumber(method.nameIdentifier ?: method)

        when {
            method.name in listOf("checkClientTrusted", "checkServerTrusted") &&
                    implementsInterface(containingClass, "X509TrustManager") &&
                    isMethodEmpty(method) ->
                registerMatching(method.nameIdentifier ?: method, lineNumber) { vuln ->
                    vuln.id.contains("TRUST_ALL", ignoreCase = true) && vuln.description.contains(method.name, ignoreCase = true)
                }
            method.name == "verify" && implementsInterface(containingClass, "HostnameVerifier") ->
                registerMatching(method.nameIdentifier ?: method, lineNumber) { it.id.contains("HOSTNAME_BYPASS", ignoreCase = true) }
        }
    }

    private fun implementsInterface(aClass: PsiClass, interfaceName: String): Boolean =
        aClass.implementsListTypes.any { it.canonicalText.contains(interfaceName) }

    private fun isMethodEmpty(method: PsiMethod): Boolean {
        val bodyText = method.body?.text?.removeSurrounding("{", "}")?.trim() ?: return false
        return bodyText.isEmpty() || bodyText.matches(Regex("^\\s*(?://[^\\n]*\\s*)*$"))
    }

    private inline fun registerMatching(element: PsiElement, lineNumber: Int, predicate: (Vulnerability) -> Boolean) {
        vulnerabilitiesByLine[lineNumber]?.filter(predicate)?.forEach { registerProblemOnce(element, it) }
    }

    private fun registerProblemOnce(element: PsiElement, vuln: Vulnerability) {
        if (!element.isValid) return
        val range = element.textRange
        if (range.isEmpty || range.startOffset < 0) return

        val key = "${vuln.id}:${range.startOffset}"
        if (!registeredProblems.add(key)) return

        holder.registerProblem(
            element,
            "[Security] ${vuln.id}: ${vuln.description}",
            SeverityMapper.mapToProblemHighlightType(vuln.severity),
            *createQuickFixes(vuln).toTypedArray()
        )
    }
}