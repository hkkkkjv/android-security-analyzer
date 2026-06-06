package com.hkkkkjv.androidsecurityplugin.inspection.fixes

import com.intellij.openapi.application.ReadAction
import com.intellij.openapi.command.WriteCommandAction
import com.intellij.openapi.editor.Document
import com.intellij.openapi.project.Project
import com.intellij.psi.PsiDocumentManager
import com.intellij.psi.PsiElement
import com.intellij.psi.PsiFile

class FixTrustManagerMethodFix : BaseSecurityQuickFix() {

    override fun getFamilyName(): String = "Network Security Fixes"
    override fun getText(): String = "Implement proper certificate validation"

    override fun isAvailable(project: Project, editor: com.intellij.openapi.editor.Editor?, file: PsiFile?): Boolean =
        editor != null && file != null && ReadAction.compute<Boolean, Throwable> { file.isValid }

    override fun performFix(project: Project, element: PsiElement) {
        ReadAction.run<Throwable> {
            val file = element.containingFile ?: return@run
            val document = getDocument(file) ?: return@run
            val isKotlin = file.name.endsWith(".kt", ignoreCase = true)

            val functionElement = findParentFunction(element)
            if (functionElement == null) {
                insertTodoAtCurrentLine(document, project, element.textOffset)
                return@run
            }

            val methodName = determineMethodName(functionElement)
            if (methodName == null) {
                insertTodoAtCurrentLine(document, project, element.textOffset)
                return@run
            }

            val bodyElement = findMethodBody(functionElement)
            if (bodyElement != null) {
                replaceMethodBody(bodyElement, methodName, isKotlin, document, project)
            } else {
                insertTodoAtMethodStart(document, project, functionElement, methodName, isKotlin)
            }
        }
    }

    private fun findParentFunction(element: PsiElement): PsiElement? {
        var current: PsiElement? = element
        while (current != null && current !is PsiFile) {
            val className = current.javaClass.simpleName
            if (className.contains("PsiMethod") || className == "KtNamedFunction") return current
            current = current.parent
        }
        return null
    }

    private fun determineMethodName(functionElement: PsiElement): String? {
        val text = functionElement.text
        return when {
            text.contains("checkClientTrusted") -> "checkClientTrusted"
            text.contains("checkServerTrusted") -> "checkServerTrusted"
            else -> null
        }
    }

    private fun findMethodBody(method: PsiElement): PsiElement? {
        method.children.forEach { child ->
            val className = child.javaClass.simpleName
            if (className == "PsiCodeBlock" || className == "KtBlockExpression" ||
                className.contains("CodeBlock") || className.contains("BlockExpression")
            ) {
                return child
            }
        }
        return method.children.firstNotNullOfOrNull { findMethodBody(it) }
    }

    private fun replaceMethodBody(
        bodyElement: PsiElement,
        methodName: String,
        isKotlin: Boolean,
        document: Document,
        project: Project
    ) {
        val implementation = if (isKotlin) getKotlinImplementation(methodName) else getJavaImplementation(methodName)

        WriteCommandAction.runWriteCommandAction(project) {
            val range = bodyElement.textRange
            document.replaceString(range.startOffset, range.endOffset, implementation)
            PsiDocumentManager.getInstance(project).commitDocument(document)
        }
    }

    private fun insertTodoAtMethodStart(
        document: Document,
        project: Project,
        methodElement: PsiElement,
        methodName: String,
        isKotlin: Boolean
    ) {
        val todoComment = buildTodoComment(methodName, isKotlin)

        WriteCommandAction.runWriteCommandAction(project) {
            val methodText = methodElement.text
            val openBraceIdx = methodText.indexOf('{')
            val insertOffset = if (openBraceIdx != -1) {
                methodElement.textRange.startOffset + openBraceIdx + 1
            } else {
                methodElement.textRange.startOffset
            }
            document.insertString(insertOffset, todoComment)
            PsiDocumentManager.getInstance(project).commitDocument(document)
        }
    }

    private fun insertTodoAtCurrentLine(document: Document, project: Project, offset: Int) {
        val lineNumber = document.getLineNumber(offset)
        val lineStart = document.getLineStartOffset(lineNumber)
        val todoComment = "// TODO: [TRUST_ALL] Implement proper certificate validation in this TrustManager method\n"

        WriteCommandAction.runWriteCommandAction(project) {
            document.insertString(lineStart, todoComment)
            PsiDocumentManager.getInstance(project).commitDocument(document)
        }
    }

    private fun buildTodoComment(methodName: String, isKotlin: Boolean): String = if (isKotlin) {
        "\n    // TODO: [$methodName] Implement proper certificate validation\n" +
                "    // Replace empty implementation with:\n" +
                "    // val defaultTrustManager = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm())\n" +
                "    //     .apply { init(null as KeyStore?) }\n" +
                "    //     .trustManagers\n" +
                "    //     .filterIsInstance<X509TrustManager>()\n" +
                "    //     .first()\n" +
                "    // defaultTrustManager.$methodName(chain, authType)\n"
    } else {
        "\n    // TODO: [$methodName] Implement proper certificate validation\n" +
                "    // Replace empty implementation with:\n" +
                "    // TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());\n" +
                "    // tmf.init((KeyStore) null);\n" +
                "    // X509TrustManager defaultTm = ...;\n" +
                "    // defaultTm.$methodName(chain, authType);\n"
    }

    private fun getKotlinImplementation(methodName: String): String = """
        {
            val defaultTrustManager = javax.net.ssl.TrustManagerFactory.getInstance(javax.net.ssl.TrustManagerFactory.getDefaultAlgorithm())
                .apply { init(null as java.security.KeyStore?) }
                .trustManagers
                .filterIsInstance<javax.net.ssl.X509TrustManager>()
                .first()
            defaultTrustManager.$methodName(chain, authType)
        }
    """.trimIndent()

    private fun getJavaImplementation(methodName: String): String = """
        {
            try {
                javax.net.ssl.TrustManagerFactory tmf = javax.net.ssl.TrustManagerFactory.getInstance(javax.net.ssl.TrustManagerFactory.getDefaultAlgorithm());
                tmf.init((java.security.KeyStore) null);
                javax.net.ssl.X509TrustManager defaultTm = null;
                for (javax.net.ssl.TrustManager tm : tmf.getTrustManagers()) {
                    if (tm instanceof javax.net.ssl.X509TrustManager) {
                        defaultTm = (javax.net.ssl.X509TrustManager) tm;
                        break;
                    }
                }
                if (defaultTm != null) {
                    defaultTm.$methodName(chain, authType);
                }
            } catch (Exception e) {
                throw new java.security.cert.CertificateException("Certificate validation failed", e);
            }
        }
    """.trimIndent()
}