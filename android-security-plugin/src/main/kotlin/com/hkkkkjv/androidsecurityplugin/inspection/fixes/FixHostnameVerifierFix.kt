package com.hkkkkjv.androidsecurityplugin.inspection.fixes

import com.intellij.openapi.editor.Document
import com.intellij.openapi.project.Project
import com.intellij.openapi.util.TextRange
import com.intellij.psi.PsiDocumentManager
import com.intellij.psi.PsiElement

class FixHostnameVerifierFix : BaseSecurityQuickFix() {

    override fun getFamilyName(): String = "Network Security Fixes"
    override fun getText(): String = "Replace with safe HostnameVerifier implementation"

    override fun performFix(project: Project, element: PsiElement) {
        val file = element.containingFile ?: return
        val document = getDocument(file) ?: return
        val isKotlin = file.name.endsWith(".kt", ignoreCase = true)

        val offset = element.textOffset
        val lineNumber = document.getLineNumber(offset)

        if (tryReplaceReturnTrue(document, lineNumber, isKotlin, project, file)) return

        insertTodoComment(document, lineNumber, isKotlin, project, file)
    }

    private fun tryReplaceReturnTrue(
        document: Document,
        lineNumber: Int,
        isKotlin: Boolean,
        project: Project,
        file: com.intellij.psi.PsiFile
    ): Boolean {
        val searchStart = maxOf(0, lineNumber - 20)
        val searchEnd = minOf(document.lineCount - 1, lineNumber + 20)

        for (i in searchStart..searchEnd) {
            val lineStart = document.getLineStartOffset(i)
            val lineEnd = document.getLineEndOffset(i)
            val lineText = document.getText(TextRange(lineStart, lineEnd))

            if (lineText.contains("return true") &&
                (lineText.contains("verify") || isInsideVerifyMethod(document, i))
            ) {
                val newText = if (isKotlin) {
                    lineText.replace("return true", "return HttpsURLConnection.getDefaultHostnameVerifier().verify(hostname, session)")
                } else {
                    lineText.replace("return true;", "return HttpsURLConnection.getDefaultHostnameVerifier().verify(hostname, session);")
                }

                if (newText != lineText) {
                    document.replaceString(lineStart, lineEnd, newText)
                    PsiDocumentManager.getInstance(project).commitDocument(document)
                    return true
                }
            }
        }
        return false
    }

    private fun insertTodoComment(
        document: Document,
        lineNumber: Int,
        isKotlin: Boolean,
        project: Project,
        file: com.intellij.psi.PsiFile
    ) {
        val lineStart = document.getLineStartOffset(lineNumber)
        val todoComment = buildTodoComment(isKotlin)

        document.insertString(lineStart, todoComment)
        PsiDocumentManager.getInstance(project).commitDocument(document)
    }

    private fun buildTodoComment(isKotlin: Boolean): String =
        "// TODO: [HOSTNAME_BYPASS] Review HostnameVerifier implementation.\n" +
                "// Returning 'true' unconditionally disables hostname verification\n" +
                "// and makes the app vulnerable to MITM attacks.\n" +
                "// Use HttpsURLConnection.getDefaultHostnameVerifier().verify(hostname, session) instead.\n"

    private fun isInsideVerifyMethod(document: Document, lineNumber: Int): Boolean {
        val searchStart = maxOf(0, lineNumber - 15)
        for (i in lineNumber downTo searchStart) {
            val lineStart = document.getLineStartOffset(i)
            val lineEnd = document.getLineEndOffset(i)
            val lineText = document.getText(TextRange(lineStart, lineEnd))

            if (lineText.contains("fun verify") || lineText.contains("boolean verify") ||
                lineText.contains("public boolean verify")
            ) {
                return true
            }
        }
        return false
    }
}