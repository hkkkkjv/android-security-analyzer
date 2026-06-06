package com.hkkkkjv.androidsecurityplugin.inspection.fixes

import com.intellij.openapi.editor.Editor
import com.intellij.openapi.project.Project
import com.intellij.openapi.util.TextRange
import com.intellij.psi.PsiDocumentManager
import com.intellij.psi.PsiElement
import com.intellij.psi.PsiFile

class ReplaceHttpWithHttpsFix : BaseSecurityQuickFix() {

    override fun getFamilyName(): String = "Network Security Fixes"
    override fun getText(): String = "Replace http:// with https://"

    override fun performFix(project: Project, element: PsiElement) {
        val file = element.containingFile ?: return
        val document = getDocument(file) ?: return

        val stringElement = findStringLiteral(element) ?: element
        val textRange = stringElement.textRange
        val elementText = document.getText(textRange)

        val newText = elementText.replace("http://", "https://")
        if (newText != elementText) {
            document.replaceString(textRange.startOffset, textRange.endOffset, newText)
            PsiDocumentManager.getInstance(project).commitDocument(document)
        }
    }

    override fun invoke(project: Project, editor: Editor?, file: PsiFile?) {
        if (editor == null || file == null) return
        val document = editor.document

        val caretOffset = editor.caretModel.offset
        val lineNumber = document.getLineNumber(caretOffset)
        val lineStart = document.getLineStartOffset(lineNumber)
        val lineEnd = document.getLineEndOffset(lineNumber)
        val lineText = document.getText(TextRange(lineStart, lineEnd))

        if (!lineText.contains("http://")) return

        val newText = lineText.replace("http://", "https://")
        if (newText != lineText) {
            document.replaceString(lineStart, lineEnd, newText)
            PsiDocumentManager.getInstance(project).commitDocument(document)
        }
    }
}