package com.hkkkkjv.androidsecurityplugin.inspection.fixes

import com.intellij.openapi.project.Project
import com.intellij.openapi.util.TextRange
import com.intellij.psi.PsiElement
import com.intellij.psi.xml.XmlAttribute
import com.intellij.psi.xml.XmlTag

class ChangeUserCertsToSystemFix : BaseSecurityQuickFix() {

    override fun getFamilyName(): String = "Network Security Fixes"
    override fun getText(): String = "Change src=\"user\" to src=\"system\""

    override fun performFix(project: Project, element: PsiElement) {
        val file = element.containingFile ?: return
        val document = getDocument(file) ?: return

        val targetAttribute = findUserCertsAttribute(element)

        if (targetAttribute != null) {
            val valueElement = targetAttribute.valueElement ?: return
            val valueRange = valueElement.textRange
            val newValue = valueElement.text.replace("user", "system")
            document.replaceString(valueRange.startOffset, valueRange.endOffset, newValue)
            commitDocument(project, file)
        } else {
            replaceInCurrentLine(element, document, project)
        }
    }

    private fun replaceInCurrentLine(
        element: PsiElement,
        document: com.intellij.openapi.editor.Document,
        project: Project
    ) {
        val offset = element.textOffset
        val lineNumber = document.getLineNumber(offset)
        val lineStart = document.getLineStartOffset(lineNumber)
        val lineEnd = document.getLineEndOffset(lineNumber)
        val lineText = document.getText(TextRange(lineStart, lineEnd))

        if (lineText.contains("src=\"user\"")) {
            val newText = lineText.replace("src=\"user\"", "src=\"system\"")
            document.replaceString(lineStart, lineEnd, newText)
            commitDocument(project, element.containingFile!!)
        }
    }

    private fun findUserCertsAttribute(element: PsiElement): XmlAttribute? {
        var current: PsiElement? = element
        while (current != null) {
            if (current is XmlAttribute && current.name == "src" && current.value == "user") return current
            if (current is XmlTag && current.name == "certificates") {
                return current.getAttribute("src")?.takeIf { it.value == "user" }
            }
            current = current.parent
        }
        return null
    }
}