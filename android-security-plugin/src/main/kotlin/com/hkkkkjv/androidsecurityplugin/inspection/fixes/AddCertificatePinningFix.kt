package com.hkkkkjv.androidsecurityplugin.inspection.fixes

import com.intellij.openapi.editor.Document
import com.intellij.openapi.project.Project
import com.intellij.psi.PsiElement
import com.intellij.psi.PsiFile
import com.intellij.psi.xml.XmlTag

class AddCertificatePinningFix : BaseSecurityQuickFix() {

    override fun getFamilyName(): String = "Network security fixes"
    override fun getText(): String = "Add certificate pinning template"

    override fun performFix(project: Project, element: PsiElement) {
        val file = element.containingFile ?: return
        val document = getDocument(file) ?: return
        val isXml = file.name.endsWith(".xml", ignoreCase = true)

        if (isXml) {
            applyXmlFix(element, document, project, file)
        } else {
            applyCodeFix(element, document, project, file)
        }
    }

    private fun applyXmlFix(element: PsiElement, document: Document, project: Project, file: PsiFile) {
        val targetTag = findTargetXmlTag(element)

        if (targetTag == null) {
            document.insertString(
                element.textRange.endOffset,
                "\n<pin-set expiration=\"2026-12-31\">\n    <pin digest=\"SHA-256\">YOUR_BASE64_HASH_HERE=</pin>\n</pin-set>"
            )
            commitDocument(project, file)
            return
        }

        val template = """
            <pin-set expiration="2026-12-31">
                <pin digest="SHA-256">YOUR_BASE64_HASH_HERE=</pin>
                <pin digest="SHA-256">YOUR_BACKUP_BASE64_HASH_HERE=</pin>
            </pin-set>
        """.trimIndent()

        val existingPinSet = targetTag.findFirstSubTag("pin-set")
        if (existingPinSet != null) {
            val range = existingPinSet.textRange
            document.replaceString(range.startOffset, range.endOffset, template)
        } else {
            insertPinSetIntoTag(targetTag, template, document)
        }
        commitDocument(project, file)
    }

    private fun findTargetXmlTag(element: PsiElement): XmlTag? {
        var current: PsiElement? = element
        while (current != null) {
            if (current is XmlTag && (current.name == "domain-config" || current.name == "base-config")) return current
            current = current.parent
        }
        return null
    }

    private fun insertPinSetIntoTag(targetTag: XmlTag, template: String, document: Document) {
        val subTags = targetTag.subTags
        if (subTags.isNotEmpty()) {
            val insertOffset = subTags.last().textRange.endOffset
            document.insertString(insertOffset, "\n        $template")
        } else {
            val closeTagText = "</${targetTag.name}>"
            val tagText = document.getText(targetTag.textRange)
            val closeTagIndex = tagText.lastIndexOf(closeTagText)
            if (closeTagIndex != -1) {
                val insertOffset = targetTag.textRange.startOffset + closeTagIndex
                document.insertString(insertOffset, "\n        $template\n    ")
            }
        }
    }

    private fun applyCodeFix(element: PsiElement, document: Document, project: Project, file: PsiFile) {
        val isKotlin = file.name.endsWith(".kt", ignoreCase = true)
        val builderStart = findOkHttpClientBuilderStart(element)

        if (builderStart == -1) {
            insertTodoComment(element, document, project, file, isKotlin, "PINNING_MISSING")
            return
        }

        val buildOffset = findBuildCallOffset(document, builderStart, "OkHttpClient.Builder()")
        if (buildOffset == -1) {
            insertTodoComment(element, document, project, file, isKotlin, "PINNING_MISSING")
            return
        }

        val textBeforeBuild = document.getText(com.intellij.openapi.util.TextRange(builderStart, buildOffset))
        if (textBeforeBuild.contains(".certificatePinner(")) {
            applyBackupPinFix(element, document, project, file, isKotlin)
            return
        }

        val template = buildCertificatePinnerTemplate(isKotlin)
        document.insertString(buildOffset, template)
        commitDocument(project, file)
    }

    private fun findOkHttpClientBuilderStart(element: PsiElement): Int {
        var current: PsiElement? = element
        while (current != null && current !is PsiFile) {
            val text = current.text
            val builderIndex = text.indexOf("OkHttpClient.Builder()")
            if (builderIndex != -1) return current.textRange.startOffset + builderIndex

            if (text.contains(": OkHttpClient") && text.contains("Builder()")) {
                val simpleBuilderIndex = text.indexOf("Builder()")
                return current.textRange.startOffset + simpleBuilderIndex
            }
            current = current.parent
        }
        return -1
    }

    private fun findBuildCallOffset(document: Document, builderStart: Int, builderName: String): Int {
        val fileText = document.text
        val textAfterBuilder = fileText.substring(builderStart)

        var parenDepth = 0
        var i = builderName.length
        while (i < textAfterBuilder.length) {
            val char = textAfterBuilder[i]
            when {
                char == '(' -> parenDepth++
                char == ')' -> {
                    parenDepth--
                    if (parenDepth < 0) return -1
                }
                char == '.' && parenDepth == 0 && textAfterBuilder.substring(i).startsWith(".build()") ->
                    return builderStart + i
            }
            i++
        }
        return -1
    }

    private fun buildCertificatePinnerTemplate(isKotlin: Boolean): String = if (isKotlin) {
        "\n            .certificatePinner(\n" +
                "                CertificatePinner.Builder()\n" +
                "                    .add(\"example.com\", \"sha256/YOUR_HASH_HERE=\")\n" +
                "                    .add(\"example.com\", \"sha256/YOUR_BACKUP_HASH_HERE=\")\n" +
                "                    .build()\n" +
                "            )"
    } else {
        "\n            .certificatePinner(\n" +
                "                new CertificatePinner.Builder()\n" +
                "                    .add(\"example.com\", \"sha256/YOUR_HASH_HERE=\")\n" +
                "                    .add(\"example.com\", \"sha256/YOUR_BACKUP_HASH_HERE=\")\n" +
                "                    .build()\n" +
                "            )"
    }

    private fun applyBackupPinFix(element: PsiElement, document: Document, project: Project, file: PsiFile, isKotlin: Boolean) {
        var current: PsiElement? = element
        var pinnerBuilderStart = -1

        while (current != null && current !is PsiFile) {
            val builderIndex = current.text.indexOf("CertificatePinner.Builder()")
            if (builderIndex != -1) {
                pinnerBuilderStart = current.textRange.startOffset + builderIndex
                break
            }
            current = current.parent
        }

        if (pinnerBuilderStart == -1) return

        val buildOffset = findBuildCallOffset(document, pinnerBuilderStart, "CertificatePinner.Builder()")
        if (buildOffset == -1) return

        val backupPin = "\n                    .add(\"example.com\", \"sha256/YOUR_BACKUP_HASH_HERE=\")"
        document.insertString(buildOffset, backupPin)
        commitDocument(project, file)
    }

    private fun insertTodoComment(
        element: PsiElement,
        document: Document,
        project: Project,
        file: PsiFile,
        isKotlin: Boolean,
        vulnId: String
    ) {
        val lineNumber = document.getLineNumber(element.textOffset)
        val lineStart = document.getLineStartOffset(lineNumber)
        val todoComment = buildTodoComment(isKotlin, vulnId)

        document.insertString(lineStart, todoComment)
        commitDocument(project, file)
    }

    private fun buildTodoComment(isKotlin: Boolean, vulnId: String): String = if (isKotlin) {
        "// TODO: [$vulnId] Add CertificatePinner to protect against MITM attacks.\n" +
                "// Example:\n" +
                "//   val pinner = CertificatePinner.Builder()\n" +
                "//       .add(\"your.domain.com\", \"sha256/HASH=\")\n" +
                "//       .add(\"your.domain.com\", \"sha256/BACKUP_HASH=\")\n" +
                "//       .build()\n" +
                "//   OkHttpClient.Builder().certificatePinner(pinner).build()\n "
    } else {
        "// TODO: [$vulnId] Add CertificatePinner to protect against MITM attacks.\n" +
                "// Example:\n" +
                "//   CertificatePinner pinner = new CertificatePinner.Builder()\n" +
                "//       .add(\"your.domain.com\", \"sha256/HASH=\")\n" +
                "//       .add(\"your.domain.com\", \"sha256/BACKUP_HASH=\")\n" +
                "//       .build();\n" +
                "//   new OkHttpClient.Builder().certificatePinner(pinner).build();\n "
    }
}