package com.hkkkkjv.androidsecurityplugin.util

import com.intellij.openapi.editor.Document
import com.intellij.openapi.util.TextRange
import com.intellij.psi.PsiDocumentManager
import com.intellij.psi.PsiElement
import com.intellij.psi.PsiFile

object PsiUtils {

    /**
     * Получает номер строки (1-based) для PSI-элемента.
     */
    fun getLineNumber(element: PsiElement): Int {
        val document = PsiDocumentManager.getInstance(element.project)
            .getDocument(element.containingFile) ?: return -1
        return document.getLineNumber(element.textOffset) + 1
    }

    /**
     * Извлекает номер строки из строки локации вида "path/to/file:line".
     */
    fun extractLineNumber(location: String): Int {
        val lastColon = location.lastIndexOf(':')
        if (lastColon == -1 || lastColon == location.length - 1) return -1
        return location.substring(lastColon + 1).toIntOrNull() ?: -1
    }

    /**
     * Извлекает относительный путь из строки локации.
     */
    fun extractRelativePath(location: String): String {
        return location.substringBeforeLast(":").replace("\\", "/")
    }

    /**
     * Получает текст строки документа по номеру (0-based).
     */
    fun getLineText(document: Document, lineNumber: Int): String {
        if (lineNumber < 0 || lineNumber >= document.lineCount) return ""
        val start = document.getLineStartOffset(lineNumber)
        val end = document.getLineEndOffset(lineNumber)
        return document.getText(TextRange(start, end))
    }

    /**
     * Безопасно выполняет запись в документ с коммитом.
     */
    inline fun writeAndCommit(
        document: Document,
        project: com.intellij.openapi.project.Project,
        action: () -> Unit
    ) {
        action()
        PsiDocumentManager.getInstance(project).commitDocument(document)
    }

    /**
     * Проверяет, является ли файл Kotlin-файлом.
     */
    fun isKotlinFile(file: PsiFile): Boolean {
        return file.name.endsWith(".kt", ignoreCase = true)
    }

    /**
     * Проверяет, является ли файл Java-файлом.
     */
    fun isJavaFile(file: PsiFile): Boolean {
        return file.name.endsWith(".java", ignoreCase = true)
    }

    /**
     * Проверяет, является ли файл XML-файлом.
     */
    fun isXmlFile(file: PsiFile): Boolean {
        return file.name.endsWith(".xml", ignoreCase = true)
    }
}