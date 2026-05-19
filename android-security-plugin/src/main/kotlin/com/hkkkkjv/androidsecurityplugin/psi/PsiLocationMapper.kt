package com.hkkkkjv.androidsecurityplugin.psi

import com.intellij.openapi.project.Project
import com.intellij.openapi.vfs.LocalFileSystem
import com.intellij.psi.PsiDocumentManager
import com.intellij.psi.PsiElement
import com.intellij.psi.PsiManager
import java.io.File

class PsiLocationMapper(private val project: Project) {

    fun mapToPsiElement(location: String, projectBasePath: String): PsiElement? {
        val (relativePath, targetLine) = parseLocation(location)
        if (targetLine < 1) return null

        // Канонический абсолютный путь — устраняет "..", "/./", разные разделители
        val absolutePath = if (File(relativePath).isAbsolute) {
            File(relativePath).canonicalPath
        } else {
            File(projectBasePath, relativePath).canonicalPath
        }

        val virtualFile = LocalFileSystem.getInstance()
            .refreshAndFindFileByPath(absolutePath)  // refreshAndFind — надёжнее findFileByPath
            ?: return null

        if (!virtualFile.isValid) return null

        val psiFile = PsiManager.getInstance(project).findFile(virtualFile) ?: return null
        val document = PsiDocumentManager.getInstance(project).getDocument(psiFile) ?: return null

        // Строки в документе 0-based, в location — 1-based
        val lineIndex = targetLine - 1
        if (lineIndex >= document.lineCount) return null

        val lineStart = document.getLineStartOffset(lineIndex)
        val lineEnd   = document.getLineEndOffset(lineIndex)

        // Ищем первый значимый элемент в строке (не пробел/перенос)
        for (offset in lineStart..lineEnd) {
            val element = psiFile.findElementAt(offset)
            if (element != null && element.textRange.length > 0) return element
        }

        return psiFile.findElementAt(lineStart)
    }

    private fun parseLocation(location: String): Pair<String, Int> {
        val lastColon = location.lastIndexOf(':')
        if (lastColon <= 0 || lastColon == location.length - 1) {
            return Pair(location, -1)
        }
        val path = location.substring(0, lastColon)
        val line = location.substring(lastColon + 1).toIntOrNull() ?: return Pair(location, -1)
        return Pair(path, line)
    }
}