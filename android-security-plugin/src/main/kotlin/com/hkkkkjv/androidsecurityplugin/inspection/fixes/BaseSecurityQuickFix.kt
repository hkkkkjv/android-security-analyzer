package com.hkkkkjv.androidsecurityplugin.inspection.fixes

import com.intellij.codeInsight.intention.impl.BaseIntentionAction
import com.intellij.codeInspection.LocalQuickFix
import com.intellij.codeInspection.ProblemDescriptor
import com.intellij.openapi.editor.Editor
import com.intellij.openapi.project.Project
import com.intellij.psi.PsiDocumentManager
import com.intellij.psi.PsiElement
import com.intellij.psi.PsiFile

/**
 * Базовый класс для всех QuickFix, устраняющий дублирование кода.
 */
abstract class BaseSecurityQuickFix : BaseIntentionAction(), LocalQuickFix {

    abstract override fun getFamilyName(): String

    override fun isAvailable(project: Project, editor: Editor?, file: PsiFile?): Boolean =
        editor != null && file != null && file.isValid

    override fun startInWriteAction(): Boolean = true

    override fun applyFix(project: Project, descriptor: ProblemDescriptor) {
        val element = descriptor.psiElement ?: return
        performFix(project, element)
    }

    override fun invoke(project: Project, editor: Editor?, file: PsiFile?) {
        if (editor == null || file == null) return
        val offset = editor.caretModel.offset
        val element = file.findElementAt(offset) ?: return
        performFix(project, element)
    }

    protected abstract fun performFix(project: Project, element: PsiElement)

    protected fun getDocument(file: PsiFile) =
        PsiDocumentManager.getInstance(file.project).getDocument(file)

    protected fun commitDocument(project: Project, file: PsiFile) {
        getDocument(file)?.let { PsiDocumentManager.getInstance(project).commitDocument(it) }
    }

    protected fun findStringLiteral(element: PsiElement): PsiElement? {
        val className = element.javaClass.simpleName
        if (className == "PsiLiteralExpression" || className == "KtStringTemplateExpression") return element

        return element.children.firstNotNullOfOrNull { findStringLiteral(it) }
    }
}