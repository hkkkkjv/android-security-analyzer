package com.hkkkkjv.androidsecurityplugin.inspection.fixes

import com.intellij.codeInsight.intention.impl.BaseIntentionAction
import com.intellij.codeInspection.LocalQuickFix
import com.intellij.codeInspection.ProblemDescriptor
import com.intellij.openapi.editor.Editor
import com.intellij.openapi.project.Project
import com.intellij.psi.PsiFile


class AddCertificatePinningFix : BaseIntentionAction(), LocalQuickFix {

    override fun getFamilyName(): String = "Network security fixes"
    override fun applyFix(p0: Project, p1: ProblemDescriptor) {
        TODO("Not yet implemented")
    }

    override fun getText(): String = "Add certificate pinning template"
    override fun isAvailable(
        p0: Project,
        p1: Editor?,
        p2: PsiFile?
    ): Boolean {
        TODO("Not yet implemented")
    }

    override fun invoke(project: Project, editor: Editor?, file: PsiFile) {
        // Логика добавления шаблона CertificatePinner в код
    }

    override fun startInWriteAction(): Boolean = true
}