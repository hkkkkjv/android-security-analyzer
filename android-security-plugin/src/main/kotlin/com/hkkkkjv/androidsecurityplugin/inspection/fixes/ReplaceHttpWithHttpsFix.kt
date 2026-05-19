package com.hkkkkjv.androidsecurityplugin.inspection.fixes

import com.intellij.codeInsight.intention.impl.BaseIntentionAction
import com.intellij.codeInspection.LocalQuickFix
import com.intellij.codeInspection.ProblemDescriptor
import com.intellij.openapi.editor.Editor
import com.intellij.openapi.project.Project
import com.intellij.psi.PsiFile

class ReplaceHttpWithHttpsFix : BaseIntentionAction(), LocalQuickFix {

    override fun getFamilyName(): String = "Network Security Fixes"
    override fun applyFix(p0: Project, p1: ProblemDescriptor) {
        TODO("Not yet implemented")
    }

    override fun getText(): String = "Replace http:// with https://"
    override fun isAvailable(
        p0: Project,
        p1: Editor?,
        p2: PsiFile?
    ): Boolean {
        TODO("Not yet implemented")
    }

    override fun invoke(project: Project, editor: Editor?, file: PsiFile) {
        // Логика замены http:// на https:// в строковых литералах
    }

    override fun startInWriteAction(): Boolean = true
}