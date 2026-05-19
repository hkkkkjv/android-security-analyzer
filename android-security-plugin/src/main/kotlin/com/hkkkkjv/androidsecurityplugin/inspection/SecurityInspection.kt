package com.hkkkkjv.androidsecurityplugin.inspection

import com.hkkkkjv.androidsecurityplugin.inspection.visitors.JavaSecurityVisitor
import com.hkkkkjv.androidsecurityplugin.inspection.visitors.KotlinSecurityVisitor
import com.hkkkkjv.androidsecurityplugin.inspection.visitors.XmlSecurityVisitor
import com.hkkkkjv.androidsecurityplugin.service.SecurityAnalyzerService
import com.intellij.codeInspection.LocalInspectionTool
import com.intellij.codeInspection.ProblemsHolder
import com.intellij.psi.PsiElementVisitor
import com.intellij.psi.PsiJavaFile
import com.intellij.psi.xml.XmlFile

class SecurityInspection : LocalInspectionTool() {

    override fun buildVisitor(holder: ProblemsHolder, isOnTheFly: Boolean): PsiElementVisitor {
        val file = holder.file
        val project = file.project

        // Получаем сервис и данные
        val service = project.getService(SecurityAnalyzerService::class.java) ?: return PsiElementVisitor.EMPTY_VISITOR
        val projectPath = project.basePath ?: return PsiElementVisitor.EMPTY_VISITOR

        // Используем блокирующий вызов только для Inspection API (оно работает в фоне)
        // В будущем можно заменить на кэшированный результат из ExternalAnnotator
        val vulnerabilities = service.analyzeProjectBlocking(projectPath)

        if (vulnerabilities.isEmpty()) {
            return PsiElementVisitor.EMPTY_VISITOR
        }

        // Делегируем обработку специализированным визиторам
        return when {
            file is XmlFile -> XmlSecurityVisitor(holder, file, vulnerabilities)
            file is PsiJavaFile -> JavaSecurityVisitor(holder, file, vulnerabilities)
            file.virtualFile?.name?.endsWith(".kt") == true -> KotlinSecurityVisitor(holder, file, vulnerabilities)
            else -> PsiElementVisitor.EMPTY_VISITOR
        }
    }

    override fun getDisplayName() = "AndroidNetworkSecurityInspection"
    override fun getShortName() = "AndroidNetworkSecurity"
    override fun getGroupDisplayName() = "Security"
}