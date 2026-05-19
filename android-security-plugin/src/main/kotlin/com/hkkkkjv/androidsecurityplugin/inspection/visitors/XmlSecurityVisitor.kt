package com.hkkkkjv.androidsecurityplugin.inspection.visitors

import com.hkkkkjv.androidsecurityplugin.inspection.SeverityMapper
import com.hkkkkjv.androidsecurityplugin.inspection.createQuickFixes
import com.hkkkkjv.androidsecurityplugin.model.Vulnerability
import com.intellij.codeInspection.ProblemsHolder
import com.intellij.psi.XmlElementVisitor
import com.intellij.psi.xml.XmlAttribute
import com.intellij.psi.xml.XmlFile
import com.intellij.psi.xml.XmlTag

class XmlSecurityVisitor(
    private val holder: ProblemsHolder,
    private val file: XmlFile,
    private val vulnerabilities: List<Vulnerability>
) : XmlElementVisitor() {

    override fun visitXmlAttribute(attribute: XmlAttribute) {
        super.visitXmlAttribute(attribute)
        processAttribute(attribute)
    }

    override fun visitXmlTag(tag: XmlTag) {
        super.visitXmlTag(tag)
    }

    private fun processAttribute(attribute: XmlAttribute) {
        val name = attribute.name
        val value = attribute.value

        val relevant = vulnerabilities.filter { vulnerability ->
            vulnerability.location.contains(file.virtualFile?.name ?: return@filter false) &&
                    (vulnerability.description.contains(name, ignoreCase = true) ||
                            vulnerability.description.contains(value.toString(), ignoreCase = true))
        }

        for (vulnerability in relevant) {
            holder.registerProblem(
                attribute,
                "[Security] ${vulnerability.id}: ${vulnerability.description}",
                SeverityMapper.mapToProblemHighlightType(vulnerability.severity),
                *createQuickFixes(vulnerability).toTypedArray()
            )
        }
    }
}