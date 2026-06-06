package com.hkkkkjv.androidsecurityplugin.inspection.visitors

import com.hkkkkjv.androidsecurityplugin.inspection.SeverityMapper
import com.hkkkkjv.androidsecurityplugin.inspection.fixes.createQuickFixes
import com.hkkkkjv.androidsecurityplugin.model.Vulnerability
import com.hkkkkjv.androidsecurityplugin.util.PsiUtils
import com.intellij.codeInspection.ProblemsHolder
import com.intellij.psi.PsiElement
import com.intellij.psi.XmlElementVisitor
import com.intellij.psi.xml.XmlAttribute
import com.intellij.psi.xml.XmlFile
import com.intellij.psi.xml.XmlTag

class XmlSecurityVisitor(
    private val holder: ProblemsHolder,
    private val file: XmlFile,
    private val vulnerabilities: List<Vulnerability>
) : XmlElementVisitor() {

    private val vulnerabilitiesByLine: Map<Int, List<Vulnerability>> by lazy { buildVulnerabilitiesByLine() }
    private val registeredVulnerabilities = mutableSetOf<String>()

    private fun buildVulnerabilitiesByLine(): Map<Int, List<Vulnerability>> {
        val fileName = file.virtualFile?.name ?: return emptyMap()
        return vulnerabilities
            .filter { it.location.contains(fileName) }
            .groupBy { PsiUtils.extractLineNumber(it.location) }
            .filterKeys { it > 0 }
    }

    override fun visitXmlAttribute(attribute: XmlAttribute) {
        super.visitXmlAttribute(attribute)
        val lineNumber = PsiUtils.getLineNumber(attribute)
        if (lineNumber < 0) return

        vulnerabilitiesByLine[lineNumber]
            ?.filter { isVulnerabilityAboutAttribute(it, attribute) }
            ?.forEach { registerProblemOnce(attribute, it) }
    }

    override fun visitXmlTag(tag: XmlTag) {
        super.visitXmlTag(tag)
        val lineNumber = PsiUtils.getLineNumber(tag)
        if (lineNumber < 0) return

        vulnerabilitiesByLine[lineNumber]
            ?.filter { isVulnerabilityAboutTag(it, tag) }
            ?.forEach { registerProblemOnce(tag, it) }
    }

    private fun isVulnerabilityAboutAttribute(vuln: Vulnerability, attribute: XmlAttribute): Boolean {
        val attrName = attribute.name
        val attrValue = attribute.value ?: ""
        val vulnId = vuln.id.uppercase()

        return when {
            attrName == "cleartextTrafficPermitted" &&
                    (vulnId.contains("CLEARTEXT_DOMAIN") || vulnId.contains("CLEARTEXT_BASE")) -> true

            attrName.endsWith("usesCleartextTraffic") && vulnId.contains("MANIFEST_CLEARTEXT") -> true

            attrName == "src" && attrValue == "user" && vulnId.contains("USER_CERTS") -> true

            attrName.endsWith("networkSecurityConfig") &&
                    (vulnId.contains("NSC_BROKEN") || vulnId.contains("NSC_MISSING")) -> true

            attrName == "digest" && vulnId.contains("PIN_HASH") -> true

            attrName == "name" && vulnId.contains("MANIFEST_PERM_INFO") -> true

            else -> false
        }
    }

    private fun isVulnerabilityAboutTag(vuln: Vulnerability, tag: XmlTag): Boolean {
        val tagName = tag.name
        val vulnId = vuln.id.uppercase()

        return when (tagName) {
            "domain-config" -> vulnId.contains("MISSING_PINNING")
            "pin-set" -> vulnId.contains("EMPTY_PINNING")
            "certificates" -> tag.getAttributeValue("src") == "user" && vulnId.contains("USER_CERTS")
            "pin" -> vulnId.contains("SINGLE_PIN")
            "application" -> vulnId.contains("NSC_MISSING") || vulnId.contains("MANIFEST_CLEARTEXT")
            "uses-permission" -> vulnId.contains("MANIFEST_PERM_INFO")
            "string" -> vulnId.contains("HTTP_IN_STRINGS")
            else -> false
        }
    }

    private fun registerProblemOnce(element: PsiElement, vuln: Vulnerability) {
        val lineNumber = PsiUtils.getLineNumber(element)
        val key = "${vuln.id}:$lineNumber"

        if (!registeredVulnerabilities.add(key)) return

        holder.registerProblem(
            element,
            "[Security] ${vuln.id}: ${vuln.description}",
            SeverityMapper.mapToProblemHighlightType(vuln.severity),
            *createQuickFixes(vuln).toTypedArray()
        )
    }
}