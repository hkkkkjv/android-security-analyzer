package com.hkkkkjv.androidsecutiryplugin

import com.google.gson.Gson
import com.hkkkkjv.androidsecurityplugin.model.ScanReport
import com.hkkkkjv.androidsecurityplugin.service.SecurityAnalyzerService
import org.junit.Assert.assertEquals
import org.junit.Test

class JsonParserTest {
    private val gson = Gson()

    @Test
    fun `parse full CLI JSON report correctly`() {
        val json = """
    {
      "scan_metadata": {
        "scan_date": "2025-11-15T18:30:00+00:00",
        "project_path": "/home/user/MyApp",
        "scan_duration_ms": 2450
      },
      "vulnerabilities": [
        {
          "id": "CLEARTEXT_BASE_001",
          "severity": "CRITICAL",
          "cvss_score": 9.8,
          "category": "Insecure Communication",
          "description": "cleartextTrafficPermitted=\"true\" в base-config...",
          "location": "app/src/main/res/xml/network_security_config.xml:3",
          "recommendation": "Установите cleartextTrafficPermitted=\"false\"..."
        }
      ],
      "summary": {
        "total_issues": 1,
        "critical": 1,
        "high": 0,
        "medium": 0,
        "low": 0
      }
    }
    """.trimIndent()

        val report = gson.fromJson(json, ScanReport::class.java)

        assertEquals(2450L, report.scanMetadata.scanDurationMs)
        assertEquals("/home/user/MyApp", report.scanMetadata.projectPath)
        assertEquals(1, report.vulnerabilities.size)
        assertEquals("CRITICAL", report.vulnerabilities[0].severity)
        assertEquals(9.8, report.vulnerabilities[0].cvssScore, 0.01)
        assertEquals("app/src/main/res/xml/network_security_config.xml:3",
            report.vulnerabilities[0].location)
    }
}