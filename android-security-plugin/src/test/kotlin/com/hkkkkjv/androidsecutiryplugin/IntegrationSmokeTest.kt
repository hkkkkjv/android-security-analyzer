package com.hkkkkjv.androidsecutiryplugin

import com.google.gson.Gson
import com.hkkkkjv.androidsecurityplugin.model.ScanReport
import org.junit.Assert.*
import org.junit.Test
import java.io.File

class IntegrationSmokeTest {

    private val gson = Gson()

    @Test
    fun `CLI output matches Kotlin models`() {
        // Запускаем CLI на тестовом проекте (требует, чтобы CLI был в относительном пути)
        val testProject = System.getProperty("user.home") + "/Study/3course/Android/coursework/repo/android-security-analyzer/test-projects/18-invalid-pin-hash/"
        val cliScript = System.getProperty("user.home") + "/Study/3course/Android/coursework/repo/android-security-analyzer/cli/src/main.py"
        val tempReportFile = File.createTempFile("security-report-", ".json")
        tempReportFile.deleteOnExit()
        println(System.getProperty("user.home"))
        if (!File(cliScript).exists()) {
            println("CLI not found, skipping integration test")
            return
        }

        val process = ProcessBuilder("python3", cliScript, "--project", testProject, "--output", tempReportFile.absolutePath)
            .redirectErrorStream(true)
            .start()

        val consoleOutput = process.inputStream.bufferedReader().readText()
        val exitCode = process.waitFor()
        println("Console Output:\n$consoleOutput")
        println("Exit Code: $exitCode")

        assertEquals("CLI should return exit code 1 when vulnerabilities found", 1, exitCode)
        assertTrue("Report file was not created", tempReportFile.exists())
        assertTrue("Report file is empty", tempReportFile.length() > 0)

        val jsonContent = tempReportFile.readText()
        try {
            val report = gson.fromJson(jsonContent, ScanReport::class.java)

            assertNotNull("Report should not be null", report)
            assertNotNull("Vulnerabilities list should not be null", report.vulnerabilities)

            println("Successfully parsed report with ${report.vulnerabilities.size} issues.")

            assertTrue("Should find at least one vulnerability", report.vulnerabilities.isNotEmpty())

            val hasHigh = report.vulnerabilities.any { it.severity == "HIGH" }
            assertTrue("Should contain at least one HIGH issue", hasHigh)

        } catch (e: Exception) {
            fail("Failed to parse JSON from file. Content preview: ${jsonContent.take(200)}. Error: ${e.message}")
        }
    }
}