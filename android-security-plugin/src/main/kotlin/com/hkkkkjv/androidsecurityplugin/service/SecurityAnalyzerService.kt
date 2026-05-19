package com.hkkkkjv.androidsecurityplugin.service

import com.google.gson.Gson
import com.hkkkkjv.androidsecurityplugin.model.ScanReport
import com.hkkkkjv.androidsecurityplugin.model.Vulnerability
import com.intellij.openapi.components.Service
import com.intellij.openapi.diagnostic.thisLogger
import com.intellij.openapi.project.Project
import com.intellij.util.io.awaitExit
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.io.File

@Service(Service.Level.PROJECT)
class SecurityAnalyzerService(private val project: Project) {

    private val gson = Gson()
    private val logger = thisLogger()

    private data class CachedResult(val issues: List<Vulnerability>, val timestamp: Long)
    private val cache = mutableMapOf<String, CachedResult>()

    suspend fun analyzeProjectAsync(
        projectPath: String,
        pythonPath: String = System.getenv("ANDROID_SEC_PYTHON") ?: "python3"
    ): List<Vulnerability> = withContext(Dispatchers.IO) {

        logger.info("[ANALYZER] analyzeProjectAsync START: project=$projectPath")

        // 1. Проверка кэша
        val now = System.currentTimeMillis()
        cache[projectPath]?.takeIf { (now - it.timestamp) < 300_000 }?.let {
            logger.info("[ANALYZER] Cache HIT for $projectPath (${it.issues.size} issues)")
            return@withContext it.issues
        }
        logger.info("[ANALYZER] Cache MISS for $projectPath")

        // 2. Поиск скрипта
        val scriptPath = resolveCliScriptPath()
        if (scriptPath == null) {
            logger.warn("[ANALYZER] main.py NOT FOUND. Tried paths:\n" +
                    listOf(
                        System.getenv("ANDROID_SEC_ANALYZER_PATH"),
                        "$projectPath/../android-security-analyzer/cli/src/main.py",
                        "$projectPath/android-security-analyzer/cli/src/main.py",
                        "${System.getProperty("user.home")}/android-security-analyzer/cli/src/main.py",
                        "${System.getProperty("user.home")}/.android-security-analyzer/cli/src/main.py"
                    ).joinToString("\n  - ") { it ?: "null" }
            )
            return@withContext emptyList()
        }
        logger.info("[ANALYZER] Found CLI script: $scriptPath")

        // 3. Подготовка временного файла
        val tempFile = File.createTempFile("android_sec_report_", ".json")
        tempFile.deleteOnExit()
        logger.info("[ANALYZER] Temp report file: ${tempFile.absolutePath}")

        try {
            // 4. Формирование команды
            val cmd = listOf(pythonPath, scriptPath, "--project", projectPath, "--output", tempFile.absolutePath)
            logger.info("[ANALYZER] Running CLI: ${cmd.joinToString(" ")}")

            // 5. Запуск процесса
            val process = ProcessBuilder(cmd)
                .directory(File(projectPath))
                .redirectErrorStream(true)
                .start()
            logger.info("[ANALYZER] Process started, PID: ${process.pid()}")

            // 6. Чтение вывода
            val consoleOutput = process.inputStream.bufferedReader().readText()
            val exitCode = process.awaitExit()

            logger.info("[ANALYZER] CLI console output (${consoleOutput.length} chars):\n${consoleOutput.take(500)}")
            logger.info("[ANALYZER] CLI exit code: $exitCode")

            // 7. Проверка кода выхода
            if (exitCode > 1) {
                logger.warn("[ANALYZER] CLI failed with exit code $exitCode")
                return@withContext emptyList()
            }

            // 8. Проверка файла отчёта
            if (!tempFile.exists()) {
                logger.error("[ANALYZER] Report file does NOT exist: ${tempFile.absolutePath}")
                return@withContext emptyList()
            }
            if (tempFile.length() == 0L) {
                logger.error("[ANALYZER] Report file is EMPTY: ${tempFile.absolutePath}")
                return@withContext emptyList()
            }
            logger.info("[ANALYZER] Report file exists, size: ${tempFile.length()} bytes")

            // 9. Парсинг JSON
            val jsonContent = tempFile.readText()
            logger.info("[ANALYZER] JSON preview: ${jsonContent.take(300)}")

            val report = try {
                gson.fromJson(jsonContent, ScanReport::class.java)
            } catch (e: Exception) {
                logger.error("[ANALYZER] JSON parse error: ${e.message}", e)
                logger.error("[ANALYZER] Invalid JSON: ${jsonContent.take(500)}")
                return@withContext emptyList()
            }
            logger.info("[ANALYZER] JSON parsed successfully")

            // 10. Кэширование и возврат
            val vulnerabilities = report.vulnerabilities
            cache[projectPath] = CachedResult(vulnerabilities, now)
            logger.info("[ANALYZER] DONE. Found ${vulnerabilities.size} vulnerabilities:")
            vulnerabilities.forEachIndexed { i, v ->
                logger.info("   [$i] ${v.id} [${v.severity}] at ${v.location}")
            }
            vulnerabilities

        } catch (e: Exception) {
            logger.error("[ANALYZER] Unexpected error: ${e.message}", e)
            emptyList()
        } finally {
            tempFile.delete()
            logger.info("[ANALYZER] Temp file deleted")
        }
    }

    private fun resolveCliScriptPath(): String? {
        logger.debug("[PATH] Resolving CLI script path...")

        val fromEnv = System.getenv("ANDROID_SEC_ANALYZER_PATH")
        if (fromEnv != null) {
            logger.debug("[PATH] Env var ANDROID_SEC_ANALYZER_PATH=$fromEnv")
            if (File(fromEnv).isFile) {
                logger.info("[PATH] Using script from env: $fromEnv")
                return fromEnv
            } else {
                logger.warn("[PATH] Env path is not a file: $fromEnv")
            }
        } else {
            logger.debug("[PATH] Env var ANDROID_SEC_ANALYZER_PATH not set")
        }

        val base = project.basePath ?: return null.also {
            logger.warn("[PATH] Project basePath is null")
        }
        val home = System.getProperty("user.home")
        logger.debug("[PATH] Project base: $base, User home: $home")

        val candidates = listOf(
            "$base/../android-security-analyzer/cli/src/main.py",
            "$base/android-security-analyzer/cli/src/main.py",
            "$home/android-security-analyzer/cli/src/main.py",
            "$home/.android-security-analyzer/cli/src/main.py"
        )

        for (path in candidates) {
            val file = File(path)
            logger.debug("[PATH] Checking: $path (exists=${file.exists()}, isFile=${file.isFile})")
            if (file.isFile) {
                val canonical = file.canonicalPath
                logger.info("[PATH] Found script: $canonical")
                return canonical
            }
        }

        logger.warn("[PATH] Script NOT FOUND in any candidate path")
        return null
    }

    fun analyzeProjectBlocking(projectPath: String): List<Vulnerability> {
        return kotlinx.coroutines.runBlocking {
            analyzeProjectAsync(projectPath)
        }
    }
}