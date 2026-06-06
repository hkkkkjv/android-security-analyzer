package com.hkkkkjv.androidsecurityplugin.service

import com.google.gson.Gson
import com.hkkkkjv.androidsecurityplugin.model.ScanReport
import com.hkkkkjv.androidsecurityplugin.model.Vulnerability
import com.hkkkkjv.androidsecurityplugin.util.Log
import com.intellij.codeInsight.daemon.DaemonCodeAnalyzer
import com.intellij.openapi.Disposable
import com.intellij.openapi.application.ApplicationManager
import com.intellij.openapi.application.WriteAction
import com.intellij.openapi.components.Service
import com.intellij.openapi.editor.event.DocumentEvent
import com.intellij.openapi.editor.event.DocumentListener
import com.intellij.openapi.editor.EditorFactory
import com.intellij.openapi.fileEditor.FileDocumentManager
import com.intellij.openapi.fileEditor.FileEditorManager
import com.intellij.openapi.project.Project
import com.intellij.openapi.vfs.VirtualFileManager
import com.intellij.openapi.vfs.newvfs.BulkFileListener
import com.intellij.openapi.vfs.newvfs.events.VFileEvent
import com.intellij.psi.PsiManager
import com.intellij.util.io.awaitExit
import com.intellij.util.messages.MessageBusConnection
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.io.File
import java.util.Timer
import java.util.TimerTask

@Service(Service.Level.PROJECT)
class SecurityAnalyzerService(private val project: Project) : Disposable {

    private val gson = Gson()
    private val cache = mutableMapOf<String, CachedResult>()

    private var connection: MessageBusConnection? = null
    private var debounceTimer: Timer? = null
    private var documentListener: DocumentListener? = null

    @Volatile
    private var isAnalyzing: Boolean = false

    @Volatile
    private var isSavingDocuments: Boolean = false

    private data class CachedResult(val issues: List<Vulnerability>, val timestamp: Long)

    companion object {
        private const val TAG = "ANALYZER"
        private const val DEBOUNCE_MS = 1000L
        private const val CACHE_TTL_MS = 300_000L
        private const val ANALYSIS_COOLDOWN_MS = 2000L
        private val RELEVANT_EXTENSIONS = setOf(".kt", ".java", ".xml", ".gradle")
    }

    init {
        setupDocumentListener()
        setupVfsListener()
    }

    private fun setupDocumentListener() {
        documentListener = object : DocumentListener {
            override fun documentChanged(event: DocumentEvent) {
                if (isSavingDocuments) return
                val fileName = FileDocumentManager.getInstance().getFile(event.document)?.name ?: return
                if (RELEVANT_EXTENSIONS.any { fileName.endsWith(it, ignoreCase = true) }) {
                    scheduleCacheInvalidation()
                }
            }
        }
        EditorFactory.getInstance().eventMulticaster.addDocumentListener(documentListener!!, this)
    }

    private fun setupVfsListener() {
        connection = project.messageBus.connect(this)
        connection?.subscribe(VirtualFileManager.VFS_CHANGES, object : BulkFileListener {
            override fun after(events: MutableList<out VFileEvent>) {
                if (isSavingDocuments) return
                if (events.any { event -> RELEVANT_EXTENSIONS.any { event.path.endsWith(it, ignoreCase = true) } }) {
                    Log.info(TAG, "VFS change detected, scheduling invalidation")
                    scheduleCacheInvalidation()
                }
            }
        })
    }

    private fun scheduleCacheInvalidation() {
        if (isAnalyzing) return
        debounceTimer?.cancel()
        debounceTimer = Timer().apply {
            schedule(object : TimerTask() {
                override fun run() = invalidateCacheAndRestartAnalysis()
            }, DEBOUNCE_MS)
        }
    }

    private fun invalidateCacheAndRestartAnalysis() {
        if (isAnalyzing) {
            Log.info(TAG, "Analysis already in progress, skipping")
            return
        }

        try {
            val projectPath = project.basePath ?: return

            ApplicationManager.getApplication().invokeLater {
                if (project.isDisposed) {
                    isAnalyzing = false
                    return@invokeLater
                }

                saveAllDocumentsSafely()
                cache.remove(projectPath)
                Log.info(TAG, "Invalidated cache for project: $projectPath")
                restartAnalysisForOpenFiles()

                Timer().schedule(object : TimerTask() {
                    override fun run() {
                        isAnalyzing = false
                    }
                }, ANALYSIS_COOLDOWN_MS)
            }
        } catch (e: Exception) {
            Log.error(TAG, "Error in invalidateCacheAndRestartAnalysis", e)
            isAnalyzing = false
        }
    }

    private fun saveAllDocumentsSafely() {
        isSavingDocuments = true
        try {
            WriteAction.run<Throwable> { FileDocumentManager.getInstance().saveAllDocuments() }
            Log.info(TAG, "All documents saved to disk")
        } finally {
            isSavingDocuments = false
        }
    }

    private fun restartAnalysisForOpenFiles() {
        val fileEditorManager = FileEditorManager.getInstance(project)
        val psiManager = PsiManager.getInstance(project)
        val daemonCodeAnalyzer = DaemonCodeAnalyzer.getInstance(project)

        fileEditorManager.openFiles.forEach { virtualFile ->
            val psiFile = psiManager.findFile(virtualFile)
            if (psiFile != null && psiFile.isValid) {
                Log.info(TAG, "Restarting analysis for: ${virtualFile.name}")
                daemonCodeAnalyzer.restart(psiFile)
            }
        }
    }

    override fun dispose() {
        debounceTimer?.cancel()
        connection?.disconnect()
    }

    suspend fun analyzeProjectAsync(
        projectPath: String,
        pythonPath: String = System.getenv("ANDROID_SEC_PYTHON") ?: "python3"
    ): List<Vulnerability> = withContext(Dispatchers.IO) {
        Log.info(TAG, "analyzeProjectAsync START: project=$projectPath")

        getCachedResult(projectPath)?.let { return@withContext it }

        val scriptPath = resolveCliScriptPath(projectPath)
        if (scriptPath == null) {
            Log.warn(TAG, "main.py NOT FOUND")
            return@withContext emptyList()
        }
        Log.info(TAG, "Found CLI script: $scriptPath")

        val tempFile = File.createTempFile("android_sec_report_", ".json").apply { deleteOnExit() }

        try {
            runPythonAnalysis(pythonPath, scriptPath, projectPath, tempFile)
            parseReport(tempFile)?.also { vulnerabilities ->
                cache[projectPath] = CachedResult(vulnerabilities, System.currentTimeMillis())
                Log.info(TAG, "Found ${vulnerabilities.size} vulnerabilities")
            } ?: emptyList()
        } catch (e: Exception) {
            Log.error(TAG, "Unexpected error during analysis", e)
            emptyList()
        } finally {
            tempFile.delete()
        }
    }

    private fun getCachedResult(projectPath: String): List<Vulnerability>? {
        val now = System.currentTimeMillis()
        return cache[projectPath]?.takeIf { (now - it.timestamp) < CACHE_TTL_MS }?.also {
            Log.info(TAG, "Cache HIT for $projectPath (${it.issues.size} issues)")
        }?.issues
    }

    private suspend fun runPythonAnalysis(
        pythonPath: String,
        scriptPath: String,
        projectPath: String,
        tempFile: File
    ) {
        val cmd = listOf(pythonPath, scriptPath, "--project", projectPath, "--output", tempFile.absolutePath)
        Log.info(TAG, "Running CLI: ${cmd.joinToString(" ")}")

        val process = ProcessBuilder(cmd)
            .directory(File(projectPath))
            .redirectErrorStream(true)
            .start()

        Log.info(TAG, "Process started, PID: ${process.pid()}")

        val consoleOutput = process.inputStream.bufferedReader().readText()
        val exitCode = process.awaitExit()

        Log.info(TAG, "CLI output (${consoleOutput.length} chars): ${consoleOutput.take(500)}")
        Log.info(TAG, "CLI exit code: $exitCode")

        if (exitCode > 1) {
            Log.warn(TAG, "CLI failed with exit code $exitCode")
        }
    }

    private fun parseReport(tempFile: File): List<Vulnerability>? {
        if (!tempFile.exists() || tempFile.length() == 0L) {
            Log.error(TAG, "Report file is missing or empty: ${tempFile.absolutePath}")
            return null
        }

        val jsonContent = tempFile.readText()
        Log.info(TAG, "JSON preview: ${jsonContent.take(300)}")

        return try {
            gson.fromJson(jsonContent, ScanReport::class.java).vulnerabilities
        } catch (e: Exception) {
            Log.error(TAG, "JSON parse error: ${e.message}", e)
            Log.error(TAG, "Invalid JSON: ${jsonContent.take(500)}")
            null
        }
    }

    private fun resolveCliScriptPath(projectPath: String): String? {
        Log.debug(TAG, "Resolving CLI script path...")

        System.getenv("ANDROID_SEC_ANALYZER_PATH")?.let { envPath ->
            if (File(envPath).isFile) {
                Log.info(TAG, "Using script from env: $envPath")
                return envPath
            }
            Log.warn(TAG, "Env path is not a file: $envPath")
        }

        val base = project.basePath ?: return null
        val home = System.getProperty("user.home")

        val candidates = listOf(
            "$base/../android-security-analyzer/cli/src/main.py",
            "$base/android-security-analyzer/cli/src/main.py",
            "$home/android-security-analyzer/cli/src/main.py",
            "$home/.android-security-analyzer/cli/src/main.py"
        )

        return candidates.firstOrNull { File(it).isFile }?.let {
            Log.info(TAG, "Found script: ${File(it).canonicalPath}")
            File(it).canonicalPath
        }
    }

    fun analyzeProjectBlocking(projectPath: String): List<Vulnerability> {
        return kotlinx.coroutines.runBlocking { analyzeProjectAsync(projectPath) }
    }
}