package com.hkkkkjv.androidsecurityplugin

import com.intellij.openapi.diagnostic.Logger
import com.intellij.openapi.project.Project
import com.intellij.openapi.startup.ProjectActivity

class AndroidSecurityPlugin : ProjectActivity {

    companion object {
        private val LOG = Logger.getInstance(AndroidSecurityPlugin::class.java)
        private const val PLUGIN_NAME = "Android Network Security Analyzer"
    }

    override suspend fun execute(project: Project) {
        LOG.info("$PLUGIN_NAME initialized for project: ${project.name}")
    }
}