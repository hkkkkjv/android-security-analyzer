package com.hkkkkjv.androidsecurityplugin

import com.intellij.openapi.diagnostic.Logger
import com.intellij.openapi.project.Project
import com.intellij.openapi.startup.ProjectActivity

class AndroidSecurityPlugin : ProjectActivity {
    companion object {
        private val LOG = Logger.getInstance(AndroidSecurityPlugin::class.java)
    }


    override suspend fun execute(project: Project) {
        LOG.warn("Android Network Security Plugin initialized for project: ${project.name}")
    }
}