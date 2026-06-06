package com.hkkkkjv.androidsecurityplugin.model

import com.google.gson.annotations.SerializedName

data class ScanMetadata(
    @SerializedName("scan_date") val scanDate: String,
    @SerializedName("project_path") val projectPath: String,
    @SerializedName("scan_duration_ms") val scanDurationMs: Long
)