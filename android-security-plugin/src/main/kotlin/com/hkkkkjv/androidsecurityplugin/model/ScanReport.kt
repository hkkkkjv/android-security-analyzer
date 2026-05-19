package com.hkkkkjv.androidsecurityplugin.model

import com.google.gson.annotations.SerializedName

data class ScanReport(
    @SerializedName("scan_metadata") val scanMetadata: ScanMetadata,
    @SerializedName("vulnerabilities") val vulnerabilities: List<Vulnerability>,
    @SerializedName("summary") val summary: Summary
)