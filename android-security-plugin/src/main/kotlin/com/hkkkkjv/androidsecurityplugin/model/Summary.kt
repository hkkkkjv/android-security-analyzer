package com.hkkkkjv.androidsecurityplugin.model

import com.google.gson.annotations.SerializedName

data class Summary(
    @SerializedName("total_issues") val totalIssues: Int,
    @SerializedName("critical") val critical: Int,
    @SerializedName("high") val high: Int,
    @SerializedName("medium") val medium: Int,
    @SerializedName("low") val low: Int
)