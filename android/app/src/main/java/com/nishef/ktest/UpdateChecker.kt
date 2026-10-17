package com.nishef.ktest

import java.net.URL
import javax.net.ssl.HttpsURLConnection
import org.json.JSONArray

data class UpdateInfo(val message: String, val downloadUrl: String? = null)

// User initiated only. APK verification and installation remain the Android OS's job.
object UpdateChecker {
    fun check(): UpdateInfo {
        val connection = (URL("https://api.github.com/repos/Nishef1/ktest/releases?per_page=10")
            .openConnection() as HttpsURLConnection)
        connection.connectTimeout = 6000
        connection.readTimeout = 6000
        connection.setRequestProperty("Accept", "application/vnd.github+json")
        connection.setRequestProperty("User-Agent", "ktest-android")
        try {
            if (connection.responseCode != 200) {
                return UpdateInfo("Could not check updates (HTTP ${connection.responseCode}).")
            }
            val releases = connection.inputStream.bufferedReader().use { JSONArray(it.readText()) }
            for (i in 0 until releases.length()) {
                val release = releases.getJSONObject(i)
                if (release.optBoolean("draft") || release.optBoolean("prerelease")) continue
                val version = release.optString("tag_name").removePrefix("v")
                if (!isNewer(version, BuildConfig.VERSION_NAME)) continue
                val assets = release.optJSONArray("assets") ?: continue
                for (j in 0 until assets.length()) {
                    val asset = assets.getJSONObject(j)
                    val name = asset.optString("name").lowercase()
                    val url = asset.optString("browser_download_url")
                    if (name.endsWith(".apk") &&
                        (name.startsWith("ktest-connection-") || name.contains("android")) &&
                        url.startsWith("https://github.com/Nishef1/ktest/releases/download/")
                    ) {
                        return UpdateInfo("New Android version: ${version}", url)
                    }
                }
            }
            return UpdateInfo("No newer Android APK release is available.")
        } finally {
            connection.disconnect()
        }
    }

    private fun isNewer(candidate: String, current: String): Boolean {
        val a = candidate.split('.').map { it.toIntOrNull() ?: return false }
        val b = current.split('.').map { it.toIntOrNull() ?: return false }
        for (i in 0 until maxOf(a.size, b.size)) {
            val left = a.getOrElse(i) { 0 }
            val right = b.getOrElse(i) { 0 }
            if (left != right) return left > right
        }
        return false
    }
}
