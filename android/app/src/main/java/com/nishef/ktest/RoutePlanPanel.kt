package com.nishef.ktest

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.selection.SelectionContainer
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.Text
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import org.json.JSONObject
import java.time.Instant
import java.time.ZoneId
import java.time.format.DateTimeFormatter

/** App-level state keeps observations and disclosure choices across tab changes. */
internal class RoutePlanState {
    var report by mutableStateOf<JSONObject?>(null)
    var readError by mutableStateOf<String?>(null)
    var error by mutableStateOf<String?>(null)
    var starting by mutableStateOf(false)
    var canceling by mutableStateOf(false)
    var expandedTargets by mutableStateOf(emptySet<String>())
    var changedProfileAt by mutableStateOf<String?>(null)

    val manualBusy: Boolean
        get() = starting || canceling || (report?.optBoolean("running") == true && report?.optBoolean("manual") == true)
    val busy: Boolean
        get() = manualBusy || report?.optBoolean("running") == true
}

@Composable
internal fun RoutePlanPanel(
    s: RoutePlanState, connected: Boolean, connecting: Boolean,
    canTest: Boolean, onTest: () -> Unit, onCancel: () -> Unit
) {
    val report = s.report
    val profile = report?.optJSONObject("profile")
    val running = report?.optBoolean("running") == true
    val manual = report?.optBoolean("manual") == true
    val canceled = report?.optBoolean("canceled") == true
    val fresh = report?.optBoolean("fresh") == true
    val targetsChanged = s.changedProfileAt != null &&
        (profile == null || profile.optString("completed_at") == s.changedProfileAt)
    Panel {
        Row(verticalAlignment = Alignment.CenterVertically) {
            IconTile(KIcons.Route, K.cyan)
            Spacer(Modifier.width(14.dp))
            Column(Modifier.weight(1f)) {
                Text("Manual route diagnostics", color = K.text, fontSize = 16.sp, fontWeight = FontWeight.SemiBold)
                Text("Optional observations · connection stays adaptive",
                    color = K.muted, fontSize = 12.sp)
            }
        }
        Note("Connect starts without these tests and learns routes from live traffic. Manual results describe only the tested URLs, not feeds or playback.")
        if (running || s.starting) {
            val done = report?.optInt("completed") ?: 0
            val total = report?.optInt("total") ?: 0
            Text(when {
                canceled || s.canceling -> "Stopping manual test…"
                s.starting -> "Preparing manual test…"
                manual -> "Manual test · ${report?.optString("phase").orEmpty().replace('_', ' ')}"
                else -> "Manual diagnostics · ${report?.optString("phase").orEmpty().replace('_', ' ')}"
            }, color = K.cyan, fontSize = 14.sp)
            if (total > 0) {
                LinearProgressIndicator(progress = { (done.toFloat() / total).coerceIn(0f, 1f) },
                    modifier = Modifier.fillMaxWidth(), color = K.cyan, trackColor = K.stroke)
            } else {
                LinearProgressIndicator(modifier = Modifier.fillMaxWidth(), color = K.cyan, trackColor = K.stroke)
            }
            Text("$done / $total checks · ${formatDuration((report?.optLong("elapsed_ms") ?: 0) / 1000)} elapsed",
                color = K.muted, fontSize = 12.sp)
            report?.optString("current_target")?.takeIf { it.isNotBlank() }?.let { RoutePlanDetail("Current target", it) }
            report?.optString("current_method")?.takeIf { it.isNotBlank() }?.let { RoutePlanDetail("Current method", it) }
        }
        if (s.manualBusy || (running && manual)) {
            SecondaryButton(if (s.canceling || canceled) "Stopping test…" else "Cancel manual test", onCancel,
                Modifier.fillMaxWidth(), enabled = !s.starting && !s.canceling && !canceled, tint = K.amber)
            Note("This test uses the existing cores without starting a VPN or a connected session. Connect is unavailable until the test cores finish stopping.")
        } else {
            SecondaryButton("Test routes", onTest, Modifier.fillMaxWidth(), enabled = canTest, icon = KIcons.Search)
            if (connected || connecting) Note("Disconnect before running a manual test. The saved observations remain available here.")
        }
        if (!running && canceled) Note("Manual test canceled. Any saved profile below is from its displayed completion time; cancellation does not prove a new result.", Tone.Warn)
        if (targetsChanged) Note("Diagnostic targets changed. Run a manual test to refresh these observations; Connect remains available.", Tone.Warn)
        (s.error ?: s.readError ?: report?.optString("error")?.takeIf { !canceled && it.isNotBlank() })?.let { Note(it, Tone.Warn) }
        if (profile == null) {
            if (!running && !s.starting) Note(if (report == null) "Loading saved observations…" else "No saved observations yet. Connect directly, or run an optional test while disconnected.")
        } else {
            RoutePlanDetail("Profile completed", formatProfileTime(profile.optString("completed_at")))
            Text(when {
                targetsChanged -> "Historical results for the previous targets"
                fresh -> "Recent manual observations · not a connection prerequisite"
                else -> "Outside the cache window · shown as historical observations"
            }, color = if (fresh && !targetsChanged) K.muted else K.amber, fontSize = 12.sp)
            RoutePlanDetail("Other destinations", "Adaptive race across all methods")
            val rows = profile.objectRows("rows")
            val selections = profile.objectRows("selections")
            val targetIds = (selections.map { it.optString("target_id") } + rows.map { it.optString("target_id") }).distinct()
            targetIds.forEach { id ->
                val selection = selections.firstOrNull { it.optString("target_id") == id }
                val methods = rows.filter { it.optString("target_id") == id }
                val winner = methods.firstOrNull { it.optString("method") == selection?.optString("method") }
                Column(Modifier.fillMaxWidth().clip(RoundedCornerShape(14.dp)).background(K.bg).padding(14.dp),
                    verticalArrangement = Arrangement.spacedBy(9.dp)) {
                    Text(methods.firstOrNull()?.optString("target")?.ifBlank { id } ?: id,
                        color = K.text, fontWeight = FontWeight.SemiBold, fontSize = 14.sp)
                    RoutePlanDetail("Test URL", selection?.optString("url") ?: methods.firstOrNull()?.optString("url").orEmpty())
                    if (selection != null) {
                        Text("Selected: ${selection.optString("method").ifBlank { "No responsive method" }}",
                            color = K.text, fontSize = 13.sp)
                        RouteEvidence(selection, winner)
                    } else Note("No method was selected for this target.", Tone.Warn)
                    val expanded = id in s.expandedTargets
                    SecondaryButton(if (expanded) "Hide method matrix" else "Show method matrix (${methods.size})", {
                        s.expandedTargets = if (expanded) s.expandedTargets - id else s.expandedTargets + id
                    }, Modifier.fillMaxWidth())
                    if (expanded) methods.forEach { row ->
                        Hairline()
                        Text(row.optString("method"), color = K.text, fontSize = 13.sp, fontWeight = FontWeight.Medium)
                        RouteEvidence(row, row)
                    }
                }
            }
        }
        report?.optString("note")?.takeIf { it.isNotBlank() }?.let { Note(it) }
        Note("A successful HTTPS request proves only the listed probe. HTTP 403 is a service refusal, even with verified TLS. These checks do not prove native-app CA trust, account access, working APIs or playable media.")
    }
}

private fun JSONObject.objectRows(key: String): List<JSONObject> = optJSONArray(key)?.let { array ->
    (0 until array.length()).mapNotNull { array.optJSONObject(it) }
}.orEmpty()

private fun formatProfileTime(raw: String): String = runCatching {
    DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss z").withZone(ZoneId.systemDefault()).format(Instant.parse(raw))
}.getOrDefault(raw)

@Composable
private fun RoutePlanDetail(label: String, value: String) {
    Column(Modifier.fillMaxWidth(), verticalArrangement = Arrangement.spacedBy(3.dp)) {
        Text(label, color = K.muted, fontSize = 11.sp)
        SelectionContainer { Text(value, modifier = Modifier.fillMaxWidth(), color = K.text, fontSize = 12.sp, lineHeight = 17.sp) }
    }
}

@Composable
private fun RouteEvidence(result: JSONObject, measurements: JSONObject?) {
    val attempts = result.optInt("attempts")
    val successes = result.optInt("successes")
    val assessment = result.optString("assessment")
    val http = measurements?.optInt("http_status") ?: 0
    val verified = assessment == "https_verified" && attempts >= 3 && successes == attempts && http < 400
    val color = when {
        verified -> K.mint
        assessment == "unreachable" -> K.red
        assessment == "not_applicable" -> K.faint
        else -> K.amber
    }
    Text(when {
        http == 403 -> "HTTP 403 · service refused"
        http >= 400 -> "HTTP $http · service refused"
        verified -> "Repeated HTTPS probe succeeded"
        assessment == "service_refused" -> "TLS response received · service refused"
        assessment == "intermittent" -> "Intermittent HTTPS success"
        assessment == "not_applicable" -> "Method not applicable to this target"
        else -> "No verified HTTPS result"
    }, color = color, fontSize = 12.sp)
    Text("Successful requests: $successes / $attempts", color = K.muted, fontSize = 12.sp)
    val responses = measurements?.optInt("responses")
    if (responses != null) Text("Verified TLS / HTTP responses: $responses / $attempts", color = K.muted, fontSize = 12.sp)
    if ((responses ?: successes) > 0) {
        Text("Median elapsed: ${result.optLong("median_ms")} ms · Jitter (range): ${result.optLong("jitter_ms")} ms",
            color = K.muted, fontSize = 12.sp, lineHeight = 17.sp)
    }
    if (measurements != null && attempts > 0) {
        Text("Last TCP connect: ${measurements.optLong("tcp_ms")} ms · TLS handshake: ${measurements.optLong("tls_ms")} ms",
            color = K.muted, fontSize = 12.sp, lineHeight = 17.sp)
        Text("Last HTTP status: ${http.takeIf { it > 0 } ?: "no response"}", color = K.muted, fontSize = 12.sp)
        measurements.optString("error").takeIf { it.isNotBlank() }?.let { Text(it, color = K.amber, fontSize = 12.sp) }
    }
}
