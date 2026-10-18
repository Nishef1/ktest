package com.nishef.ktest

import androidx.compose.animation.AnimatedVisibility
import androidx.compose.animation.core.animateFloatAsState
import androidx.compose.animation.expandVertically
import androidx.compose.animation.fadeIn
import androidx.compose.animation.fadeOut
import androidx.compose.animation.shrinkVertically
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.draw.rotate
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import mobilebridge.Mobilebridge
import org.json.JSONObject
import kotlin.math.roundToInt

/** Tool inputs and results outlive tab switches; network calls run on the app scope. */
internal class ToolsState {
    var expanded by mutableStateOf<String?>("diagnose")

    var diagTarget by mutableStateOf("https://example.com")
    var diagNetwork by mutableStateOf("tcp")
    var diagBusy by mutableStateOf(false)
    var diagReport by mutableStateOf<JSONObject?>(null)
    var diagError by mutableStateOf<String?>(null)

    var cdnProvider by mutableStateOf("cloudflare")
    var cdnBudget by mutableFloatStateOf(120f)
    var cdnStarting by mutableStateOf(false)
    var cdnError by mutableStateOf<String?>(null)

    var frontUrl by mutableStateOf("https://example.com")
    var frontSni by mutableStateOf("example.com")
    var frontHost by mutableStateOf("example.com")
    var frontEdges by mutableStateOf("")
    var frontRounds by mutableStateOf("1")
    var frontProof by mutableStateOf(false)
    var frontBusy by mutableStateOf(false)
    var frontReport by mutableStateOf<JSONObject?>(null)
    var frontError by mutableStateOf<String?>(null)

    var echBusy by mutableStateOf(false)
    var echReport by mutableStateOf<JSONObject?>(null)
    var echError by mutableStateOf<String?>(null)

    var wsAddress by mutableStateOf("")
    var wsName by mutableStateOf("")
    var wsTransport by mutableStateOf("wstunnel")
    var wsBusy by mutableStateOf(false)
    var wsReport by mutableStateOf<JSONObject?>(null)
    var wsError by mutableStateOf<String?>(null)
}

private fun CoroutineScope.runTool(
    setBusy: (Boolean) -> Unit, setError: (String?) -> Unit, fallback: String,
    work: () -> String, done: (JSONObject) -> Unit
) {
    setBusy(true); setError(null)
    launch {
        try { done(withContext(Dispatchers.IO) { JSONObject(work()) }) }
        catch (e: Exception) { setError(e.message ?: fallback) }
        finally { setBusy(false) }
    }
}

@Composable
internal fun ToolsScreen(s: ToolsState, scope: CoroutineScope, onCopy: (String) -> Unit) {
    Column(verticalArrangement = Arrangement.spacedBy(12.dp)) {
        ScreenTitle("Tools", "Desktop diagnostics, running on your current Android network.")
        Spacer(Modifier.height(4.dp))
        ToolCard(s, "diagnose", KIcons.Globe, "Network diagnosis", "DNS, TCP and TLS checked separately") {
            DiagnoseTool(s, scope)
        }
        ToolCard(s, "cdn", KIcons.Search, "CDN scan", "Find responsive provider edges") {
            CDNScanTool(s, scope, onCopy)
        }
        ToolCard(s, "front", KIcons.Route, "Fronting test", "Compare up to 12 edges, optional origin proof") {
            FrontingTool(s, scope)
        }
        ToolCard(s, "ech", KIcons.Lock, "ECH bootstrap", "Fetch a fresh Cloudflare ECH configuration") {
            EchTool(s, scope)
        }
        ToolCard(s, "windscribe", KIcons.Wind, "Windscribe carrier", "WStunnel / Stealth readiness for one entry") {
            WindscribeCarrierTool(s, scope)
        }
        Spacer(Modifier.height(4.dp))
        Note("Results describe your network right now. DoH, DoT, resolver IPs and TLS/SNI can each be blocked independently; one failure does not prove the Internet or a destination is down.")
    }
}

@Composable
private fun ToolCard(
    s: ToolsState, id: String, icon: ImageVector, title: String, summary: String,
    content: @Composable ColumnScope.() -> Unit
) {
    val open = s.expanded == id
    val arrow by animateFloatAsState(if (open) 180f else 0f, label = "arrow")
    Panel(padding = 0.dp) {
        Row(
            Modifier.fillMaxWidth().clickable { s.expanded = if (open) null else id }.padding(16.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            IconTile(icon, if (open) K.mint else K.muted)
            Spacer(Modifier.width(14.dp))
            Column(Modifier.weight(1f)) {
                Text(title, color = K.text, fontSize = 15.sp, fontWeight = FontWeight.SemiBold)
                Text(summary, color = K.muted, fontSize = 12.sp, maxLines = 1, overflow = TextOverflow.Ellipsis)
            }
            Icon(KIcons.ExpandMore, if (open) "Collapse" else "Expand", tint = K.muted, modifier = Modifier.rotate(arrow))
        }
        AnimatedVisibility(open, enter = fadeIn() + expandVertically(), exit = fadeOut() + shrinkVertically()) {
            Column(Modifier.padding(start = 16.dp, end = 16.dp, bottom = 18.dp),
                verticalArrangement = Arrangement.spacedBy(12.dp), content = content)
        }
    }
}

@Composable
private fun DiagnoseTool(s: ToolsState, scope: CoroutineScope) {
    Segmented(listOf("tcp" to "Automatic", "tcp4" to "IPv4", "tcp6" to "IPv6"), s.diagNetwork,
        { s.diagNetwork = it }, enabled = !s.diagBusy)
    KField(s.diagTarget, { s.diagTarget = it }, "Destination URL", enabled = !s.diagBusy, keyboardType = KeyboardType.Uri)
    Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
        SecondaryButton("TikTok", {
            s.diagTarget = "https://www.tiktok.com/"
        }, Modifier.weight(1f), busy = s.diagBusy)
        SecondaryButton("Telegram Web", {
            s.diagTarget = "https://web.telegram.org/a/"
        }, Modifier.weight(1f), busy = s.diagBusy)
    }
    PrimaryButton(if (s.diagBusy) "Testing…" else "Run diagnosis", {
        scope.runTool({ s.diagBusy = it }, { s.diagError = it }, "Diagnostic failed",
            { Mobilebridge.diagnoseNetwork(s.diagTarget.trim(), s.diagNetwork) }) { s.diagReport = it }
        s.diagReport = null
    }, enabled = s.diagTarget.isNotBlank(), busy = s.diagBusy)
    s.diagError?.let { Note(it, Tone.Danger) }
    s.diagReport?.let { r ->
        val stages = listOf(
            Triple("DNS", "dns", "${r.optInt("dns_ipv4_count")} IPv4 · ${r.optInt("dns_ipv6_count")} IPv6"),
            Triple("TCP", "tcp", when (r.optString("network")) { "tcp4" -> "IPv4"; "tcp6" -> "IPv6"; else -> "Automatic IP family" }),
            Triple("TLS", "tls", listOf(r.optString("tls_version"), r.optString("alpn")).filter { it.isNotBlank() }.joinToString(" · "))
        )
        Column(Modifier.fillMaxWidth().clip(RoundedCornerShape(16.dp)).background(K.bg)
            .border(1.dp, K.stroke, RoundedCornerShape(16.dp)).padding(14.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp)) {
            stages.forEachIndexed { i, (label, key, detail) ->
                val state = r.optString("${key}_status")
                val ok = when (state) { "ok", "verified" -> true; "failed" -> false; else -> null }
                Row(verticalAlignment = Alignment.Top) {
                    Box(Modifier.padding(top = 3.dp).size(10.dp).clip(CircleShape)
                        .background(when (ok) { true -> K.mint; false -> K.amber; null -> K.faint }))
                    Spacer(Modifier.width(12.dp))
                    Column(Modifier.weight(1f)) {
                        Row(verticalAlignment = Alignment.CenterVertically) {
                            Text(label, color = K.text, fontWeight = FontWeight.SemiBold, fontSize = 14.sp,
                                modifier = Modifier.weight(1f))
                            Text("${r.optLong("${key}_duration_ms")} ms", color = K.muted, fontSize = 12.sp, fontFamily = K.mono)
                            Spacer(Modifier.width(8.dp))
                            ResultBadge(ok, state.ifBlank { "n/a" }.replace('_', ' ').uppercase())
                        }
                        if (ok == true && detail.isNotBlank()) Text(detail, color = K.muted, fontSize = 12.sp)
                        r.optString("${key}_error").takeIf { it.isNotBlank() }?.let {
                            Text(it, color = K.amber.copy(alpha = .85f), fontSize = 12.sp, lineHeight = 16.sp)
                        }
                    }
                }
                if (i < stages.lastIndex) Hairline()
            }
        }
        KeyValue("Outcome", r.optString("outcome", "Unknown").replace('_', ' '))
        KeyValue("Total", "${r.optLong("total_duration_ms")} ms", mono = true)
    }
    Note("Uses Android's default network, not the proxy. Success does not prove a VPN connection.")
}

@Composable
private fun CDNScanTool(s: ToolsState, scope: CoroutineScope, onCopy: (String) -> Unit) {
    var status by remember { mutableStateOf(JSONObject(Mobilebridge.cdnScanStatus())) }
    LaunchedEffect(Unit) {
        while (isActive) {
            status = withContext(Dispatchers.IO) { JSONObject(Mobilebridge.cdnScanStatus()) }
            delay(500)
        }
    }
    val running = status.optBoolean("running")
    val busy = s.cdnStarting || running
    val budget = s.cdnBudget.roundToInt()
    Segmented(listOf("cloudflare" to "Cloudflare", "akamai" to "Akamai", "fastly" to "Fastly", "google" to "Google"),
        s.cdnProvider, { s.cdnProvider = it }, enabled = !busy)
    Column {
        Row {
            Text("Candidate budget", color = K.muted, fontSize = 13.sp, modifier = Modifier.weight(1f))
            Text("$budget", color = K.text, fontSize = 13.sp, fontFamily = K.mono)
        }
        Slider(value = s.cdnBudget, onValueChange = { s.cdnBudget = it }, valueRange = 10f..300f, enabled = !busy,
            colors = SliderDefaults.colors(thumbColor = K.mint, activeTrackColor = K.mint,
                inactiveTrackColor = K.stroke, disabledThumbColor = K.faint, disabledActiveTrackColor = K.strokeStrong))
    }
    Row(horizontalArrangement = Arrangement.spacedBy(10.dp)) {
        PrimaryButton(if (busy) "Scanning…" else "Start scan", {
            s.cdnStarting = true; s.cdnError = null
            scope.launch {
                try {
                    withContext(Dispatchers.IO) {
                        Mobilebridge.startCDNScanForProvider(s.cdnProvider, budget.toLong(), minOf(10, budget).toLong())
                    }
                    status = JSONObject(Mobilebridge.cdnScanStatus())
                } catch (e: Exception) { s.cdnError = e.message ?: "Scan could not start" }
                finally { s.cdnStarting = false }
            }
        }, Modifier.weight(1f), busy = busy)
        if (running) SecondaryButton("Cancel", { Mobilebridge.cancelCDNScan() }, tint = K.red)
    }
    val attempted = status.optInt("attempted")
    val total = status.optInt("budget").coerceAtLeast(1)
    val verified = status.optJSONArray("verified_http")
    val found = verified?.length() ?: 0
    if (busy || attempted > 0) {
        LinearProgressIndicator(progress = { (attempted.toFloat() / total).coerceIn(0f, 1f) },
            modifier = Modifier.fillMaxWidth().height(6.dp).clip(CircleShape), color = K.mint, trackColor = K.stroke,
            drawStopIndicator = {})
        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            Stat("Checked", "$attempted / $total", Modifier.weight(1f))
            Stat("Verified", "$found", Modifier.weight(1f), if (found > 0) K.mint else K.text)
            Stat("Time", "${status.optLong("elapsed_ms") / 1000}s", Modifier.weight(1f))
        }
    }
    if (!busy && status.optBoolean("reached_goal")) Note("Stopped early: found ${status.optInt("goal")} verified edges.", Tone.Good)
    if (status.optBoolean("canceled")) Note(if (running) "Canceling…" else "Canceled; partial results shown.", Tone.Warn)
    if (verified != null && found > 0) {
        val ips = (0 until found).map { verified.getString(it) }
        @OptIn(ExperimentalLayoutApi::class)
        FlowRow(horizontalArrangement = Arrangement.spacedBy(6.dp), verticalArrangement = Arrangement.spacedBy(6.dp)) {
            ips.forEach { ip ->
                Text(ip, color = K.mint, fontSize = 12.sp, fontFamily = K.mono,
                    modifier = Modifier.clip(RoundedCornerShape(8.dp)).background(K.mint.copy(alpha = .1f))
                        .clickable { onCopy(ip) }.padding(horizontal = 9.dp, vertical = 5.dp))
            }
        }
        Row(horizontalArrangement = Arrangement.spacedBy(10.dp)) {
            SecondaryButton("Copy all", { onCopy(ips.joinToString("\n")) }, Modifier.weight(1f), icon = KIcons.Copy)
            SecondaryButton("Fronting test", {
                s.frontEdges = ips.take(12).joinToString(", ")
                s.expanded = "front"
            }, Modifier.weight(1f), icon = KIcons.Route)
        }
    }
    (s.cdnError ?: status.optString("error").takeIf { it.isNotBlank() })?.let { Note(it, Tone.Danger) }
    Note("Up to six checks run at once, for at most 90 seconds. A provider check does not prove arbitrary fronting, DNS availability or a working VPN.")
}

@Composable
private fun Stat(label: String, value: String, modifier: Modifier, color: androidx.compose.ui.graphics.Color = K.text) {
    Column(modifier.clip(RoundedCornerShape(14.dp)).background(K.bg).border(1.dp, K.stroke, RoundedCornerShape(14.dp))
        .padding(horizontal = 12.dp, vertical = 10.dp)) {
        Text(label, color = K.faint, fontSize = 11.sp)
        Text(value, color = color, fontSize = 15.sp, fontWeight = FontWeight.SemiBold, fontFamily = K.mono)
    }
}

@Composable
private fun FrontingTool(s: ToolsState, scope: CoroutineScope) {
    val busy = s.frontBusy
    KField(s.frontUrl, { s.frontUrl = it }, "HTTPS URL", enabled = !busy, keyboardType = KeyboardType.Uri)
    Row(horizontalArrangement = Arrangement.spacedBy(10.dp)) {
        KField(s.frontSni, { s.frontSni = it }, "TLS SNI", Modifier.weight(1f), enabled = !busy)
        KField(s.frontHost, { s.frontHost = it }, "HTTP Host", Modifier.weight(1f), enabled = !busy)
    }
    KField(s.frontEdges, { s.frontEdges = it }, "Edge IPs (comma or newline separated)", enabled = !busy,
        singleLine = false, minLines = 2, mono = true, supporting = "1–12 numeric addresses from an authorized edge")
    Column(verticalArrangement = Arrangement.spacedBy(6.dp)) {
        Text("Rounds per edge", color = K.muted, fontSize = 13.sp)
        Segmented(listOf("1" to "1", "2" to "2", "3" to "3"), s.frontRounds, { s.frontRounds = it }, enabled = !busy)
    }
    Row(verticalAlignment = Alignment.CenterVertically) {
        Column(Modifier.weight(1f)) {
            Text("Require origin proof", color = K.text, fontSize = 14.sp)
            Text("Only count edges that reach your controlled origin", color = K.muted, fontSize = 12.sp)
        }
        Switch(s.frontProof, { s.frontProof = it }, enabled = !busy,
            colors = SwitchDefaults.colors(checkedThumbColor = K.bg, checkedTrackColor = K.mint,
                uncheckedThumbColor = K.muted, uncheckedTrackColor = K.surfaceHigh, uncheckedBorderColor = K.strokeStrong))
    }
    PrimaryButton(if (busy) "Testing edges…" else "Compare edges", {
        s.frontReport = null
        scope.runTool({ s.frontBusy = it }, { s.frontError = it }, "Fronting test failed", {
            Mobilebridge.testFronts(s.frontUrl.trim(), s.frontSni.trim(), s.frontHost.trim(), s.frontEdges.trim(),
                s.frontRounds.toLong(), s.frontProof)
        }) { s.frontReport = it }
    }, enabled = s.frontEdges.isNotBlank(), busy = busy)
    s.frontError?.let { Note(it, Tone.Danger) }
    s.frontReport?.let { r ->
        val candidates = r.optJSONArray("candidates")
        if (candidates != null) for (i in 0 until candidates.length()) {
            val c = candidates.optJSONObject(i) ?: continue
            val attempts = c.optInt("attempts").coerceAtLeast(1)
            val assessment = c.optString("assessment")
            val color = when (assessment) {
                "origin_verified" -> K.mint; "http_2xx_unverified" -> K.cyan
                "tls_only", "tcp_only" -> K.amber; else -> K.red
            }
            Column(Modifier.fillMaxWidth().clip(RoundedCornerShape(16.dp)).background(K.bg)
                .border(1.dp, K.stroke, RoundedCornerShape(16.dp)).padding(14.dp),
                verticalArrangement = Arrangement.spacedBy(8.dp)) {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Text(c.optString("ip"), color = K.text, fontFamily = K.mono, fontSize = 14.sp, modifier = Modifier.weight(1f))
                    Tag(assessment.replace('_', ' '), color)
                }
                Row(horizontalArrangement = Arrangement.spacedBy(14.dp)) {
                    for ((label, key) in listOf("TCP" to "tcp_connected", "TLS" to "tls_verified",
                        "HTTP" to "http_2xx", "Origin" to "origin_verified")) {
                        Column {
                            Text(label, color = K.faint, fontSize = 10.sp)
                            Text("${c.optInt(key)}/$attempts", color = if (c.optInt(key) > 0) K.text else K.faint,
                                fontSize = 13.sp, fontFamily = K.mono)
                        }
                    }
                    Spacer(Modifier.weight(1f))
                    Column(horizontalAlignment = Alignment.End) {
                        Text("Median", color = K.faint, fontSize = 10.sp)
                        Text("${c.optLong("median_elapsed_ms")} ms", color = K.text, fontSize = 13.sp, fontFamily = K.mono)
                    }
                }
                c.optString("last_error").takeIf { it.isNotBlank() }?.let {
                    Text(it, color = K.faint, fontSize = 11.sp, maxLines = 2, overflow = TextOverflow.Ellipsis)
                }
            }
        }
        r.optString("note").takeIf { it.isNotBlank() }?.let { Note(it) }
    }
    Note("Use only an edge you are authorized to test. TLS or HTTP success alone does not prove origin routing.", Tone.Warn)
}

@Composable
private fun EchTool(s: ToolsState, scope: CoroutineScope) {
    Text("Checks whether Cloudflare returns a fresh, DNS-independent ECH retry configuration. No tunnel is opened.",
        color = K.muted, fontSize = 13.sp, lineHeight = 18.sp)
    SecondaryButton(if (s.echBusy) "Checking ECH…" else "Test ECH configuration", {
        s.echReport = null
        scope.runTool({ s.echBusy = it }, { s.echError = it }, "ECH probe failed", { Mobilebridge.probeEch() }) { s.echReport = it }
    }, Modifier.fillMaxWidth(), busy = s.echBusy, icon = KIcons.Key)
    s.echError?.let { Note(it, Tone.Danger) }
    s.echReport?.let { r ->
        KeyValue("Edge", r.optString("edge"), K.mint, mono = true)
        KeyValue("Config size", "${r.optInt("ech_config_bytes")} bytes", mono = true)
        KeyValue("Prefix", r.optString("config_prefix").take(16), K.muted, mono = true)
        Note(r.optString("note"))
    }
}

@Composable
private fun WindscribeCarrierTool(s: ToolsState, scope: CoroutineScope) {
    val busy = s.wsBusy
    Text("Test an authorized entry or your own CDN route. Use a hostname with a valid certificate.",
        color = K.muted, fontSize = 13.sp, lineHeight = 18.sp)
    KField(s.wsAddress, { s.wsAddress = it }, "Entry IP:port", enabled = !busy, mono = true, keyboardType = KeyboardType.Uri)
    KField(s.wsName, { s.wsName = it }, "TLS and HTTP hostname", enabled = !busy, keyboardType = KeyboardType.Uri)
    Segmented(listOf("wstunnel" to "WStunnel", "stealth" to "Stealth"), s.wsTransport, { s.wsTransport = it }, enabled = !busy)
    PrimaryButton(if (busy) "Testing…" else "Test carrier", {
        s.wsReport = null
        scope.runTool({ s.wsBusy = it }, { s.wsError = it }, "Carrier test failed", {
            Mobilebridge.testWindscribeCarrier(s.wsAddress.trim(), s.wsName.trim(), s.wsName.trim(), s.wsTransport)
        }) { s.wsReport = it }
    }, enabled = s.wsAddress.isNotBlank() && s.wsName.isNotBlank(), busy = busy)
    s.wsError?.let { Note(it, Tone.Danger) }
    s.wsReport?.let { r ->
        @OptIn(ExperimentalLayoutApi::class)
        FlowRow(horizontalArrangement = Arrangement.spacedBy(6.dp), verticalArrangement = Arrangement.spacedBy(6.dp)) {
            for ((label, key) in listOf("TCP" to "tcp", "TLS" to "tls_handshake", "Certificate" to "certificate_verified",
                "WebSocket" to "websocket")) {
                ResultBadge(r.optBoolean(key), (if (r.optBoolean(key)) "✓ " else "✗ ") + label)
            }
        }
        KeyValue("Elapsed", "${r.optLong("elapsed_ms")} ms", mono = true)
        if (r.optString("failure").isNotBlank()) Note("${r.optString("stage")}: ${r.optString("failure")}", Tone.Warn)
    }
    Note("TLS or WebSocket readiness does not prove OpenVPN authentication or VPN data. No VPN credentials are sent.")
}
