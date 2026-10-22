package com.nishef.ktest

import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
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
import androidx.compose.foundation.text.selection.SelectionContainer
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.draw.rotate
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.semantics.stateDescription
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import mobilebridge.Mobilebridge
import org.json.JSONObject
import java.io.File
import kotlin.math.roundToInt

/** Tool inputs and results outlive tab switches; network calls run on the app scope. */
internal class ToolsState {
    var expanded by mutableStateOf<String?>("diagnose")

    var diagTarget by mutableStateOf("https://example.com")
    var diagNetwork by mutableStateOf("tcp")
    var diagBusy by mutableStateOf(false)
    var diagReport by mutableStateOf<JSONObject?>(null)
    var diagError by mutableStateOf<String?>(null)

    var dnsInput by mutableStateOf("1.1.1.1\n8.8.8.8\n9.9.9.9\n223.5.5.5")
    var dnsBusy by mutableStateOf(false)
    var dnsReport by mutableStateOf<JSONObject?>(null)
    var dnsError by mutableStateOf<String?>(null)
    var dnsSelected by mutableStateOf("")
    var dnsMessage by mutableStateOf<String?>(null)

    var cdnProvider by mutableStateOf("cloudflare")
    var cdnFamily by mutableStateOf("ipv4")
    var cdnBudget by mutableFloatStateOf(120f)
    var cdnStarting by mutableStateOf(false)
    var cdnError by mutableStateOf<String?>(null)
    var cdnStatus by mutableStateOf(JSONObject())
    var cdnStatusLoaded by mutableStateOf(false)
    var cdnStatusError by mutableStateOf<String?>(null)
    var cdnExportBusy by mutableStateOf(false)
    var cdnExportPath by mutableStateOf<String?>(null)
    var cdnExportMessage by mutableStateOf<String?>(null)

    var frontTarget by mutableStateOf("x")
    var frontUrl by mutableStateOf("https://x.com/")
    var frontMode by mutableStateOf("auto")
    var frontSni by mutableStateOf("")
    var frontHost by mutableStateOf("")
    var frontPreset by mutableStateOf<JSONObject?>(null)
    var frontPresetFor by mutableStateOf("")
    var frontPresetError by mutableStateOf<String?>(null)
    var frontEdges by mutableStateOf("")
    var frontRounds by mutableStateOf("1")
    var frontProof by mutableStateOf(false)
    var frontBusy by mutableStateOf(false)
    var frontReport by mutableStateOf<JSONObject?>(null)
    var frontError by mutableStateOf<String?>(null)
    var frontRunMode by mutableStateOf("auto")
    var frontRunPreset by mutableStateOf<JSONObject?>(null)
    var frontRunUrl by mutableStateOf("")
    var frontRunSni by mutableStateOf("")
    var frontRunHost by mutableStateOf("")

    var echBusy by mutableStateOf(false)
    var echReport by mutableStateOf<JSONObject?>(null)
    var echError by mutableStateOf<String?>(null)

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
internal fun ToolsScreen(s: ToolsState, scope: CoroutineScope, onCopy: (String) -> Unit, scanAllowed: Boolean) {
    Column(verticalArrangement = Arrangement.spacedBy(12.dp)) {
        ScreenTitle("Tools", "Desktop diagnostics, running on your current Android network.")
        Spacer(Modifier.height(4.dp))
        ToolCard(s, "diagnose", KIcons.Globe, "Network diagnosis", "DNS, TCP and TLS checked separately") {
            DiagnoseTool(s, scope)
        }
        ToolCard(s, "dns", KIcons.Globe, "DNS resolver test", "Compare DNS servers and verify HTTPS") {
            DNSResolverTool(s, scope)
        }
        ToolCard(s, "cdn", KIcons.Search, "CDN scan", "Find responsive provider edges") {
            CDNScanTool(s, scope, onCopy, scanAllowed)
        }
        ToolCard(s, "front", KIcons.Route, "Fronting test", "Target presets or controlled-origin comparison") {
            FrontingTool(s, scope)
        }
        ToolCard(s, "ech", KIcons.Lock, "ECH bootstrap", "Fetch a fresh Cloudflare ECH configuration") {
            EchTool(s, scope)
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
private fun DNSResolverTool(s: ToolsState, scope: CoroutineScope) {
    val context = LocalContext.current
    val preferences = remember(context) {
        context.getSharedPreferences("ktest_android", android.content.Context.MODE_PRIVATE)
    }
    LaunchedEffect(Unit) {
        s.dnsSelected = preferences.getString("dns_override", "").orEmpty()
    }
    KField(
        s.dnsInput,
        { s.dnsInput = it; s.dnsError = null },
        "DNS server IPs",
        singleLine = false,
        minLines = 4,
        keyboardType = KeyboardType.Ascii,
        mono = true,
        enabled = !s.dnsBusy,
        supporting = "One IP per line; optional :port (default 53). Up to 12 entries."
    )
    Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
        PrimaryButton(
            if (s.dnsBusy) "Testing…" else "Test DNS servers",
            {
                s.dnsReport = null
                s.dnsMessage = null
                scope.runTool(
                    { s.dnsBusy = it },
                    { s.dnsError = it },
                    "DNS scan failed",
                    { Mobilebridge.scanDNS(s.dnsInput.trim()) }
                ) { s.dnsReport = it }
            },
            Modifier.weight(1f),
            enabled = s.dnsInput.isNotBlank(),
            busy = s.dnsBusy
        )
        SecondaryButton(
            "Automatic",
            {
                preferences.edit().remove("dns_override").apply()
                s.dnsSelected = ""
                s.dnsMessage = "Automatic encrypted DNS will be used on the next connection."
            },
            Modifier.weight(1f),
            enabled = !s.dnsBusy && s.dnsSelected.isNotBlank()
        )
    }
    if (s.dnsSelected.isNotBlank()) {
        Note("Selected for the next connection: ${s.dnsSelected}", Tone.Good)
    } else {
        Note("Automatic DNS is selected. KTest will use its built-in adaptive resolver list.")
    }
    val results = s.dnsReport?.optJSONArray("results")?.let { array ->
        (0 until array.length()).mapNotNull { array.optJSONObject(it) }
    }.orEmpty()
    val recommended = s.dnsReport?.optString("recommended").orEmpty()
    if (recommended.isNotBlank()) {
        Note("Best verified result: $recommended. DNS and an HTTPS/TLS handshake both succeeded.", Tone.Good)
        SecondaryButton(
            "Use best verified DNS",
            {
                preferences.edit().putString("dns_override", recommended).apply()
                s.dnsSelected = recommended
                s.dnsMessage = "DNS saved for the next connection."
            },
            Modifier.fillMaxWidth(),
            enabled = !s.dnsBusy
        )
    } else if (results.isNotEmpty()) {
        Note("No resolver completed both a usable DNS answer and an HTTPS/TLS check. You can still select a DNS-only result, but Internet access is not verified.", Tone.Warn)
    }
    results.forEach { result ->
        val server = result.optString("server")
        val dnsOK = result.optBoolean("dns")
        val internetOK = result.optBoolean("internet")
        Column(
            Modifier.fillMaxWidth().clip(RoundedCornerShape(14.dp)).background(K.bg)
                .border(1.dp, K.stroke, RoundedCornerShape(14.dp)).padding(12.dp),
            verticalArrangement = Arrangement.spacedBy(7.dp)
        ) {
            Text(server, color = K.text, fontFamily = K.mono, fontSize = 14.sp)
            Row(horizontalArrangement = Arrangement.spacedBy(6.dp), verticalAlignment = Alignment.CenterVertically) {
                Tag(if (result.optBoolean("udp")) "UDP OK" else "UDP failed", if (result.optBoolean("udp")) K.mint else K.amber)
                Tag(if (result.optBoolean("tcp")) "TCP OK" else "TCP failed", if (result.optBoolean("tcp")) K.mint else K.amber)
                Tag(if (internetOK) "Internet verified" else if (dnsOK) "DNS only" else "No DNS", if (internetOK) K.mint else K.amber)
            }
            Text(
                "DNS: ${result.optLong("dns_latency_ms")} ms · HTTPS/TLS: " +
                    (if (internetOK) "${result.optLong("https_latency_ms")} ms via ${result.optString("https_host")}" else "not verified"),
                color = K.muted, fontSize = 12.sp, lineHeight = 17.sp
            )
            val addresses = result.optJSONArray("addresses")
            if (addresses != null && addresses.length() > 0) {
                Text("Returned IPs: " + (0 until minOf(3, addresses.length())).joinToString(", ") { addresses.optString(it) },
                    color = K.faint, fontSize = 11.sp, fontFamily = K.mono)
            }
            result.optString("error").takeIf { it.isNotBlank() }?.let {
                Text(it, color = K.amber, fontSize = 11.sp, lineHeight = 15.sp)
            }
            SecondaryButton(
                if (s.dnsSelected == server) "Selected for next connection" else "Use this DNS",
                {
                    preferences.edit().putString("dns_override", server).apply()
                    s.dnsSelected = server
                    s.dnsMessage = if (internetOK) "Verified DNS saved for the next connection."
                        else "DNS responder saved for the next connection; Internet access was not verified."
                },
                Modifier.fillMaxWidth(),
                enabled = dnsOK && s.dnsSelected != server && !s.dnsBusy
            )
        }
    }
    s.dnsError?.let { Note(it, Tone.Danger) }
    s.dnsMessage?.let { Note(it, if (s.dnsSelected.isNotBlank()) Tone.Good else Tone.Info) }
    Note(
        "The test uses this phone's underlying network, not the active KTest tunnel. IP-based DNS queries are unencrypted. A selected resolver is used on the next Balanced/Fast connection and by the optional local anti-DPI carrier. Protected Aether/Psiphon/Tor packet DNS stays on the verified exit to avoid leaks."
    )
}

@Composable
private fun CDNScanTool(s: ToolsState, scope: CoroutineScope, onCopy: (String) -> Unit, scanAllowed: Boolean) {
    val context = LocalContext.current
    val pollError = s.cdnStatusError
    val exportCsv = rememberLauncherForActivityResult(ActivityResultContracts.CreateDocument("text/csv")) { uri ->
        val path = s.cdnExportPath
        s.cdnExportPath = null
        if (uri == null) {
            s.cdnExportBusy = false
        } else {
            scope.launch {
                try {
                    withContext(Dispatchers.IO) {
                        val source = privateScanCsv(context.filesDir, path ?: error("No completed scan selected"))
                        source.inputStream().use { input ->
                            val output = context.contentResolver.openOutputStream(uri, "w")
                                ?: error("Android could not open the selected CSV file")
                            output.use { input.copyTo(it) }
                        }
                    }
                    s.cdnExportMessage = "CSV saved with every attempted IP and its measured result."
                } catch (e: Exception) {
                    s.cdnError = e.message ?: "Unable to export scan results"
                } finally {
                    s.cdnExportBusy = false
                }
            }
        }
    }
    val status = s.cdnStatus
    val running = status.optBoolean("running")
    val busy = s.cdnStarting || running
    val controlsBusy = busy || s.cdnExportBusy || pollError != null || !s.cdnStatusLoaded || !scanAllowed
    val budget = if (s.cdnBudget.roundToInt() >= 310) 0L else s.cdnBudget.roundToInt().toLong()
    val budgetLabel = if (budget == 0L) "Until stopped" else "$budget IPs"
    Segmented(listOf("cloudflare" to "Cloudflare", "akamai" to "Akamai", "fastly" to "Fastly", "google" to "Google"),
        s.cdnProvider, { s.cdnProvider = it }, enabled = !controlsBusy)
    Segmented(listOf("meta" to "Meta", "cloudfront" to "CloudFront", "gcore" to "Gcore"),
        s.cdnProvider, { s.cdnProvider = it }, enabled = !controlsBusy)
    Segmented(listOf("ipv4" to "IPv4", "ipv6" to "IPv6"), s.cdnFamily,
        { s.cdnFamily = it }, enabled = !controlsBusy)
    Note(if (s.cdnFamily == "ipv6") "IPv6-only scan. Requires a working IPv6 route; no IPv4 fallback is attempted."
        else "IPv4-only scan. Choose IPv6 to test the provider's IPv6 inventory.")
    // Complete provider inventories (official lists or RIPEstat ASN data),
    // refreshed automatically while connected; this updates them now.
    var rangesInfo by remember { mutableStateOf<JSONObject?>(null) }
    var rangesBusy by remember { mutableStateOf(false) }
    LaunchedEffect(Unit) {
        rangesInfo = withContext(Dispatchers.IO) { runCatching { JSONObject(Mobilebridge.cdnRanges(context.filesDir.canonicalPath)) }.getOrNull() }
    }
    val inventory = rangesInfo?.optJSONArray("providers")?.let { array ->
        (0 until array.length()).mapNotNull { array.optJSONObject(it) }.firstOrNull { it.optString("name") == s.cdnProvider }
    }
    if (inventory != null) Note("${inventory.optLong("addresses")} provider addresses in ${inventory.optInt("prefixes")} prefixes · updated ${inventory.optString("updated")}")
    SecondaryButton(if (rangesBusy) "Updating IP ranges…" else "Update IP ranges", {
        rangesBusy = true
        scope.launch {
            rangesInfo = withContext(Dispatchers.IO) {
                runCatching { JSONObject(Mobilebridge.updateCDNRanges(context.filesDir.canonicalPath)) }
                    .getOrElse { runCatching { JSONObject(Mobilebridge.cdnRanges(context.filesDir.canonicalPath)) }.getOrNull() }
            }
            rangesBusy = false
        }
    }, enabled = !rangesBusy && !controlsBusy, busy = rangesBusy)
    Column {
        Row {
            Text("Candidate budget", color = K.muted, fontSize = 13.sp, modifier = Modifier.weight(1f))
            Text(budgetLabel, color = K.text, fontSize = 13.sp, fontFamily = K.mono)
        }
        Slider(value = s.cdnBudget, onValueChange = { s.cdnBudget = it }, valueRange = 10f..310f,
            steps = 29, enabled = !controlsBusy, modifier = Modifier.semantics { stateDescription = budgetLabel },
            colors = SliderDefaults.colors(thumbColor = K.mint, activeTrackColor = K.mint,
                inactiveTrackColor = K.stroke, disabledThumbColor = K.faint, disabledActiveTrackColor = K.strokeStrong))
        Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
            Text("10 IPs", color = K.faint, fontSize = 11.sp)
            Text("300 IPs · Until stopped →", color = K.muted, fontSize = 11.sp)
        }
    }
    Row(horizontalArrangement = Arrangement.spacedBy(10.dp)) {
        PrimaryButton(if (busy) "Scanning…" else "Start scan", {
            s.cdnStarting = true; s.cdnError = null
            s.cdnExportMessage = null
            val provider = s.cdnProvider
            val family = s.cdnFamily
            scope.launch {
                try {
                    s.cdnStatus = withContext(Dispatchers.IO) {
                        Mobilebridge.startCDNScanToFileFamily(provider, family, budget, context.filesDir.canonicalPath)
                        JSONObject(Mobilebridge.cdnScanStatus())
                    }
                    s.cdnStatusLoaded = true
                    s.cdnStatusError = null
                } catch (e: Exception) { s.cdnError = e.message ?: "Scan could not start" }
                finally { s.cdnStarting = false }
            }
        }, Modifier.weight(1f), enabled = !controlsBusy, busy = busy)
        if (running) SecondaryButton("Stop", {
            scope.launch { withContext(Dispatchers.IO) { Mobilebridge.cancelCDNScan() } }
        }, tint = K.red)
    }
    val attempted = status.optLong("attempted")
    val total = status.optLong("budget")
    val unlimited = status.optBoolean("unlimited")
    val found = status.optLong("total_verified")
    val results = status.optJSONArray("results")?.let { array ->
        (0 until array.length()).mapNotNull { array.optJSONObject(it) }
    }.orEmpty()
    if (busy || attempted > 0) {
        if (unlimited && busy) {
            LinearProgressIndicator(modifier = Modifier.fillMaxWidth().height(6.dp).clip(CircleShape),
                color = K.mint, trackColor = K.stroke)
        } else if (!unlimited && total > 0) {
            LinearProgressIndicator(progress = { (attempted.toFloat() / total).coerceIn(0f, 1f) },
                modifier = Modifier.fillMaxWidth().height(6.dp).clip(CircleShape), color = K.mint, trackColor = K.stroke,
                drawStopIndicator = {})
        }
        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            Stat("Attempted", "$attempted", Modifier.weight(1f))
            Stat("Provider HTTPS", "$found", Modifier.weight(1f), if (found > 0) K.mint else K.text)
            Stat("Elapsed", formatDuration(status.optLong("elapsed_ms") / 1000), Modifier.weight(1f))
        }
        Text(if (unlimited) "Budget: Until stopped" else "Budget: $total IPs",
            color = K.muted, fontSize = 12.sp)
    }
    if (!busy && status.optBoolean("exhausted")) Note("Provider candidate inventory exhausted.")
    if (status.optBoolean("canceled")) Note(if (running) "Stopping…" else "Stopped; completed checks are retained.", Tone.Warn)
    SecondaryButton(if (s.cdnExportBusy) "Saving CSV…" else "Export all scan results (.csv)", {
        s.cdnExportBusy = true; s.cdnError = null; s.cdnExportMessage = null
        scope.launch {
            try {
                s.cdnExportPath = withContext(Dispatchers.IO) {
                    privateScanCsv(context.filesDir, Mobilebridge.cdnScanExportPath()).path
                }
                exportCsv.launch("ktest-cdn-results.csv")
            } catch (e: Exception) {
                s.cdnExportBusy = false
                s.cdnError = e.message ?: "No completed CSV is available"
            }
        }
    }, Modifier.fillMaxWidth(), enabled = !busy && pollError == null && status.optString("export_path").isNotBlank(),
        busy = s.cdnExportBusy, icon = KIcons.Download)
    if (results.isNotEmpty()) {
        FrontTargetInput(s, enabled = !s.frontBusy)
        LoadFrontingPreset(s)
        val preset = s.frontPreset.takeIf { s.frontPresetFor == s.frontUrl.trim() }
        val provider = status.optString("provider")
        val compatible = preset?.optBoolean("supported") == true && when (preset.optString("family")) {
            "fastly" -> provider == "fastly"
            "cloudflare", "google", "akamai", "meta" -> provider == preset.optString("family")
            else -> false
        }
        val candidates = results.filter {
            it.optString("ip").isNotBlank() && (it.optBoolean("tls_verified") ||
                it.optBoolean("http_verified") || it.optLong("tcp_ms") > 0 || it.optString("assessment") == "tcp_only")
        }.sortedWith(compareByDescending<JSONObject> { it.optBoolean("http_verified") && it.optBoolean("tls_verified") }
            .thenByDescending { it.optBoolean("tls_verified") }
            .thenBy { it.optLong("tcp_ms", Long.MAX_VALUE) }
            .thenBy { it.optLong("elapsed_ms", Long.MAX_VALUE) })
        SecondaryButton("Use best for fronting test", {
            s.frontEdges = candidates.map { it.optString("ip") }.distinct().take(12).joinToString(", ")
            s.frontMode = "auto"
            s.frontReport = null
            s.frontError = null
            s.expanded = "front"
        }, Modifier.fillMaxWidth(), enabled = compatible && candidates.isNotEmpty() && !s.frontBusy, icon = KIcons.Route)
        Text(when {
            compatible -> "Selects up to 12 family-compatible edges from this preview, ranked by provider HTTPS, TLS and TCP connect time. Target proof is a separate test."
            preset?.optString("family") == "twimg" -> "This target needs its own customer-specific Fastly edges. Enter those IPs in Fronting test."
            else -> "Choose a target supported by this provider's family, or scan its provider first. X uses Cloudflare; YouTube uses Google."
        },
            color = K.muted, fontSize = 12.sp, lineHeight = 17.sp)
        s.frontPresetError?.let { Note(it, Tone.Warn) }
        Text("Result preview · ${minOf(24, results.size)} of ${results.size} returned results",
            color = K.muted, fontSize = 12.sp)
        results.take(24).forEach { result ->
            val tls = result.optBoolean("tls_verified")
            val http = result.optBoolean("http_verified")
            val tcp = tls || http || result.optLong("tcp_ms") > 0 || result.optString("assessment") == "tcp_only"
            val color = if (tls && http) K.mint else if (tcp) K.amber else K.red
            Column(Modifier.fillMaxWidth().clip(RoundedCornerShape(14.dp)).background(K.bg).padding(12.dp),
                verticalArrangement = Arrangement.spacedBy(6.dp)) {
                Text(result.optString("ip"), color = color, fontFamily = K.mono, fontSize = 14.sp,
                    modifier = Modifier.fillMaxWidth().clickable { onCopy(result.optString("ip")) })
                Text(when {
                    tls && http -> "Provider HTTPS verified · target proof not tested"
                    tls -> "TLS only · provider HTTP not verified"
                    tcp -> "TCP only · TLS not verified"
                    else -> "Connection not verified"
                }, color = color, fontSize = 12.sp)
                Text("TCP connect: ${if (tcp) "${result.optLong("tcp_ms")} ms" else "not connected"} · " +
                    "TLS: ${if (tls) "verified" else "not verified"} (${result.optLong("tls_ms")} ms)",
                    color = K.muted, fontSize = 12.sp)
                Text("HTTP: ${result.optInt("http_status").takeIf { it > 0 } ?: "no response"} · " +
                    "Elapsed: ${result.optLong("elapsed_ms")} ms", color = K.muted, fontSize = 12.sp)
                result.optString("error").takeIf { it.isNotBlank() }?.let { Text(it, color = K.amber, fontSize = 11.sp) }
            }
        }
        Note("The preview is bounded. Provider HTTPS total and the CSV include results beyond this list. TCP connect measures a connection handshake, not ICMP ping.")
    }
    (s.cdnError ?: pollError ?: status.optString("error").takeIf { it.isNotBlank() })?.let { Note(it, Tone.Danger) }
    s.cdnExportMessage?.let { Note(it, Tone.Good) }
    Note("CDN scanning is available only while offline. Stop a running scan before Connect or Test routes. Finite budgets check the selected number of candidates; Until stopped continues until you stop it or the provider inventory is exhausted. A completed CSV can still be exported while connected. Provider HTTPS does not prove target fronting or VPN access.")
}

private fun privateScanCsv(filesDir: File, path: String): File {
    require(path.isNotBlank() && File(path).isAbsolute) { "No completed private CSV is available" }
    val root = filesDir.canonicalFile
    val source = File(path).canonicalFile
    require(source.path.startsWith(root.path + File.separator) && source.isFile && source.extension.equals("csv", true)) {
        "Scan export must be a CSV inside KTest's private files directory"
    }
    return source
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
private fun FrontTargetInput(s: ToolsState, enabled: Boolean, showUrl: Boolean = true) {
    Segmented(listOf("x" to "X", "youtube" to "YouTube", "custom" to "Custom URL"), s.frontTarget, {
        s.frontTarget = it
        when (it) {
            "x" -> s.frontUrl = "https://x.com/"
            "youtube" -> s.frontUrl = "https://www.youtube.com/"
        }
    }, enabled = enabled)
    if (showUrl && s.frontTarget == "custom") {
        KField(s.frontUrl, { s.frontUrl = it }, "Target HTTPS URL", enabled = enabled, keyboardType = KeyboardType.Uri)
    }
}

@Composable
private fun LoadFrontingPreset(s: ToolsState) {
    val url = s.frontUrl.trim()
    LaunchedEffect(url) {
        if (s.frontPresetFor == url && s.frontPreset != null) return@LaunchedEffect
        s.frontPresetError = null
        s.frontPreset = null
        delay(250)
        try {
            val preset = withContext(Dispatchers.IO) { JSONObject(Mobilebridge.frontingPreset(url)) }
            s.frontPreset = preset
            s.frontPresetFor = url
        } catch (e: kotlinx.coroutines.CancellationException) {
            throw e
        } catch (e: Exception) {
            s.frontPresetError = e.message ?: "Could not resolve target preset"
        }
    }
}

@Composable
private fun ToolDetail(label: String, value: String, mono: Boolean = false) {
    Column(Modifier.fillMaxWidth(), verticalArrangement = Arrangement.spacedBy(3.dp)) {
        Text(label, color = K.muted, fontSize = 12.sp)
        SelectionContainer {
            Text(value, modifier = Modifier.fillMaxWidth(), color = K.text, fontSize = 13.sp,
                fontFamily = if (mono) K.mono else null, lineHeight = 18.sp)
        }
    }
}

@Composable
private fun FrontingTool(s: ToolsState, scope: CoroutineScope) {
    val privateDir = LocalContext.current.filesDir.canonicalPath
    val busy = s.frontBusy
    val automatic = s.frontMode == "auto"
    FrontTargetInput(s, enabled = !busy, showUrl = automatic)
    Segmented(listOf("auto" to "Target preset", "manual" to "Manual SNI / Host"), s.frontMode,
        { s.frontMode = it }, enabled = !busy)
    LoadFrontingPreset(s)
    val preset = s.frontPreset.takeIf { s.frontPresetFor == s.frontUrl.trim() }
    if (automatic) {
        if (preset != null) {
            ToolDetail("Method", if (preset.optBoolean("uses_ech")) "Encrypted Client Hello (ECH)" else "Family fronting probe")
            ToolDetail("Family", preset.optString("family").ifBlank { "Unsupported" })
            ToolDetail(if (preset.optBoolean("uses_ech")) "Outer SNI · target name is encrypted" else "TLS SNI",
                preset.optString("sni").ifBlank { "No SNI" }, mono = true)
            ToolDetail("HTTP Host", preset.optString("http_host"), mono = true)
            preset.optString("note").takeIf { it.isNotBlank() }?.let { Note(it) }
            if (!preset.optBoolean("supported")) Note("No automatic family preset for this URL. Use manual mode for a controlled origin.", Tone.Warn)
        } else if (s.frontPresetError == null) {
            Note("Resolving the target's family and transport method…")
        }
        s.frontPresetError?.let { Note(it, Tone.Warn) }
        Note("Automatic tests use the Go family's real transport, including ECH when required. Setting a plain SNI to cloudflare-ech.com does not negotiate ECH.")
    } else {
        KField(s.frontUrl, { s.frontUrl = it; s.frontTarget = "custom" }, "Manual HTTPS URL", enabled = !busy,
            keyboardType = KeyboardType.Uri)
        KField(s.frontSni, { s.frontSni = it }, "TLS SNI (blank uses URL hostname)", enabled = !busy)
        KField(s.frontHost, { s.frontHost = it }, "HTTP Host (blank uses URL host)", enabled = !busy)
        Note("Manual mode sends the SNI and Host you specify without ECH. Use a controlled origin and its proof response to verify routing.", Tone.Warn)
    }
    KField(s.frontEdges, { s.frontEdges = it }, "Edge IPs (comma or newline separated)", enabled = !busy,
        singleLine = false, minLines = 2, mono = true, supporting = "Comparison batch: 1–12 numeric IPs. This is separate from the CDN scan budget.")
    Column(verticalArrangement = Arrangement.spacedBy(6.dp)) {
        Text("Rounds per edge", color = K.muted, fontSize = 13.sp)
        Segmented(listOf("1" to "1", "2" to "2", "3" to "3"), s.frontRounds, { s.frontRounds = it }, enabled = !busy)
    }
    if (!automatic) Row(verticalAlignment = Alignment.CenterVertically) {
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
        s.frontRunMode = s.frontMode
        s.frontRunPreset = preset
        s.frontRunUrl = s.frontUrl.trim()
        s.frontRunSni = s.frontSni.trim()
        s.frontRunHost = s.frontHost.trim()
        val url = s.frontRunUrl
        val edges = s.frontEdges.trim()
        val rounds = s.frontRounds.toLong()
        val sni = s.frontRunSni
        val host = s.frontRunHost
        val proof = s.frontProof
        scope.runTool({ s.frontBusy = it }, { s.frontError = it }, "Fronting test failed", {
            if (automatic) Mobilebridge.testTargetFronting(privateDir, url, edges, rounds)
            else Mobilebridge.testFronts(url, sni, host, edges, rounds, proof)
        }) { s.frontReport = it }
    }, enabled = s.frontEdges.isNotBlank() && s.frontUrl.isNotBlank() &&
        (!automatic || preset?.optBoolean("supported") == true), busy = busy)
    s.frontError?.let { Note(it, Tone.Danger) }
    s.frontReport?.let { r ->
        val autoResult = s.frontRunMode == "auto"
        ToolDetail("Tested URL", r.optString("url").ifBlank { s.frontRunUrl }, mono = true)
        ToolDetail("Method", r.optString("method").ifBlank {
            if (!autoResult) "Manual TLS / HTTP Host probe"
            else if (s.frontRunPreset?.optBoolean("uses_ech") == true) "Target family probe with ECH"
            else "Target family fronting probe"
        })
        val reportedSni = r.optString("tls_name").ifBlank { r.optString("sni") }
        ToolDetail(if (reportedSni.isBlank()) "Requested TLS / outer SNI" else "Reported TLS / outer SNI",
            reportedSni.ifBlank {
                if (autoResult) s.frontRunPreset?.optString("sni").orEmpty().ifBlank { "No SNI" }
                else s.frontRunSni.ifBlank { "URL hostname" }
            }, mono = true)
        ToolDetail("HTTP Host", r.optString("http_host").ifBlank {
            if (autoResult) s.frontRunPreset?.optString("http_host").orEmpty()
            else s.frontRunHost.ifBlank { "URL host" }
        }, mono = true)
        val candidates = r.optJSONArray("candidates")
        if (candidates != null) for (i in 0 until candidates.length()) {
            val c = candidates.optJSONObject(i) ?: continue
            val attempts = c.optInt("attempts")
            val assessment = c.optString("assessment")
            val verified = attempts > 0 && c.optInt("origin_verified") == attempts
            val color = if (verified) K.mint else if (c.optInt("tcp_connected") > 0 ||
                c.optInt("tls_verified") > 0 || c.optInt("http_2xx") > 0) K.amber else K.red
            Column(Modifier.fillMaxWidth().clip(RoundedCornerShape(16.dp)).background(K.bg)
                .border(1.dp, K.stroke, RoundedCornerShape(16.dp)).padding(14.dp),
                verticalArrangement = Arrangement.spacedBy(8.dp)) {
                Text(c.optString("ip"), color = K.text, fontFamily = K.mono, fontSize = 14.sp)
                Text(if (verified) (if (autoResult) "Target proof verified" else "Controlled origin verified")
                    else "${assessment.ifBlank { "No proof" }.replace('_', ' ')} · target proof unverified",
                    color = color, fontSize = 12.sp)
                @OptIn(ExperimentalLayoutApi::class)
                FlowRow(horizontalArrangement = Arrangement.spacedBy(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                    for ((label, key) in listOf("TCP" to "tcp_connected", "TLS" to "tls_verified",
                        "HTTP 2xx" to "http_2xx", (if (autoResult) "Target proof" else "Origin proof") to "origin_verified")) {
                        Column {
                            Text(label, color = K.faint, fontSize = 10.sp)
                            Text("${c.optInt(key)}/$attempts", color = if (c.optInt(key) > 0) K.text else K.faint,
                                fontSize = 13.sp, fontFamily = K.mono)
                        }
                    }
                    Column {
                        Text("Median elapsed", color = K.faint, fontSize = 10.sp)
                        Text("${c.optLong("median_elapsed_ms")} ms", color = K.text, fontSize = 13.sp, fontFamily = K.mono)
                    }
                }
                c.optInt("last_http_status").takeIf { it > 0 }?.let {
                    Text("Last HTTP status: $it", color = K.muted, fontSize = 12.sp)
                }
                for ((label, key) in listOf("Method" to "method", "SNI" to "sni", "HTTP Host" to "http_host", "Evidence" to "evidence")) {
                    c.optString(key).takeIf { it.isNotBlank() }?.let { ToolDetail(label, it) }
                }
                Text(if (verified) "Explicit ${if (autoResult) "target" else "origin"} proof passed in every round."
                    else "A response status, including HTTP 200, does not verify arbitrary fronting.",
                    color = if (verified) K.mint else K.muted, fontSize = 12.sp)
                c.optString("last_error").takeIf { it.isNotBlank() }?.let {
                    Text(it, color = K.amber, fontSize = 11.sp)
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
