package com.nishef.ktest

import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.content.Intent
import android.net.Uri
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.animation.core.FastOutSlowInEasing
import androidx.compose.animation.core.RepeatMode
import androidx.compose.animation.core.animateFloat
import androidx.compose.animation.core.infiniteRepeatable
import androidx.compose.animation.core.rememberInfiniteTransition
import androidx.compose.animation.core.tween
import androidx.compose.foundation.Canvas
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.geometry.Size
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.StrokeCap
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import mobilebridge.Mobilebridge
import org.json.JSONObject

private val background = Color(0xFF080F15)
private val surface = Color(0xFF14212A)
private val edge = Color(0xFF293B48)
private val accent = Color(0xFF79DFC6)
private val white = Color(0xFFF1F5F4)
private val muted = Color(0xFF9EB1BE)
private val amber = Color(0xFFFFD08B)
private val red = Color(0xFFFFAB9E)

private data class ConnectionMode(
    val id: String, val title: String, val subtitle: String, val available: Boolean,
    val limitation: String
)

// The Go catalog is the canonical description of the current CLI modes.
// Android does not silently rebrand Psiphon or Tor as unrelated transports.
private val modes: List<ConnectionMode> by lazy {
    runCatching {
        val values = JSONObject(Mobilebridge.connectionModes()).getJSONArray("modes")
        (0 until values.length()).map { i ->
            val item = values.getJSONObject(i)
            ConnectionMode(
                item.getString("id"), item.getString("title"),
                item.getString("subtitle"), item.getBoolean("available"),
                item.optString("limitation")
            )
        }
    }.getOrElse {
        listOf(ConnectionMode("balanced", "Balanced", "Connection catalog unavailable", false,
            "Cannot read the Go engine's mode definitions."))
    }
}

class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        window.statusBarColor = android.graphics.Color.rgb(8, 15, 21)
        window.navigationBarColor = android.graphics.Color.rgb(8, 15, 21)
        setContent {
            MaterialTheme(colorScheme = darkColorScheme(
                background = background, surface = surface, primary = accent,
                onPrimary = background, onBackground = white, onSurface = white
            )) {
                ConnectionApp()
            }
        }
    }
}

@Composable
private fun ConnectionApp() {
    val context = LocalContext.current
    val prefs = remember { context.getSharedPreferences("ktest_android", Context.MODE_PRIVATE) }
    var tab by rememberSaveable { mutableIntStateOf(0) }
    var modeId by rememberSaveable { mutableStateOf(prefs.getString("mode", "balanced") ?: "balanced") }
    var upstream by remember { mutableStateOf(prefs.getString("upstream_$modeId", "") ?: "") }
    var status by remember { mutableStateOf(JSONObject(Mobilebridge.proxyStatus())) }
    var connecting by remember { mutableStateOf(false) }
    var checkingRoute by remember { mutableStateOf(false) }
    var routeReport by remember { mutableStateOf<JSONObject?>(null) }
    var error by remember { mutableStateOf<String?>(null) }
    var testing by remember { mutableStateOf(false) }
    var target by rememberSaveable { mutableStateOf("https://example.com") }
    var report by remember { mutableStateOf<JSONObject?>(null) }
    var frontUrl by rememberSaveable { mutableStateOf("https://example.com") }
    var frontSni by rememberSaveable { mutableStateOf("example.com") }
    var frontHost by rememberSaveable { mutableStateOf("example.com") }
    var frontEdge by rememberSaveable { mutableStateOf("") }
    var frontBusy by remember { mutableStateOf(false) }
    var frontReport by remember { mutableStateOf<JSONObject?>(null) }
    var echBusy by remember { mutableStateOf(false) }
    var echReport by remember { mutableStateOf<JSONObject?>(null) }
    var checkingUpdates by remember { mutableStateOf(false) }
    var update by remember { mutableStateOf<UpdateInfo?>(null) }
    val scope = rememberCoroutineScope()
    val running = status.optBoolean("running")
    LaunchedEffect(Unit) {
        while (isActive) {
            status = runCatching { JSONObject(Mobilebridge.proxyStatus()) }
                .getOrElse { JSONObject() }
            if (status.optBoolean("running") || ProxyService.lastError != null) connecting = false
            if (ProxyService.lastError != null) error = ProxyService.lastError
            delay(900)
        }
    }

    Column(
        Modifier.fillMaxSize().background(background)
            .padding(WindowInsets.safeDrawing.asPaddingValues())
    ) {
        Column(
            Modifier.weight(1f).verticalScroll(rememberScrollState())
                .padding(horizontal = 22.dp, vertical = 20.dp),
            verticalArrangement = Arrangement.spacedBy(20.dp)
        ) {
            Row(Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.SpaceBetween) {
                Column {
                    Text("KTEST", fontWeight = FontWeight.ExtraBold, color = white,
                        fontSize = 25.sp, letterSpacing = 2.sp)
                    Text("CONNECTION", fontSize = 10.sp, color = accent, letterSpacing = 2.5.sp)
                }
                Surface(color = surface, shape = RoundedCornerShape(50.dp)) {
                    Text("v${BuildConfig.VERSION_NAME} PREVIEW",
                        modifier = Modifier.padding(horizontal = 12.dp, vertical = 8.dp),
                        color = muted, fontSize = 10.sp)
                }
            }
            when (tab) {
                0 -> {
                    ConnectionScreen(
                        activeMode = activeMode,
                        running = running,
                        status = status,
                        connecting = connecting,
                        routeReport = routeReport, checkingRoute = checkingRoute,
                        onCheckRoute = {
                            checkingRoute = true
                            routeReport = null
                            scope.launch {
                                try {
                                    routeReport = withContext(Dispatchers.IO) {
                                        JSONObject(Mobilebridge.checkRoute())
                                    }
                                } catch (e: Exception) {
                                    error = e.message ?: "Route check failed"
                                } finally {
                                    checkingRoute = false
                                }
                            }
                        },
                        upstream = upstream,
                        onUpstream = { upstream = it; prefs.edit().putString("upstream_$modeId", it).apply() },
                        error = error,
                        onMode = {
                            if (!running) {
                                modeId = it
                                upstream = prefs.getString("upstream_$it", "") ?: ""
                                prefs.edit().putString("mode", it).apply()
                                error = null
                            }
                        },
                        onPower = {
                            error = null
                            if (running || connecting) {
                                context.startService(Intent(context, ProxyService::class.java).apply {
                                    action = ProxyService.ACTION_STOP
                                })
                                connecting = false
                            } else if (activeMode.available) {
                                connecting = true
                                routeReport = null
                                ProxyService.lastError = null
                                try {
                                    androidx.core.content.ContextCompat.startForegroundService(
                                        context,
                                        Intent(context, ProxyService::class.java).apply {
                                            action = ProxyService.ACTION_CONNECT
                                            putExtra(ProxyService.EXTRA_MODE, modeId)
                                            putExtra(ProxyService.EXTRA_UPSTREAM, upstream.trim())
                                        }
                                    )
                                } catch (e: Exception) {
                                    error = e.message ?: "Unable to start Go proxy"
                                    connecting = false
                                }
                            }
                        },
                        onCopy = { text ->
                            (context.getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager)
                                .setPrimaryClip(ClipData.newPlainText("KTest proxy address", text))
                        }
                    )
                }
                1 -> ToolsScreen(
                    target = target, onTarget = { target = it }, busy = testing,
                    report = report, error = error,
                    frontUrl = frontUrl, frontSni = frontSni, frontHost = frontHost, frontEdge = frontEdge,
                    setFrontUrl = { frontUrl = it }, setFrontSni = { frontSni = it },
                    setFrontHost = { frontHost = it }, setFrontEdge = { frontEdge = it },
                    frontBusy = frontBusy, frontReport = frontReport,
                    echBusy = echBusy, echReport = echReport,
                    runFront = {
                        frontBusy = true; frontReport = null; error = null
                        scope.launch {
                            try {
                                frontReport = withContext(Dispatchers.IO) {
                                    JSONObject(Mobilebridge.testFront(frontUrl.trim(), frontSni.trim(),
                                        frontHost.trim(), frontEdge.trim()))
                                }
                            } catch (e: Exception) { error = e.message ?: "CDN test failed" }
                            finally { frontBusy = false }
                        }
                    },
                    runEch = {
                        echBusy = true; echReport = null; error = null
                        scope.launch {
                            try {
                                echReport = withContext(Dispatchers.IO) { JSONObject(Mobilebridge.probeEch()) }
                            } catch (e: Exception) { error = e.message ?: "ECH probe failed" }
                            finally { echBusy = false }
                        }
                    },
                    runTest = {
                        testing = true
                        report = null
                        error = null
                        scope.launch {
                            try {
                                report = withContext(Dispatchers.IO) {
                                    JSONObject(Mobilebridge.diagnose(target.trim()))
                                }
                            } catch (e: Exception) {
                                error = e.message ?: "Diagnostic failed"
                            } finally {
                                testing = false
                            }
                        }
                    }
                )
                else -> SettingsScreen(
                    checking = checkingUpdates, update = update,
                    check = {
                        checkingUpdates = true
                        scope.launch {
                            update = try { withContext(Dispatchers.IO) { UpdateChecker.check() } }
                            catch (_: Exception) { UpdateInfo("Cannot reach GitHub releases right now.") }
                            checkingUpdates = false
                        }
                    },
                    openDownload = { url ->
                        context.startActivity(Intent(Intent.ACTION_VIEW, Uri.parse(url)))
                    }
                )
            }
        }
        NavigationBar(containerColor = surface, contentColor = white, tonalElevation = 0.dp) {
            for ((index, title) in listOf("Connect", "Tools", "Settings").withIndex()) {
                NavigationBarItem(
                    selected = tab == index,
                    onClick = { tab = index; error = null },
                    icon = {
                        Text(when (index) { 0 -> "◉"; 1 -> "◇"; else -> "⚙" }, fontSize = 19.sp)
                    },
                    label = { Text(title, fontSize = 12.sp) },
                    colors = NavigationBarItemDefaults.colors(
                        selectedIconColor = accent, selectedTextColor = accent,
                        unselectedIconColor = muted, unselectedTextColor = muted,
                        indicatorColor = edge
                    )
                )
            }
        }
    }
}

@Composable
private fun ConnectionScreen(
    activeMode: ConnectionMode, running: Boolean, status: JSONObject,
    connecting: Boolean, routeReport: JSONObject?, checkingRoute: Boolean,
    onCheckRoute: () -> Unit,
    upstream: String, onUpstream: (String) -> Unit, error: String?,
    onMode: (String) -> Unit, onPower: () -> Unit, onCopy: (String) -> Unit
) {
    Column(verticalArrangement = Arrangement.spacedBy(20.dp)) {
        Column {
            Text("Your connection", fontSize = 25.sp, fontWeight = FontWeight.SemiBold, color = white)
            Spacer(Modifier.height(5.dp))
            Text("Choose a route and control your proxy.", color = muted, fontSize = 13.sp)
        }
        Surface(color = surface, shape = RoundedCornerShape(29.dp)) {
            Column(
                Modifier.fillMaxWidth().padding(vertical = 24.dp, horizontal = 14.dp),
                horizontalAlignment = Alignment.CenterHorizontally,
                verticalArrangement = Arrangement.spacedBy(10.dp)
            ) {
                val coreNeeded = activeMode.id == "aether"
                val canConnect = activeMode.available && (!coreNeeded || upstream.isNotBlank())
                val stateLabel = when {
                    running -> "PROXY ACTIVE"
                    connecting -> "CHECKING ROUTE"
                    !activeMode.available -> "NOT AVAILABLE YET"
                    !canConnect -> "SOCKS5 CORE REQUIRED"
                    else -> "DISCONNECTED"
                }
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Box(Modifier.size(8.dp).background(
                        if (running) accent else if (!canConnect) amber else muted,
                        CircleShape
                    ))
                    Spacer(Modifier.width(8.dp))
                    Text(stateLabel, color = if (running) accent else muted,
                        fontWeight = FontWeight.Bold, fontSize = 12.sp, letterSpacing = 1.4.sp)
                }
                PowerOrb(enabled = running || connecting || canConnect,
                    active = running, onClick = onPower)
                Text(
                    when {
                        running -> "Disconnect"
                        connecting -> "Connecting..."
                        !activeMode.available -> "Unavailable on Android"
                        !canConnect -> "Configure SOCKS5 first"
                        else -> "Connect"
                    },
                    color = white, fontSize = 23.sp, fontWeight = FontWeight.SemiBold
                )
                Text(
                    when {
                        running -> "Local proxy active · Not a system VPN"
                        connecting -> "Verifying local upstream and foreign exit..."
                        !activeMode.available -> "This desktop core has not been ported."
                        !canConnect -> "Connect an existing local SOCKS5 core"
                        else -> "Start local SOCKS5 + HTTP proxy"
                    },
                    color = muted, textAlign = TextAlign.Center, fontSize = 12.sp
                )
                if (running) {
                    Spacer(Modifier.height(8.dp))
                    Button(onClick = onCheckRoute, enabled = !checkingRoute,
                        colors = ButtonDefaults.buttonColors(containerColor = edge, contentColor = white)) {
                        Text(if (checkingRoute) "Checking HTTPS routes..." else "Verify real HTTPS traffic")
                    }
                    if (routeReport != null) {
                        val successes = routeReport.optInt("verified")
                        val attempts = routeReport.optInt("attempted")
                        Text("$successes / $attempts real HTTPS targets succeeded",
                            color = if (successes > 0) accent else amber, fontSize = 12.sp)
                    }

                    for ((label, key) in listOf("SOCKS5" to "socks", "HTTP" to "http")) {
                        val address = status.optString(key)
                        if (address.isNotBlank()) {
                            Row(verticalAlignment = Alignment.CenterVertically,
                                modifier = Modifier.fillMaxWidth().padding(horizontal = 10.dp)) {
                                Text(label, color = muted, modifier = Modifier.width(60.dp),
                                    fontSize = 10.sp)
                                Text(address, color = white, modifier = Modifier.weight(1f),
                                    fontSize = 13.sp)
                                TextButton(onClick = { onCopy(address) }) {
                                    Text("Copy", color = accent, fontSize = 12.sp)
                                }
                            }
                        }
                    }
                }
            }
        }

        Surface(color = surface, shape = RoundedCornerShape(24.dp)) {
            Column(Modifier.fillMaxWidth().padding(18.dp)) {
                Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically) {
                    Text("CONNECTION MODE", color = muted, fontSize = 11.sp,
                        letterSpacing = 1.5.sp, fontWeight = FontWeight.Bold)
                    if (running) Text("LOCKED WHILE ACTIVE", color = amber, fontSize = 9.sp)
                }
                Spacer(Modifier.height(14.dp))
                Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                    modes.forEach { mode ->
                        val selected = activeMode.id == mode.id
                        Row(
                            Modifier.fillMaxWidth().clip(RoundedCornerShape(15.dp))
                                .background(if (selected) edge else Color.Transparent)
                                .clickable(enabled = !running) { onMode(mode.id) }
                                .padding(horizontal = 12.dp, vertical = 11.dp),
                            verticalAlignment = Alignment.CenterVertically
                        ) {
                            Box(Modifier.size(17.dp).background(
                                if (selected) accent else edge, CircleShape
                            ), contentAlignment = Alignment.Center) {
                                if (selected) Box(Modifier.size(7.dp).background(background, CircleShape))
                            }
                            Spacer(Modifier.width(12.dp))
                            Column(Modifier.weight(1f)) {
                                Text(mode.title, color = white, fontSize = 14.sp,
                                    fontWeight = if (selected) FontWeight.Bold else FontWeight.Medium)
                                Text(mode.subtitle, color = muted, fontSize = 11.sp)
                                if (selected && mode.limitation.isNotBlank()) {
                                    Text(mode.limitation, color = amber, fontSize = 10.sp,
                                        lineHeight = 14.sp)
                                }
                            }
                            if (!mode.available) {
                                Text("SOON", color = amber, fontSize = 10.sp,
                                    fontWeight = FontWeight.SemiBold)
                            } else if (mode.id == "aether") {
                                Text(if (selected && upstream.isNotBlank()) "CONFIGURED" else "EXTERNAL",
                                    color = amber, fontSize = 10.sp)
                            } else if (selected) {
                                Text("LOCAL", color = accent, fontSize = 10.sp)
                            }
                        }
                    }
                }
            }
        }

        Surface(color = surface, shape = RoundedCornerShape(20.dp)) {
            Column(
                Modifier.fillMaxWidth().padding(17.dp),
                verticalArrangement = Arrangement.spacedBy(9.dp)
            ) {
                Text("OPTIONAL UPSTREAM SOCKS5", color = accent, fontWeight = FontWeight.Bold,
                    fontSize = 11.sp, letterSpacing = 1.sp)
                Text(
                    if (activeMode.id == "aether")
                        "Use the desktop core's optional local SOCKS5 exit. Managed Aether transports are not yet ported."
                    else
                        "Balanced and Fast can use a separately running, verified local SOCKS5 exit.",
                    color = muted, fontSize = 12.sp
                )
                if (activeMode.available) OutlinedTextField(
                    value = upstream,
                    onValueChange = onUpstream,
                    enabled = !running,
                    singleLine = true,
                    label = { Text("Local address (e.g. 127.0.0.1:9050)") },
                    modifier = Modifier.fillMaxWidth(),
                    colors = OutlinedTextFieldDefaults.colors(
                        focusedBorderColor = accent, unfocusedBorderColor = edge,
                        focusedTextColor = white, unfocusedTextColor = white
                    )
                )
                Text("Only the existing Go core performs exit verification. A listening local port alone does not prove Internet access.",
                    color = muted, fontSize = 11.sp)
                if (running && status.optString("exit_location").isNotEmpty()) {
                    Text("Observed exit region: ${status.optString("exit_location")}",
                        color = accent, fontSize = 12.sp)
                }
            }
        }

        Surface(color = Color(0xFF1A2832), shape = RoundedCornerShape(19.dp)) {
            Column(Modifier.fillMaxWidth().padding(17.dp),
                verticalArrangement = Arrangement.spacedBy(7.dp)) {
                Text("COVERAGE", color = accent, fontSize = 11.sp,
                    letterSpacing = 1.4.sp, fontWeight = FontWeight.Bold)
                Text("Proxy apps only", color = white, fontWeight = FontWeight.SemiBold,
                    fontSize = 16.sp)
                Text("Set the app to use the local SOCKS5 or HTTP endpoint. Other apps are not tunneled. TUN/VPN mode is under development.",
                    color = muted, fontSize = 12.sp, lineHeight = 18.sp)
                Text("Protected hostnames require a verified foreign exit. Raw IP destinations and unknown subdomains are not identity-safe.",
                    color = amber, fontSize = 11.sp, lineHeight = 16.sp)
            }
        }
        if (error != null) {
            Surface(color = Color(0xFF37262B), shape = RoundedCornerShape(14.dp)) {
                Text(error, color = red, modifier = Modifier.fillMaxWidth().padding(14.dp),
                    fontSize = 12.sp)
            }
        }
    }
}

@Composable
private fun PowerOrb(enabled: Boolean, active: Boolean, onClick: () -> Unit) {
    // Do not keep an infinite animation alive while disconnected.
    val pulse = if (active) {
        val transition = rememberInfiniteTransition(label = "power")
        val value by transition.animateFloat(
            initialValue = 0f, targetValue = 1f,
            animationSpec = infiniteRepeatable(
                animation = tween(2200, easing = FastOutSlowInEasing),
                repeatMode = RepeatMode.Reverse
            ), label = "pulse"
        )
        value
    } else 0f
    val color = when {
        active -> accent
        enabled -> white
        else -> muted
    }
    Box(
        modifier = Modifier.size(205.dp)
            .semantics { contentDescription = if (active) "Disconnect proxy" else "Connect proxy" }
            .clip(CircleShape)
            .clickable(enabled = enabled, onClick = onClick),
        contentAlignment = Alignment.Center
    ) {
        Canvas(Modifier.fillMaxSize()) {
            val radius = size.minDimension / 2
            drawCircle(
                color = if (active) accent.copy(alpha = .07f + pulse * .09f)
                    else Color(0xFF253740),
                radius = radius * (if (active) .97f + pulse * .03f else .93f)
            )
            drawCircle(color = if (active) accent.copy(alpha = .26f) else edge,
                radius = radius * .80f, style = Stroke(width = 1.5.dp.toPx()))
            val ringR = radius * .65f
            drawArc(
                color = color, startAngle = -60f, sweepAngle = 300f, useCenter = false,
                topLeft = Offset(center.x - ringR, center.y - ringR),
                size = Size(ringR * 2f, ringR * 2f),
                style = Stroke(width = 10.dp.toPx(), cap = StrokeCap.Round)
            )
            drawLine(color, Offset(center.x, center.y - radius * .83f),
                Offset(center.x, center.y + radius * .06f),
                strokeWidth = 10.dp.toPx(), cap = StrokeCap.Round)
        }
    }
}

@Composable
private fun ToolsScreen(
    target: String, onTarget: (String) -> Unit, busy: Boolean,
    report: JSONObject?, error: String?, runTest: () -> Unit,
    frontUrl: String, frontSni: String, frontHost: String, frontEdge: String,
    setFrontUrl: (String) -> Unit, setFrontSni: (String) -> Unit,
    setFrontHost: (String) -> Unit, setFrontEdge: (String) -> Unit,
    frontBusy: Boolean, frontReport: JSONObject?, runFront: () -> Unit,
    echBusy: Boolean, echReport: JSONObject?, runEch: () -> Unit
) {
    Column(verticalArrangement = Arrangement.spacedBy(17.dp)) {
        Text("Tools & diagnostics", fontSize = 25.sp, color = white,
            fontWeight = FontWeight.SemiBold)
        Text("Technical tools from the desktop client live here.",
            color = muted, fontSize = 13.sp)
        Surface(color = surface, shape = RoundedCornerShape(23.dp)) {
            Column(Modifier.padding(18.dp), verticalArrangement = Arrangement.spacedBy(13.dp)) {
                Text("NETWORK DIAGNOSIS", color = accent, fontSize = 11.sp, letterSpacing = 1.4.sp)
                Text("Check DNS, TCP and TLS independently.", color = muted, fontSize = 12.sp)
                OutlinedTextField(
                    value = target, onValueChange = onTarget, modifier = Modifier.fillMaxWidth(),
                    singleLine = true, label = { Text("Destination URL") },
                    keyboardOptions = KeyboardOptions(keyboardType = androidx.compose.ui.text.input.KeyboardType.Uri),
                    colors = OutlinedTextFieldDefaults.colors(
                        focusedBorderColor = accent, unfocusedBorderColor = edge,
                        focusedTextColor = white, unfocusedTextColor = white
                    )
                )
                Button(onClick = runTest, enabled = !busy && target.isNotBlank(),
                    modifier = Modifier.fillMaxWidth(),
                    colors = ButtonDefaults.buttonColors(containerColor = accent, contentColor = background)) {
                    Text(if (busy) "Testing…" else "Run diagnosis")
                }
                if (report != null) {
                    listOf("dns_status" to "DNS", "tcp_status" to "TCP", "tls_status" to "TLS").forEach {
                        val state = report.optString(it.first)
                        Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
                            Text(it.second, color = muted)
                            Text(state.uppercase(), color = if (state == "ok") accent else amber)
                        }
                    }
                    Text("Outcome: ${report.optString("outcome", "Unknown")}", color = white)
                    Text("Total: ${report.optLong("total_duration_ms")} ms",
                        color = muted, fontSize = 12.sp)
                }
                if (error != null) Text(error, color = red, fontSize = 12.sp)
                Text("Diagnostics use Android's default network. Success does not prove a VPN connection.",
                    color = muted, fontSize = 11.sp)
            }
        }
        Surface(color = surface, shape = RoundedCornerShape(23.dp)) {
            Column(Modifier.padding(18.dp), verticalArrangement = Arrangement.spacedBy(10.dp)) {
                Text("CDN FRONTING TEST", color = accent, fontSize = 11.sp, letterSpacing = 1.5.sp)
                Text("Use an authorized edge. TLS or HTTP success alone does not prove origin routing.",
                    color = muted, fontSize = 12.sp)
                OutlinedTextField(value = frontUrl, onValueChange = setFrontUrl,
                    label = { Text("HTTPS URL") }, modifier = Modifier.fillMaxWidth(), singleLine = true)
                OutlinedTextField(value = frontSni, onValueChange = setFrontSni,
                    label = { Text("TLS SNI / certificate name") }, modifier = Modifier.fillMaxWidth(), singleLine = true)
                OutlinedTextField(value = frontHost, onValueChange = setFrontHost,
                    label = { Text("HTTP Host") }, modifier = Modifier.fillMaxWidth(), singleLine = true)
                OutlinedTextField(value = frontEdge, onValueChange = setFrontEdge,
                    label = { Text("Edge IP address") }, modifier = Modifier.fillMaxWidth(), singleLine = true)
                Button(onClick = runFront, enabled = !frontBusy && frontEdge.isNotBlank(),
                    colors = ButtonDefaults.buttonColors(containerColor = accent, contentColor = background)) {
                    Text(if (frontBusy) "Testing…" else "Test fronting route")
                }
                if (frontReport != null) {
                    val candidates = frontReport.optJSONArray("candidates")
                    val first = if (candidates != null && candidates.length() > 0)
                        candidates.optJSONObject(0) else null
                    Text("Assessment: ${first?.optString("assessment") ?: "Unknown"}",
                        color = amber, fontSize = 13.sp)
                    Text("Origin verified: ${first?.optInt("origin_verified") ?: 0}",
                        color = muted, fontSize = 12.sp)
                }
                HorizontalDivider(color = edge)
                Text("ECH BOOTSTRAP", color = accent, fontSize = 11.sp, letterSpacing = 1.5.sp)
                Text("Check if Cloudflare returns a fresh ECH configuration. No tunnel is opened.",
                    color = muted, fontSize = 12.sp)
                Button(onClick = runEch, enabled = !echBusy,
                    colors = ButtonDefaults.buttonColors(containerColor = edge, contentColor = white)) {
                    Text(if (echBusy) "Checking ECH…" else "Test ECH configuration")
                }
                if (echReport != null) {
                    Text("ECH config from ${echReport.optString("edge")}",
                        color = accent, fontSize = 12.sp)
                    Text(echReport.optString("note"), color = muted, fontSize = 11.sp)
                }
            }
        }
        Surface(color = surface, shape = RoundedCornerShape(23.dp)) {
            Column(Modifier.padding(18.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
                Text("MORE DESKTOP TOOLS", color = accent, fontSize = 11.sp, letterSpacing = 1.4.sp)
                for (entry in listOf(
                    "Aether comparison" to "Requires Android-compatible Aether core",
                    "Windscribe tests" to "Requires Windscribe integration",
                    "CDN / fronting tests" to "Available above with controlled origin checks",
                    "Saved recommendations" to "Requires per-network measurements"
                )) {
                    Column {
                        Text(entry.first, color = white, fontWeight = FontWeight.Medium)
                        Text(entry.second, color = muted, fontSize = 11.sp)
                    }
                    HorizontalDivider(color = edge)
                }
            }
        }
    }
}

@Composable
private fun SettingsScreen(
    checking: Boolean, update: UpdateInfo?, check: () -> Unit,
    openDownload: (String) -> Unit
) {
    Column(verticalArrangement = Arrangement.spacedBy(18.dp)) {
        Text("Settings", fontSize = 25.sp, color = white, fontWeight = FontWeight.SemiBold)
        Surface(color = surface, shape = RoundedCornerShape(23.dp)) {
            Column(Modifier.fillMaxWidth().padding(19.dp),
                verticalArrangement = Arrangement.spacedBy(12.dp)) {
                Text("APP UPDATES", color = accent, fontSize = 11.sp, letterSpacing = 1.5.sp)
                Text("KTest Connection · ${BuildConfig.VERSION_NAME}", color = white,
                    fontSize = 17.sp, fontWeight = FontWeight.SemiBold)
                Text("Check signed releases manually. No background downloads or silent installs.",
                    color = muted, fontSize = 12.sp)
                Button(onClick = check, enabled = !checking,
                    colors = ButtonDefaults.buttonColors(containerColor = accent, contentColor = background)) {
                    Text(if (checking) "Checking…" else "Check for updates")
                }
                if (update != null) {
                    Text(update.message, color = white, fontSize = 12.sp)
                    if (update.downloadUrl != null) {
                        TextButton(onClick = { openDownload(update.downloadUrl) }) {
                            Text("Open official download", color = accent)
                        }
                    }
                }
            }
        }
        Surface(color = surface, shape = RoundedCornerShape(23.dp)) {
            Column(Modifier.padding(19.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
                Text("ENGINE & PRIVACY", color = accent, fontSize = 11.sp, letterSpacing = 1.5.sp)
                Text("Go local proxy core", color = white, fontWeight = FontWeight.SemiBold)
                Text("The Android UI calls the existing Go core through gomobile. Unsupported desktop transports remain disabled until their original Go launchers are portable.",
                    color = muted, fontSize = 12.sp)
                HorizontalDivider(color = edge)
                Text("System-wide coverage", color = white, fontWeight = FontWeight.SemiBold)
                Text("The existing CLI is proxy-first. Android VPN coverage needs a platform adapter once the Go core can drive it safely.",
                    color = muted, fontSize = 12.sp)
                HorizontalDivider(color = edge)
                Text("MITM and certificates", color = white, fontWeight = FontWeight.SemiBold)
                Text("The optional domain-fronting CA code is preserved in the Go repository. No certificate is installed by this app.",
                    color = muted, fontSize = 12.sp)
            }
        }
    }
}
