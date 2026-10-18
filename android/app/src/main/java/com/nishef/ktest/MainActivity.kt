package com.nishef.ktest

import android.Manifest
import android.app.Activity
import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.graphics.Color as AndroidColor
import android.net.Uri
import android.net.VpnService
import android.os.Build
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.SystemBarStyle
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.animation.AnimatedContent
import androidx.compose.animation.animateColorAsState
import androidx.compose.animation.core.tween
import androidx.compose.animation.fadeIn
import androidx.compose.animation.fadeOut
import androidx.compose.animation.togetherWith
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Icon
import androidx.compose.material3.Text
import androidx.compose.runtime.*
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.core.content.ContextCompat
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import mobilebridge.Mobilebridge
import org.json.JSONObject

class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        enableEdgeToEdge(
            statusBarStyle = SystemBarStyle.dark(AndroidColor.TRANSPARENT),
            navigationBarStyle = SystemBarStyle.dark(AndroidColor.TRANSPARENT)
        )
        super.onCreate(savedInstanceState)
        setContent { KTheme { KTestApp() } }
    }
}

private val connectingPhases = setOf("preparing", "starting_core", "verifying_upstream", "calibrating")

@Composable
private fun KTestApp() {
    val context = LocalContext.current
    val privateDir = remember(context) { context.filesDir.canonicalPath }
    val prefs = remember { context.getSharedPreferences("ktest_android", Context.MODE_PRIVATE) }
    val scope = rememberCoroutineScope()
    var tab by rememberSaveable { mutableIntStateOf(0) }
    val scrolls = listOf(rememberScrollState(), rememberScrollState(), rememberScrollState())
    var modeId by rememberSaveable { mutableStateOf(prefs.getString("mode", "balanced") ?: "balanced") }
    var upstream by remember { mutableStateOf(prefs.getString("upstream_$modeId", "") ?: "") }
    var nativeMethod by remember { mutableStateOf(prefs.getString("method_$modeId", "auto") ?: "auto") }
    var status by remember { mutableStateOf(JSONObject(Mobilebridge.proxyStatus())) }
    var vpnCapability by remember { mutableStateOf(JSONObject(Mobilebridge.vpnCapability())) }
    var connecting by remember { mutableStateOf(false) }
    var checkingRoute by remember { mutableStateOf(false) }
    var routeReport by remember { mutableStateOf<JSONObject?>(null) }
    var error by remember { mutableStateOf<String?>(null) }
    var coverage by rememberSaveable { mutableStateOf(prefs.getString("coverage", "vpn") ?: "vpn") }
    var vpnState by remember { mutableStateOf(KTestVpnService.state) }
    var connectAfterConsent by remember { mutableStateOf(false) }
    val tools = remember { ToolsState() }
    val settings = remember { SettingsState() }
    val routePlan = remember { RoutePlanState() }
    val routeTargets = remember { RouteTargetsState() }
    val running = status.optBoolean("running")
    val activeMode = modes.firstOrNull { it.id == modeId } ?: modes.first()
    val manualTesting = routePlan.manualBusy
    val offline = !running && !connecting && !connectAfterConsent && !routePlan.busy &&
        vpnState != "preparing" && vpnState != "tun_running_unverified"
    val routeStatusReady = routePlan.report != null && routePlan.readError == null
    val scanBusy = tools.cdnStarting || tools.cdnStatus.optBoolean("running")
    val scanStatusReady = tools.cdnStatusLoaded && tools.cdnStatusError == null
    // Failure to read a diagnostic status must not make Fast unusable.
    // Go independently checks whether an active scan is incompatible with startup.
    val connectBlocked = (activeMode.id == "balanced" && (routePlan.busy || !routeStatusReady)) ||
        routeTargets.busy || scanBusy
    val canTestRoutes = offline && routeStatusReady && !routeTargets.busy && !settings.caBusy &&
        !scanBusy && scanStatusReady && activeMode.id == "balanced"
    val linkState = when {
        running -> LinkState.Active
        (connecting || connectAfterConsent) && !manualTesting -> LinkState.Connecting
        !activeMode.available -> LinkState.Unavailable
        else -> LinkState.Idle
    }

    val notificationConsent = rememberLauncherForActivityResult(
        ActivityResultContracts.RequestPermission()
    ) { /* Connection continues if notifications are declined. */ }
    val startVpn: () -> Unit = {
        try {
            ContextCompat.startForegroundService(context, Intent(context, KTestVpnService::class.java).apply {
                action = KTestVpnService.ACTION_START
            })
        } catch (e: Exception) {
            error = e.message ?: "Unable to start the Android VPN adapter"
        }
    }
    val launchConnect: () -> Unit = connect@{
        if (connectBlocked) {
            error = "Stop any CDN scan, finish the manual test or target update, and wait for status before connecting."
            return@connect
        }
        if (Build.VERSION.SDK_INT >= 33 &&
            ContextCompat.checkSelfPermission(context, Manifest.permission.POST_NOTIFICATIONS)
            != PackageManager.PERMISSION_GRANTED) {
            notificationConsent.launch(Manifest.permission.POST_NOTIFICATIONS)
        }
        connecting = true
        routeReport = null
        ProxyService.lastError = null
        try {
            ContextCompat.startForegroundService(context,
                Intent(context, ProxyService::class.java).apply {
                    action = ProxyService.ACTION_CONNECT
                    putExtra(ProxyService.EXTRA_MODE, activeMode.id)
                    putExtra(ProxyService.EXTRA_TITLE, activeMode.title)
                    putExtra(ProxyService.EXTRA_UPSTREAM, upstream.trim())
                    putExtra(ProxyService.EXTRA_METHOD, nativeMethod)
                    putExtra(ProxyService.EXTRA_VPN, coverage == "vpn")
                })
        } catch (e: Exception) {
            error = e.message ?: "Unable to start the connection"
            connecting = false
        }
    }
    val vpnConsent = rememberLauncherForActivityResult(
        ActivityResultContracts.StartActivityForResult()
    ) { result ->
        val resume = connectAfterConsent
        connectAfterConsent = false
        if (result.resultCode == Activity.RESULT_OK) { if (resume) launchConnect() else startVpn() }
        else error = "Android VPN permission was not granted. Choose \"Proxy apps only\" to connect without a VPN."
    }
    val copy: (String) -> Unit = { text ->
        (context.getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager)
            .setPrimaryClip(ClipData.newPlainText("KTest", text))
    }
    val openUrl: (String) -> Unit = { url ->
        runCatching { context.startActivity(Intent(Intent.ACTION_VIEW, Uri.parse(url))) }
    }

    LaunchedEffect(Unit) {
        while (isActive) {
            status = runCatching { withContext(Dispatchers.IO) { JSONObject(Mobilebridge.proxyStatus()) } }
                .getOrElse { JSONObject() }
            vpnCapability = runCatching { withContext(Dispatchers.IO) { JSONObject(Mobilebridge.vpnCapability()) } }
                .getOrElse { JSONObject() }
            try {
                val routeMode = "balanced"
                routePlan.report = withContext(Dispatchers.IO) { JSONObject(Mobilebridge.routeTestStatus(privateDir, routeMode)) }
                routePlan.readError = null
            } catch (e: CancellationException) {
                throw e
            } catch (e: Exception) {
                routePlan.readError = e.message ?: "Could not read saved route observations"
            }
            try {
                tools.cdnStatus = withContext(Dispatchers.IO) { JSONObject(Mobilebridge.cdnScanStatus()) }
                tools.cdnStatusLoaded = true
                tools.cdnStatusError = null
            } catch (e: CancellationException) {
                throw e
            } catch (e: Exception) {
                tools.cdnStatusError = e.message ?: "Could not read CDN scan status"
            }
            connecting = status.optString("phase") in connectingPhases && !routePlan.manualBusy
            if (status.optString("phase") == "failed" && !routePlan.manualBusy) {
                connecting = false
                error = status.optString("error")
            }
            if (ProxyService.lastError != null) error = ProxyService.lastError
            vpnState = KTestVpnService.state
            if (vpnState == "failed" && KTestVpnService.lastError != null && running) error = "VPN: ${KTestVpnService.lastError}"
            delay(900)
        }
    }
    LaunchedEffect(status.optString("phase")) {
        if (status.optString("phase") == "failed" && tab == 0) scrolls[0].animateScrollTo(0)
        if (!running) routeReport = null
    }

    Box(Modifier.fillMaxSize().background(K.bg)) {
        // Soft accent glow behind the header; tinted by connection state.
        val glow by animateColorAsState(
            when (linkState) { LinkState.Active -> K.mint; LinkState.Connecting -> K.cyan; else -> K.bgGlow },
            tween(800), label = "glow"
        )
        Box(Modifier.fillMaxWidth().height(420.dp).background(
            Brush.verticalGradient(listOf(glow.copy(alpha = if (linkState == LinkState.Active || linkState == LinkState.Connecting) .14f else .9f), Color.Transparent))
        ))
        Column(Modifier.fillMaxSize().windowInsetsPadding(WindowInsets.safeDrawing.only(WindowInsetsSides.Horizontal + WindowInsetsSides.Top))) {
            Header(linkState)
            AnimatedContent(tab, Modifier.weight(1f).imePadding(), label = "tab",
                transitionSpec = { fadeIn(tween(220)) togetherWith fadeOut(tween(150)) }) { page ->
                Column(
                    Modifier.fillMaxSize().verticalScroll(scrolls[page])
                        .padding(horizontal = 20.dp).padding(top = 8.dp, bottom = 120.dp)
                ) {
                    when (page) {
                        0 -> ConnectScreen(
                            activeMode = activeMode, state = linkState, status = status,
                            upstream = upstream,
                            onUpstream = { upstream = it; prefs.edit().putString("upstream_$modeId", it).apply() },
                            nativeMethod = nativeMethod,
                            onNativeMethod = { nativeMethod = it; prefs.edit().putString("method_$modeId", it).apply() },
                            error = error, onDismissError = { error = null; ProxyService.lastError = null },
                            routePlan = routePlan, connectBlocked = connectBlocked, scanBusy = scanBusy,
                            canTestRoutes = canTestRoutes,
                            onTestRoutes = {
                                if (canTestRoutes) {
                                    routePlan.starting = true
                                    routePlan.error = null
                                    val mode = activeMode.id
                                    val testUpstream = upstream.trim()
                                    scope.launch {
                                        try {
                                            routePlan.report = withContext(Dispatchers.IO) {
                                                val fronting = ProxyService.checkedFrontingOptIn(context, privateDir)
                                                ProxyService.prepareBalancedNetwork(context)
                                                Mobilebridge.startRouteTest(mode, testUpstream,
                                                    context.applicationInfo.nativeLibraryDir, privateDir, fronting)
                                                JSONObject(Mobilebridge.routeTestStatus(privateDir, mode))
                                            }
                                            routePlan.readError = null
                                        } catch (e: CancellationException) {
                                            throw e
                                        } catch (e: Exception) {
                                            routePlan.error = e.message ?: "Could not start manual route test"
                                        } finally {
                                            routePlan.starting = false
                                        }
                                    }
                                }
                            },
                            onCancelRouteTest = {
                                if (routePlan.manualBusy && !routePlan.starting && !routePlan.canceling) {
                                    routePlan.canceling = true
                                    scope.launch {
                                        try { withContext(Dispatchers.IO) { Mobilebridge.cancelRouteTest() } }
                                        catch (e: CancellationException) { throw e }
                                        catch (e: Exception) { routePlan.error = e.message ?: "Could not cancel manual route test" }
                                        finally { routePlan.canceling = false }
                                    }
                                }
                            },
                            routeReport = routeReport, checkingRoute = checkingRoute,
                            onCheckRoute = {
                                if (running && !status.optBoolean("frozen") && !checkingRoute && !routePlan.busy) {
                                    checkingRoute = true
                                    routeReport = null
                                    scope.launch {
                                        try {
                                            routeReport = withContext(Dispatchers.IO) { JSONObject(Mobilebridge.checkRoute()) }
                                        } catch (e: CancellationException) {
                                            throw e
                                        } catch (e: Exception) {
                                            error = e.message ?: "Route check failed"
                                        } finally {
                                            checkingRoute = false
                                        }
                                    }
                                }
                            },
                            onMode = {
                                if (offline && !routeTargets.busy) {
                                    modeId = it
                                    upstream = prefs.getString("upstream_$it", "") ?: ""
                                    nativeMethod = prefs.getString("method_$it", "auto") ?: "auto"
                                    prefs.edit().putString("mode", it).apply()
                                    error = null
                                    ProxyService.lastError = null
                                }
                            },
                            coverage = coverage, vpnActive = vpnState == "tun_running_unverified",
                            onCoverage = { coverage = it; prefs.edit().putString("coverage", it).apply() },
                            onPower = {
                                error = null
                                if (running || (connecting && !routePlan.manualBusy)) {
                                    context.startService(Intent(context, ProxyService::class.java).apply {
                                        action = ProxyService.ACTION_STOP
                                    })
                                    connecting = false
                                } else if (activeMode.available && !connectBlocked) {
                                    val consent = if (coverage == "vpn") VpnService.prepare(context) else null
                                    if (consent != null) {
                                        connectAfterConsent = true
                                        vpnConsent.launch(consent)
                                    } else launchConnect()
                                }
                            },
                            onCopy = copy
                        )
                        1 -> ToolsScreen(tools, scope, copy, scanAllowed = offline && routeStatusReady && !routeTargets.busy)
                        else -> SettingsScreen(
                            s = settings, scope = scope,
                            routeTargets = routeTargets, targetsEditable = offline,
                            manualTesting = manualTesting,
                            onTargetsChanged = {
                                routePlan.changedProfileAt = routePlan.report?.optJSONObject("profile")?.optString("completed_at").orEmpty()
                            },
                            nativeLibraryDir = context.applicationInfo.nativeLibraryDir,
                            vpn = vpnCapability, vpnServiceState = KTestVpnService.state,
                            vpnError = KTestVpnService.lastError,
                            onVpnAction = {
                                if (KTestVpnService.state == "tun_running_unverified") {
                                    context.startService(Intent(context, KTestVpnService::class.java).apply {
                                        action = KTestVpnService.ACTION_STOP
                                    })
                                } else if (vpnCapability.optBoolean("available") && !manualTesting) {
                                    val consent = VpnService.prepare(context)
                                    if (consent == null) startVpn() else vpnConsent.launch(consent)
                                }
                            },
                            openUrl = openUrl
                        )
                    }
                }
            }
        }
        Box(Modifier.align(Alignment.BottomCenter).fillMaxWidth()
            .background(Brush.verticalGradient(0f to Color.Transparent, .3f to K.bg.copy(alpha = .94f), 1f to K.bg))) {
            BottomNav(tab, { tab = it }, Modifier.padding(top = 18.dp))
        }
    }
}

@Composable
private fun Header(state: LinkState) {
    Row(
        Modifier.fillMaxWidth().padding(horizontal = 20.dp, vertical = 14.dp),
        verticalAlignment = Alignment.CenterVertically
    ) {
        AppMark(34.dp)
        Spacer(Modifier.width(11.dp))
        Column(Modifier.weight(1f)) {
            Text("KTest", color = K.text, fontSize = 19.sp, fontWeight = FontWeight.Bold, letterSpacing = 0.2.sp)
            Text("CONNECTION", color = K.muted, fontSize = 9.sp, letterSpacing = 2.4.sp, fontWeight = FontWeight.Medium)
        }
        when (state) {
            LinkState.Active -> StatusPill("Connected", K.mint)
            LinkState.Connecting -> StatusPill("Connecting", K.cyan)
            LinkState.Unavailable -> StatusPill("Unavailable", K.amber)
            LinkState.Idle -> StatusPill("Offline", K.muted)
        }
    }
}

@Composable
private fun BottomNav(selected: Int, onSelect: (Int) -> Unit, modifier: Modifier) {
    val shape = RoundedCornerShape(26.dp)
    Row(
        modifier.windowInsetsPadding(WindowInsets.safeDrawing.only(WindowInsetsSides.Bottom + WindowInsetsSides.Horizontal))
            .padding(horizontal = 20.dp, vertical = 12.dp).fillMaxWidth()
            .clip(shape).background(K.surface).border(1.dp, K.stroke, shape).padding(6.dp),
        horizontalArrangement = Arrangement.spacedBy(6.dp)
    ) {
        for ((index, item) in listOf("Connect" to KIcons.Power, "Tools" to KIcons.Wrench, "Settings" to KIcons.Settings).withIndex()) {
            val active = index == selected
            val bg by animateColorAsState(if (active) K.mint.copy(alpha = .12f) else Color.Transparent, label = "nav")
            val fg by animateColorAsState(if (active) K.mint else K.muted, label = "navFg")
            Row(
                Modifier.weight(1f).height(50.dp).clip(RoundedCornerShape(20.dp)).background(bg)
                    .clickable(role = Role.Tab) { onSelect(index) },
                horizontalArrangement = Arrangement.Center, verticalAlignment = Alignment.CenterVertically
            ) {
                Icon(item.second, if (active) null else item.first, tint = fg, modifier = Modifier.size(20.dp))
                if (active) {
                    Spacer(Modifier.width(8.dp))
                    Text(item.first, color = fg, fontSize = 13.sp, fontWeight = FontWeight.SemiBold)
                }
            }
        }
    }
}
