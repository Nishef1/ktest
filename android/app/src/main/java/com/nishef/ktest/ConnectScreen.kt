package com.nishef.ktest

import androidx.compose.animation.AnimatedVisibility
import androidx.compose.animation.animateColorAsState
import androidx.compose.animation.core.*
import androidx.compose.animation.expandVertically
import androidx.compose.animation.fadeIn
import androidx.compose.animation.fadeOut
import androidx.compose.animation.shrinkVertically
import androidx.compose.foundation.Canvas
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.draw.rotate
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.geometry.Size
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.StrokeCap
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.graphics.drawscope.rotate
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import kotlinx.coroutines.delay
import mobilebridge.Mobilebridge
import org.json.JSONObject

internal data class ConnectionMode(
    val id: String, val title: String, val subtitle: String, val available: Boolean,
    val limitation: String
)

internal val nativeModes = setOf("aether", "tor", "psiphon")

// The Go catalog is the canonical description of the current CLI modes.
// Android does not silently rebrand Psiphon or Tor as unrelated transports.
internal val modes: List<ConnectionMode> by lazy {
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

internal enum class LinkState { Idle, Connecting, Active, Unavailable }

@Composable
internal fun ConnectScreen(
    activeMode: ConnectionMode, state: LinkState, status: JSONObject,
    upstream: String, onUpstream: (String) -> Unit,
    nativeMethod: String, onNativeMethod: (String) -> Unit,
    error: String?, onDismissError: () -> Unit,
    routeReport: JSONObject?, checkingRoute: Boolean, onCheckRoute: () -> Unit,
    onMode: (String) -> Unit, onPower: () -> Unit, onCopy: (String) -> Unit
) {
    val locked = state == LinkState.Active || state == LinkState.Connecting
    Column(verticalArrangement = Arrangement.spacedBy(16.dp)) {
        Hero(activeMode, state, status, upstream, onPower)
        AnimatedVisibility(error != null, enter = fadeIn() + expandVertically(), exit = fadeOut() + shrinkVertically()) {
            Banner(error.orEmpty(), Tone.Danger, onDismissError)
        }
        if (state == LinkState.Active) {
            EndpointsPanel(status, routeReport, checkingRoute, onCheckRoute, onCopy)
        }
        ModeCard(activeMode, !locked, onMode)
        if (activeMode.id in nativeModes) {
            NativeMethodPanel(activeMode.id, nativeMethod, onNativeMethod, !locked)
        }
        if (activeMode.available && activeMode.id in listOf("balanced", "fast", "aether")) {
            UpstreamPanel(activeMode.id, upstream, onUpstream, !locked)
        }
        UsagePanel()
    }
}

@Composable
private fun Hero(mode: ConnectionMode, state: LinkState, status: JSONObject, upstream: String, onPower: () -> Unit) {
    val phase = status.optString("phase")
    Column(Modifier.fillMaxWidth().padding(top = 4.dp), horizontalAlignment = Alignment.CenterHorizontally) {
        PowerOrb(state, onPower)
        Spacer(Modifier.height(14.dp))
        Text(
            when (state) {
                LinkState.Active -> "Connected"
                LinkState.Connecting -> "Connecting…"
                LinkState.Unavailable -> "Not available yet"
                LinkState.Idle -> "Tap to connect"
            },
            color = K.text, fontSize = 26.sp, fontWeight = FontWeight.SemiBold, letterSpacing = (-0.3).sp
        )
        Spacer(Modifier.height(6.dp))
        when (state) {
            LinkState.Active -> Uptime()
            LinkState.Connecting -> Text(
                when (phase) {
                    "starting_core" -> "Starting ${mode.title}…"
                    "verifying_upstream" -> "Waiting for a tunnel and a verified exit"
                    else -> "Preparing routes and listeners"
                }, color = K.muted, fontSize = 13.sp, textAlign = TextAlign.Center
            )
            LinkState.Unavailable -> Text(mode.limitation.ifBlank { "This desktop core has not been ported." },
                color = K.amber, fontSize = 13.sp, textAlign = TextAlign.Center,
                modifier = Modifier.padding(horizontal = 24.dp))
            LinkState.Idle -> Text(
                if (mode.id in nativeModes && (mode.id != "aether" || upstream.isBlank()))
                    "${mode.title} · packaged core · proxy apps only"
                else "${mode.title} · local SOCKS5 + HTTP proxy",
                color = K.muted, fontSize = 13.sp, textAlign = TextAlign.Center
            )
        }
        if (state == LinkState.Connecting) {
            val native = mode.id in nativeModes && (mode.id != "aether" || upstream.isBlank())
            val steps = buildList {
                add("preparing" to "Prepare")
                if (native) add("starting_core" to "Start core")
                if (native || upstream.isNotBlank()) add("verifying_upstream" to "Verify exit")
            }
            if (steps.size > 1) {
                Spacer(Modifier.height(16.dp))
                PhaseSteps(steps, phase)
            }
        }
        if (state == LinkState.Active) {
            Spacer(Modifier.height(12.dp))
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                Tag(mode.title, K.mint)
                status.optString("method").takeIf { it.isNotBlank() }?.let { Tag(it, K.cyan) }
                status.optString("exit_location").takeIf { it.isNotBlank() }?.let { Tag("Exit · $it", K.text) }
            }
        }
    }
}

@Composable
private fun Uptime() {
    var now by remember { mutableLongStateOf(android.os.SystemClock.elapsedRealtime()) }
    LaunchedEffect(Unit) {
        while (true) { now = android.os.SystemClock.elapsedRealtime(); delay(1000) }
    }
    val since = ProxyService.connectedAt
    Text(
        if (since > 0) formatDuration(((now - since) / 1000).coerceAtLeast(0)) else "Local proxy active",
        color = K.mint, fontSize = 15.sp, fontFamily = K.mono, fontWeight = FontWeight.Medium
    )
}

@Composable
private fun PhaseSteps(steps: List<Pair<String, String>>, phase: String) {
    val current = steps.indexOfFirst { it.first == phase }.coerceAtLeast(0)
    val pulse = rememberInfiniteTransition(label = "step").animateFloat(
        .35f, 1f, infiniteRepeatable(tween(700), RepeatMode.Reverse), label = "stepPulse"
    )
    Row(verticalAlignment = Alignment.CenterVertically, modifier = Modifier.padding(horizontal = 12.dp)) {
        steps.forEachIndexed { index, (_, label) ->
            val done = index < current
            val active = index == current
            Column(horizontalAlignment = Alignment.CenterHorizontally) {
                Box(
                    Modifier.size(22.dp).clip(CircleShape)
                        .background(when { done -> K.mint; active -> K.cyan.copy(alpha = .18f); else -> K.surfaceHigh })
                        .border(1.5.dp, when { done -> K.mint; active -> K.cyan.copy(alpha = pulse.value); else -> K.stroke }, CircleShape),
                    contentAlignment = Alignment.Center
                ) {
                    if (done) Icon(KIcons.Check, null, tint = K.bg, modifier = Modifier.size(14.dp))
                    else Text("${index + 1}", color = if (active) K.cyan else K.faint, fontSize = 11.sp,
                        fontWeight = FontWeight.Bold)
                }
                Spacer(Modifier.height(5.dp))
                Text(label, fontSize = 11.sp, color = when { done -> K.mint; active -> K.text; else -> K.faint })
            }
            if (index < steps.lastIndex) {
                Box(Modifier.padding(horizontal = 6.dp).padding(bottom = 18.dp).width(34.dp).height(2.dp)
                    .clip(CircleShape).background(if (done) K.mint else K.stroke))
            }
        }
    }
}

@Composable
private fun PowerOrb(state: LinkState, onClick: () -> Unit) {
    val active = state == LinkState.Active
    val busy = state == LinkState.Connecting
    val enabled = state != LinkState.Unavailable
    val iconColor by animateColorAsState(
        when (state) { LinkState.Active -> K.mint; LinkState.Connecting -> K.cyan; LinkState.Idle -> K.text; else -> K.faint },
        tween(400), label = "orbIcon"
    )
    // Do not keep an infinite animation alive while disconnected.
    val motion = if (active || busy) {
        val transition = rememberInfiniteTransition(label = "orb")
        transition.animateFloat(0f, 1f, infiniteRepeatable(
            tween(if (busy) 1300 else 2600, easing = LinearEasing)), label = "orbMotion").value
    } else 0f
    Box(
        Modifier.size(228.dp)
            .semantics { contentDescription = when (state) {
                LinkState.Active -> "Disconnect"; LinkState.Connecting -> "Cancel connection"
                LinkState.Unavailable -> "Mode unavailable"; LinkState.Idle -> "Connect"
            } }
            .clip(CircleShape)
            .clickable(enabled = enabled, role = Role.Button, onClick = onClick),
        contentAlignment = Alignment.Center
    ) {
        Canvas(Modifier.fillMaxSize()) {
            val r = size.minDimension / 2
            val glow = when (state) { LinkState.Active -> K.mint; LinkState.Connecting -> K.cyan; else -> K.strokeStrong }
            drawCircle(Brush.radialGradient(listOf(glow.copy(alpha = if (active || busy) .22f else .10f), Color.Transparent),
                center, r), r)
            if (active) for (k in 0..1) {
                val p = (motion + k * .5f) % 1f
                drawCircle(K.mint.copy(alpha = (1f - p) * .28f), r * (.66f + p * .32f), style = Stroke(1.5.dp.toPx()))
            }
            val ringR = r * .72f
            val ringTopLeft = Offset(center.x - ringR, center.y - ringR)
            val ringSize = Size(ringR * 2, ringR * 2)
            drawCircle(K.stroke, ringR, style = Stroke(6.dp.toPx()))
            when {
                active -> drawCircle(Brush.sweepGradient(listOf(K.mint, K.cyan, K.mint), center), ringR, style = Stroke(6.dp.toPx()))
                busy -> rotate(motion * 360f) {
                    drawArc(Brush.sweepGradient(listOf(Color.Transparent, K.cyan, K.mint), center),
                        0f, 300f, false, ringTopLeft, ringSize, style = Stroke(6.dp.toPx(), cap = StrokeCap.Round))
                }
            }
            drawCircle(Brush.radialGradient(listOf(K.surfaceHigh, K.surface), center.copy(y = center.y - r * .2f), r * .7f), r * .6f)
            drawCircle(if (active) K.mint.copy(alpha = .35f) else K.strokeStrong, r * .6f, style = Stroke(1.dp.toPx()))
        }
        Icon(KIcons.Power, null, tint = iconColor, modifier = Modifier.size(64.dp))
    }
}

@Composable
@OptIn(ExperimentalMaterial3Api::class)
private fun ModeCard(active: ConnectionMode, enabled: Boolean, onMode: (String) -> Unit) {
    var open by rememberSaveable { mutableStateOf(false) }
    Panel(onClick = if (enabled) ({ open = true }) else null) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            IconTile(KIcons.Shield, if (active.available) K.mint else K.amber)
            Spacer(Modifier.width(14.dp))
            Column(Modifier.weight(1f)) {
                Text("Connection mode", color = K.muted, fontSize = 12.sp)
                Text(active.title, color = K.text, fontSize = 17.sp, fontWeight = FontWeight.SemiBold)
                Text(active.subtitle, color = K.muted, fontSize = 12.sp, maxLines = 1, overflow = TextOverflow.Ellipsis)
            }
            if (enabled) Icon(KIcons.ChevronRight, "Change mode", tint = K.muted)
            else Icon(KIcons.Lock, "Locked while connected", tint = K.faint, modifier = Modifier.size(18.dp))
        }
    }
    if (open) ModalBottomSheet(
        onDismissRequest = { open = false },
        sheetState = rememberModalBottomSheetState(skipPartiallyExpanded = true),
        containerColor = K.surface, scrimColor = Color.Black.copy(alpha = .6f)
    ) {
        Column(
            Modifier.fillMaxWidth().heightIn(max = 620.dp).verticalScroll(rememberScrollState())
                .padding(horizontal = 18.dp).padding(bottom = 28.dp),
            verticalArrangement = Arrangement.spacedBy(8.dp)
        ) {
            Text("Connection mode", color = K.text, fontSize = 22.sp, fontWeight = FontWeight.SemiBold)
            Text("Each mode keeps the desktop client's routing policy.", color = K.muted, fontSize = 13.sp)
            Spacer(Modifier.height(6.dp))
            modes.forEach { mode ->
                val selected = mode.id == active.id
                val shape = RoundedCornerShape(18.dp)
                Row(
                    Modifier.fillMaxWidth().clip(shape)
                        .background(if (selected) K.mint.copy(alpha = .08f) else K.bg)
                        .border(1.dp, if (selected) K.mint.copy(alpha = .45f) else K.stroke, shape)
                        .clickable(enabled = mode.available, role = Role.RadioButton) { onMode(mode.id); open = false }
                        .padding(14.dp),
                    verticalAlignment = Alignment.Top
                ) {
                    Box(Modifier.padding(top = 2.dp).size(18.dp).clip(CircleShape)
                        .border(2.dp, if (selected) K.mint else if (mode.available) K.strokeStrong else K.stroke, CircleShape),
                        contentAlignment = Alignment.Center) {
                        if (selected) Box(Modifier.size(8.dp).background(K.mint, CircleShape))
                    }
                    Spacer(Modifier.width(12.dp))
                    Column(Modifier.weight(1f), verticalArrangement = Arrangement.spacedBy(3.dp)) {
                        Row(verticalAlignment = Alignment.CenterVertically) {
                            Text(mode.title, color = if (mode.available) K.text else K.muted, fontSize = 15.sp,
                                fontWeight = FontWeight.SemiBold, modifier = Modifier.weight(1f, fill = false))
                            if (!mode.available) { Spacer(Modifier.width(8.dp)); Tag("Coming later", K.amber) }
                        }
                        Text(mode.subtitle, color = K.muted, fontSize = 12.sp)
                        if (mode.limitation.isNotBlank() && (selected || !mode.available))
                            Text(mode.limitation, color = if (mode.available) K.faint else K.amber.copy(alpha = .8f),
                                fontSize = 11.sp, lineHeight = 15.sp)
                    }
                }
            }
        }
    }
}

@Composable
private fun NativeMethodPanel(mode: String, method: String, onMethod: (String) -> Unit, enabled: Boolean) {
    val choices = remember(mode) {
        runCatching {
            val catalog = JSONObject(Mobilebridge.aetherProfileCatalog(mode, "auto"))
            val methods = catalog.getJSONArray("methods")
            val defaultMethod = catalog.getJSONArray("profiles").getJSONObject(0).getString("method")
            (0 until methods.length()).map { i ->
                val item = methods.getJSONObject(i)
                item.getString("id") to if (item.getString("id") == "auto")
                    "Default · $defaultMethod" else item.getString("title")
            }
        }.getOrElse { emptyList() }
    }
    var expanded by remember { mutableStateOf(false) }
    Panel {
        Row(verticalAlignment = Alignment.CenterVertically) {
            IconTile(KIcons.Bolt, K.cyan)
            Spacer(Modifier.width(14.dp))
            Column(Modifier.weight(1f)) {
                Text("Connection method", color = K.muted, fontSize = 12.sp)
                Box {
                    Row(
                        Modifier.clip(RoundedCornerShape(8.dp))
                            .clickable(enabled = enabled && choices.size > 1) { expanded = true }
                            .padding(vertical = 2.dp),
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Text(choices.firstOrNull { it.first == method }?.second ?: "Default",
                            color = K.text, fontSize = 16.sp, fontWeight = FontWeight.SemiBold)
                        if (enabled && choices.size > 1) Icon(KIcons.ExpandMore, "Choose method", tint = K.cyan)
                    }
                    DropdownMenu(expanded = expanded, onDismissRequest = { expanded = false },
                        containerColor = K.surfaceHigh) {
                        choices.forEach { (id, title) ->
                            DropdownMenuItem(
                                text = { Text(title, color = if (id == method) K.mint else K.text) },
                                trailingIcon = { if (id == method) Icon(KIcons.Check, null, tint = K.mint) },
                                onClick = { onMethod(id); expanded = false })
                        }
                    }
                }
            }
        }
        Note("The packaged core finds gateways and reconnects by itself. If a method cannot connect, disconnect and try another. First-time setup can take several minutes.")
    }
}

@Composable
private fun UpstreamPanel(mode: String, upstream: String, onUpstream: (String) -> Unit, enabled: Boolean) {
    var open by rememberSaveable { mutableStateOf(upstream.isNotBlank()) }
    Panel {
        Row(Modifier.fillMaxWidth().clip(RoundedCornerShape(12.dp)).clickable { open = !open },
            verticalAlignment = Alignment.CenterVertically) {
            IconTile(KIcons.Route, K.muted)
            Spacer(Modifier.width(14.dp))
            Column(Modifier.weight(1f)) {
                Text("Upstream SOCKS5", color = K.text, fontSize = 15.sp, fontWeight = FontWeight.Medium)
                Text(if (upstream.isBlank()) "Optional · not set" else upstream, color = if (upstream.isBlank()) K.muted else K.cyan,
                    fontSize = 12.sp, fontFamily = if (upstream.isBlank()) null else K.mono)
            }
            Icon(KIcons.ExpandMore, null, tint = K.muted,
                modifier = Modifier.rotate(if (open) 180f else 0f))
        }
        AnimatedVisibility(open) {
            Column(verticalArrangement = Arrangement.spacedBy(10.dp)) {
                Text(
                    if (mode == "aether") "Leave empty to use the packaged Aether core. Enter an address only to use an existing local SOCKS5 exit instead."
                    else "Balanced and Fast can send protected traffic through a separately running local SOCKS5 exit.",
                    color = K.muted, fontSize = 12.sp, lineHeight = 17.sp
                )
                KField(upstream, onUpstream, "Local address, e.g. 127.0.0.1:9050", enabled = enabled, mono = true,
                    keyboardType = androidx.compose.ui.text.input.KeyboardType.Uri)
                Note("Only the Go core performs exit verification. A listening port alone does not prove Internet access.")
            }
        }
    }
}

@Composable
private fun EndpointsPanel(
    status: JSONObject, routeReport: JSONObject?, checking: Boolean,
    onCheckRoute: () -> Unit, onCopy: (String) -> Unit
) {
    Panel {
        SectionLabel("Local proxy")
        for ((label, key) in listOf("SOCKS5" to "socks", "HTTP" to "http")) {
            val address = status.optString(key)
            if (address.isNotBlank()) EndpointRow(label, address, onCopy)
        }
        if (status.optString("dns_error").isNotBlank()) {
            Note("Last DNS transport failure (${status.optInt("dns_failures")}): ${status.optString("dns_error")}", Tone.Warn)
        }
        SecondaryButton(if (checking) "Checking HTTPS routes…" else "Verify real HTTPS traffic", onCheckRoute,
            Modifier.fillMaxWidth(), busy = checking, icon = KIcons.Check)
        if (routeReport != null) {
            val ok = routeReport.optInt("verified")
            val attempted = routeReport.optInt("attempted")
            Row(verticalAlignment = Alignment.CenterVertically) {
                Text("$ok of $attempted targets reachable", color = if (ok > 0) K.mint else K.amber,
                    fontSize = 14.sp, fontWeight = FontWeight.SemiBold, modifier = Modifier.weight(1f))
            }
            val targets = routeReport.optJSONArray("targets")
            if (targets != null) for (i in 0 until targets.length()) {
                val t = targets.optJSONObject(i) ?: continue
                val skipped = t.optBoolean("Skipped")
                val success = t.optBoolean("Success")
                Row(verticalAlignment = Alignment.Top) {
                    Box(Modifier.padding(top = 6.dp).size(8.dp).background(when { skipped -> K.faint; success -> K.mint; else -> K.amber }, CircleShape))
                    Spacer(Modifier.width(10.dp))
                    Column(Modifier.weight(1f)) {
                        Text(t.optString("Target"), color = K.text, fontSize = 13.sp)
                        val detail = t.optString("Detail")
                        if (!success && detail.isNotBlank()) Text(detail, color = K.faint, fontSize = 11.sp,
                            maxLines = 2, overflow = TextOverflow.Ellipsis)
                    }
                    Text(when {
                        skipped -> "skipped"
                        else -> "${t.optLong("Took") / 1_000_000} ms"
                    }, color = K.muted, fontSize = 12.sp, fontFamily = K.mono)
                }
            }
            Note(routeReport.optString("note"))
        }
    }
}

@Composable
private fun EndpointRow(label: String, address: String, onCopy: (String) -> Unit) {
    var copied by remember { mutableStateOf(false) }
    LaunchedEffect(copied) { if (copied) { delay(1600); copied = false } }
    val shape = RoundedCornerShape(14.dp)
    Row(
        Modifier.fillMaxWidth().clip(shape).background(K.bg).border(1.dp, K.stroke, shape)
            .clickable { onCopy(address); copied = true }.padding(start = 14.dp, end = 6.dp, top = 6.dp, bottom = 6.dp),
        verticalAlignment = Alignment.CenterVertically
    ) {
        Text(label, color = K.muted, fontSize = 11.sp, fontWeight = FontWeight.Bold, letterSpacing = 1.sp,
            modifier = Modifier.width(62.dp))
        Text(address, color = K.text, fontSize = 15.sp, fontFamily = K.mono, modifier = Modifier.weight(1f))
        IconButton(onClick = { onCopy(address); copied = true }) {
            Icon(if (copied) KIcons.Check else KIcons.Copy, "Copy $label address",
                tint = if (copied) K.mint else K.muted, modifier = Modifier.size(18.dp))
        }
    }
}

@Composable
private fun UsagePanel() {
    Panel {
        Row(verticalAlignment = Alignment.CenterVertically) {
            IconTile(KIcons.Phone, K.muted)
            Spacer(Modifier.width(14.dp))
            Column {
                Text("Proxy apps only", color = K.text, fontSize = 15.sp, fontWeight = FontWeight.Medium)
                Text("Not a system-wide VPN", color = K.muted, fontSize = 12.sp)
            }
        }
        for ((n, step) in listOf(
            "Connect, then copy the SOCKS5 or HTTP address.",
            "In the app you want to use (for example Telegram or a browser with proxy support), add a SOCKS5 or HTTP proxy with that address.",
            "Other apps keep using your normal network."
        ).withIndex()) {
            Row(verticalAlignment = Alignment.Top) {
                Text("${n + 1}", color = K.mint, fontSize = 12.sp, fontWeight = FontWeight.Bold,
                    modifier = Modifier.width(20.dp))
                Text(step, color = K.muted, fontSize = 12.sp, lineHeight = 17.sp)
            }
        }
        Note("Protected hostnames require a verified foreign exit. Raw IP destinations and unknown subdomains are not identity-safe.", Tone.Warn)
    }
}
