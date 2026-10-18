package com.nishef.ktest

import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.Icon
import androidx.compose.material3.Text
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import mobilebridge.Mobilebridge
import org.json.JSONObject

internal class SettingsState {
    var checkingUpdates by mutableStateOf(false)
    var update by mutableStateOf<UpdateInfo?>(null)
    var bundleBusy by mutableStateOf(false)
    var bundle by mutableStateOf<JSONObject?>(null)
    var bundleError by mutableStateOf<String?>(null)
}

private data class Notice(val name: String, val detail: String, val license: String, val url: String)

// Distribution notices for the unmodified native executables shipped in the APK.
// Keep in sync with docs/THIRD_PARTY_NOTICES.md and internal/aether/android-cores.json.
private val notices = listOf(
    Notice("Aether v2.3.0", "CluvexStudio · MASQUE / WireGuard core with Tor (Arti)", "AGPL-3.0",
        "https://github.com/CluvexStudio/Aether/tree/v2.3.0"),
    Notice("psiphon-tunnel-core", "CluvexStudio fork, shirokhorshid @ 83aa73b", "GPL-3.0",
        "https://github.com/CluvexStudio/psiphon-tunnel-core/tree/83aa73b9b982e7421e00117f5b0c5aceb5dda452"),
    Notice("lyrebird", "Tor Project pluggable transports @ fc105a0", "BSD",
        "https://gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/lyrebird/-/tree/fc105a03c0e0acc2479301c361c012ffed359c43"),
    Notice("hev-socks5-tunnel 2.19.0", "heiher · Android TUN adapter (not active yet)", "MIT",
        "https://github.com/heiher/hev-socks5-tunnel"),
    Notice("KTest", "Go connection core and this app", "Source", "https://github.com/Nishef1/ktest")
)

@Composable
internal fun SettingsScreen(
    s: SettingsState, scope: CoroutineScope, nativeLibraryDir: String,
    vpn: JSONObject, vpnServiceState: String, vpnError: String?,
    onVpnAction: () -> Unit, openUrl: (String) -> Unit
) {
    Column(verticalArrangement = Arrangement.spacedBy(14.dp)) {
        ScreenTitle("Settings", "App, engine and privacy information.")
        Spacer(Modifier.height(4.dp))

        Panel {
            Row(verticalAlignment = Alignment.CenterVertically) {
                AppMark(48.dp)
                Spacer(Modifier.width(14.dp))
                Column(Modifier.weight(1f)) {
                    Text("KTest Connection", color = K.text, fontSize = 17.sp, fontWeight = FontWeight.SemiBold)
                    Text("Version ${BuildConfig.VERSION_NAME} · preview", color = K.muted, fontSize = 12.sp)
                }
            }
            Note("Updates are checked only when you ask. No background downloads or silent installs.")
            SecondaryButton(if (s.checkingUpdates) "Checking…" else "Check for updates", {
                s.checkingUpdates = true
                scope.launch {
                    s.update = try { withContext(Dispatchers.IO) { UpdateChecker.check() } }
                    catch (_: Exception) { UpdateInfo("Cannot reach GitHub releases right now.") }
                    s.checkingUpdates = false
                }
            }, Modifier.fillMaxWidth(), busy = s.checkingUpdates, icon = KIcons.Download)
            s.update?.let { u ->
                Note(u.message, if (u.downloadUrl != null) Tone.Good else Tone.Info)
                u.downloadUrl?.let { url ->
                    SecondaryButton("Open official download", { openUrl(url) }, Modifier.fillMaxWidth(),
                        icon = KIcons.OpenInNew, tint = K.mint)
                }
            }
        }

        Panel {
            Row(verticalAlignment = Alignment.CenterVertically) {
                IconTile(KIcons.Chip, K.cyan)
                Spacer(Modifier.width(14.dp))
                Column(Modifier.weight(1f)) {
                    Text("Native cores", color = K.text, fontSize = 15.sp, fontWeight = FontWeight.SemiBold)
                    Text("Aether, Psiphon and Lyrebird executables", color = K.muted, fontSize = 12.sp)
                }
            }
            Text("Checks every packaged executable against the pinned SHA-256 manifest. Nothing is downloaded or started.",
                color = K.muted, fontSize = 12.sp, lineHeight = 17.sp)
            SecondaryButton(if (s.bundleBusy) "Verifying…" else "Verify packaged cores", {
                s.bundleBusy = true; s.bundleError = null; s.bundle = null
                scope.launch {
                    try { s.bundle = withContext(Dispatchers.IO) { JSONObject(Mobilebridge.inspectAndroidBundle(nativeLibraryDir)) } }
                    catch (e: Exception) { s.bundleError = e.message ?: "Verification failed" }
                    finally { s.bundleBusy = false }
                }
            }, Modifier.fillMaxWidth(), busy = s.bundleBusy, icon = KIcons.Shield)
            s.bundleError?.let { Note(it, Tone.Danger) }
            s.bundle?.let { b ->
                Note("All packaged executables match the pinned manifest.", Tone.Good)
                KeyValue("Aether release", b.optString("version"), mono = true)
                KeyValue("ABI", b.optString("abi"), mono = true)
                for ((label, key) in listOf("Aether" to "aether", "Psiphon" to "psiphon", "Lyrebird" to "lyrebird")) {
                    KeyValue(label, b.optString(key).substringAfterLast('/'), K.muted, mono = true)
                }
            }
        }

        Panel {
            Row(verticalAlignment = Alignment.CenterVertically) {
                IconTile(KIcons.Shield, if (vpn.optBoolean("available")) K.mint else K.faint)
                Spacer(Modifier.width(14.dp))
                Column(Modifier.weight(1f)) {
                    Text("System-wide VPN", color = K.text, fontSize = 15.sp, fontWeight = FontWeight.SemiBold)
                    Text(when (vpnServiceState) {
                        "tun_running_unverified" -> "Adapter running"
                        "failed" -> "Adapter failed"
                        "revoked" -> "Permission revoked"
                        else -> if (vpn.optBoolean("available")) "Ready" else "Not available yet"
                    }, color = K.muted, fontSize = 12.sp)
                }
                Tag(if (vpn.optBoolean("available")) "Beta" else "Locked", if (vpn.optBoolean("available")) K.mint else K.faint)
            }
            Text(
                if (vpn.optBoolean("available")) "Packet forwarding prerequisites are available. Android will ask for consent."
                else vpn.optString("reason", "Waiting for validated packet routing support (UDP, DNS and IPv6)."),
                color = K.muted, fontSize = 12.sp, lineHeight = 17.sp
            )
            vpnError?.let { Note(it, Tone.Danger) }
            if (vpn.optBoolean("available") || vpnServiceState == "tun_running_unverified") {
                SecondaryButton(if (vpnServiceState == "tun_running_unverified") "Stop VPN" else "Start system VPN",
                    onVpnAction, Modifier.fillMaxWidth())
            }
        }

        Panel {
            SectionLabel("Privacy")
            PrivacyRow(KIcons.Lock, "No logs leave the device", "Native core output can contain identifiers, so it is discarded rather than shown or written to logcat.")
            Hairline()
            PrivacyRow(KIcons.Key, "No certificates installed", "The optional domain-fronting CA stays in the Go source. This app never changes trusted certificates.")
            Hairline()
            PrivacyRow(KIcons.Globe, "No analytics", "The only network calls are the ones you start: connections, tools and update checks.")
        }

        Panel {
            SectionLabel("Open-source notices")
            Text("KTest ships these unmodified upstream programs. Their source code is available at the links below.",
                color = K.muted, fontSize = 12.sp, lineHeight = 17.sp)
            notices.forEachIndexed { i, n ->
                Row(
                    Modifier.fillMaxWidth().clip(RoundedCornerShape(12.dp)).clickable { openUrl(n.url) }.padding(vertical = 6.dp),
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Column(Modifier.weight(1f)) {
                        Text(n.name, color = K.text, fontSize = 14.sp, fontWeight = FontWeight.Medium)
                        Text(n.detail, color = K.muted, fontSize = 12.sp)
                    }
                    Tag(n.license, K.cyan)
                    Spacer(Modifier.width(6.dp))
                    Icon(KIcons.OpenInNew, "Open source", tint = K.faint, modifier = Modifier.size(16.dp))
                }
                if (i < notices.lastIndex) Hairline()
            }
        }
        Text("KTest Connection ${BuildConfig.VERSION_NAME} · Android ${android.os.Build.VERSION.RELEASE}",
            color = K.faint, fontSize = 11.sp, modifier = Modifier.fillMaxWidth().padding(vertical = 6.dp),
            textAlign = androidx.compose.ui.text.style.TextAlign.Center)
    }
}

@Composable
private fun PrivacyRow(icon: ImageVector, title: String, body: String) {
    Row(verticalAlignment = Alignment.Top) {
        Icon(icon, null, tint = K.mint, modifier = Modifier.padding(top = 2.dp).size(18.dp))
        Spacer(Modifier.width(12.dp))
        Column {
            Text(title, color = K.text, fontSize = 14.sp, fontWeight = FontWeight.Medium)
            Text(body, color = K.muted, fontSize = 12.sp, lineHeight = 17.sp)
        }
    }
}

/** The KTest mark: a gradient tile with the power glyph, used in header and settings. */
@Composable
internal fun AppMark(size: androidx.compose.ui.unit.Dp = 36.dp) {
    Box(
        Modifier.size(size).clip(RoundedCornerShape(size * 0.3f)).background(K.accentBrush),
        contentAlignment = Alignment.Center
    ) { Icon(KIcons.Power, null, tint = K.bg, modifier = Modifier.size(size * 0.56f)) }
}
