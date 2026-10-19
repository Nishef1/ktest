package com.nishef.ktest

import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.selection.SelectionContainer
import androidx.compose.material3.Icon
import androidx.compose.material3.Text
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.platform.LocalContext
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
    var caBusy by mutableStateOf(false)
    var caReport by mutableStateOf<JSONObject?>(null)
    var caError by mutableStateOf<String?>(null)
    var caMessage by mutableStateOf<String?>(null)
    var caTrust by mutableStateOf<LocalCaTrust.Result?>(null)
    var caTrustBusy by mutableStateOf(false)
    var frontingEnabled by mutableStateOf(false)
}

private data class Notice(val name: String, val detail: String, val license: String, val url: String)

// Distribution notices for the unmodified native executables shipped in the APK.
// Keep in sync with docs/THIRD_PARTY_NOTICES.md and internal/aether/android-cores.json.
private val notices = listOf(
    Notice("ByeDPI v0.17.3", "hufrea · local anti-DPI strategies shared with desktop", "MIT",
        "https://github.com/hufrea/byedpi/tree/v0.17.3"),
    Notice("Xray v26.10.10", "XTLS · official ARMv8 native TLS fragmentation core", "MPL-2.0",
        "https://github.com/XTLS/Xray-core/releases/tag/v26.10.10"),
    Notice("Aether v2.3.0", "CluvexStudio · MASQUE / WireGuard core with Tor (Arti)", "AGPL-3.0",
        "https://github.com/CluvexStudio/Aether/tree/v2.3.0"),
    Notice("psiphon-tunnel-core", "CluvexStudio fork, shirokhorshid @ 83aa73b", "GPL-3.0",
        "https://github.com/CluvexStudio/psiphon-tunnel-core/tree/83aa73b9b982e7421e00117f5b0c5aceb5dda452"),
    Notice("lyrebird", "Tor Project pluggable transports @ fc105a0", "BSD",
        "https://gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/lyrebird/-/tree/fc105a03c0e0acc2479301c361c012ffed359c43"),
    Notice("hev-socks5-tunnel 2.19.0", "heiher · Android VPN/TUN-to-SOCKS packet adapter (beta)", "MIT",
        "https://github.com/heiher/hev-socks5-tunnel"),
    Notice("KTest", "Go connection core and this app", "Source", "https://github.com/Nishef1/ktest")
)

@Composable
internal fun SettingsScreen(
    s: SettingsState, scope: CoroutineScope, nativeLibraryDir: String,
    routeTargets: RouteTargetsState, targetsEditable: Boolean, manualTesting: Boolean, onTargetsChanged: () -> Unit,
    vpn: JSONObject, vpnServiceState: String, vpnError: String?,
    onVpnAction: () -> Unit, openUrl: (String) -> Unit
) {
    val context = LocalContext.current
    val privateDir = remember(context) { context.filesDir.canonicalPath }
    val preferences = remember(context) { context.getSharedPreferences("ktest_android", android.content.Context.MODE_PRIVATE) }

    // Storage Access Framework only exports the public certificate. The CA
    // private key must never enter an Intent, shared file or clipboard.
    val exportCert = rememberLauncherForActivityResult(
        ActivityResultContracts.CreateDocument("application/x-x509-ca-cert")
    ) { uri ->
        if (uri != null) {
            s.caBusy = true
            s.caError = null
            s.caMessage = null
            scope.launch {
                try {
                    withContext(Dispatchers.IO) {
                        val pem = Mobilebridge.frontCAPublicPEM(privateDir)
                        val output = context.contentResolver.openOutputStream(uri)
                            ?: error("Android could not open the selected certificate file")
                        output.use { it.write(pem.toByteArray(Charsets.US_ASCII)) }
                    }
                    s.caMessage = "Public CA saved. Install it manually from Android Settings; private key was not exported."
                } catch (e: Exception) {
                    s.caError = e.message ?: "Unable to export the public certificate"
                } finally {
                    s.caBusy = false
                }
            }
        }
    }
    LaunchedEffect(privateDir) {
        s.frontingEnabled = preferences.getBoolean("fronting_opt_in", false)
        s.caTrustBusy = true
        s.caError = null
        s.caTrust = null
        try {
            s.caReport = withContext(Dispatchers.IO) { JSONObject(Mobilebridge.frontCAStatus(privateDir)) }
            if (s.caReport?.optString("state") == "ready") {
                s.caTrust = withContext(Dispatchers.IO) { LocalCaTrust.inspect(privateDir) }
            }
        } catch (e: Exception) {
            s.caError = e.message ?: "Could not inspect local CA"
        } finally {
            s.caTrustBusy = false
        }
    }

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
            vpn.optString("packet_adapter").takeIf { it.isNotBlank() }?.let {
                KeyValue("Packet engine", it, mono = true)
            }
            vpn.optString("fallback_reason").takeIf { it.isNotBlank() }?.let {
                Note("Automatic packet-adapter recovery: $it", Tone.Warn)
            }
            vpnError?.let { Note(it, Tone.Danger) }
            if (vpn.optBoolean("available") || vpnServiceState == "tun_running_unverified") {
                SecondaryButton(if (vpnServiceState == "tun_running_unverified") "Stop VPN" else "Start system VPN",
                    onVpnAction, Modifier.fillMaxWidth(), enabled = vpnServiceState == "tun_running_unverified" || !manualTesting)
            }
        }

        Panel {
            Row(verticalAlignment = Alignment.CenterVertically) {
                IconTile(KIcons.Key, K.cyan)
                Spacer(Modifier.width(14.dp))
                Column(Modifier.weight(1f)) {
                    Text("Local certificate generator", color = K.text, fontSize = 15.sp,
                        fontWeight = FontWeight.SemiBold)
                    Text("Optional limited-domain CA · manual install", color = K.muted, fontSize = 12.sp)
                }
            }
            Text(
                "Generate the same name-constrained CA as Windows. The private key stays in " +
                    "KTest's app-private storage. Only the public .crt can be saved.",
                color = K.muted, fontSize = 12.sp, lineHeight = 17.sp
            )
            val caState = s.caReport?.optString("state") ?: "loading"
            KeyValue("Certificate", when (caState) {
                "ready" -> "Generated locally"
                "outdated" -> "Outdated; do not install"
                "invalid" -> "Invalid or incomplete files"
                "missing" -> "Not generated"
                else -> "Checking…"
            })
            s.caReport?.optString("fingerprint")?.takeIf { it.isNotBlank() }?.let { fingerprint ->
                Column(Modifier.fillMaxWidth(), verticalArrangement = Arrangement.spacedBy(6.dp)) {
                    Text("SHA-1 fingerprint", color = K.muted, fontSize = 13.sp)
                    SelectionContainer(Modifier.fillMaxWidth()) {
                        Text(fingerprint.replace(":", "").chunked(4).joinToString(" "),
                            modifier = Modifier.fillMaxWidth(), color = K.text, fontFamily = K.mono,
                            fontSize = 13.sp, lineHeight = 21.sp, softWrap = true)
                    }
                    SecondaryButton("Copy fingerprint", {
                        val clipboard = context.getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
                        clipboard.setPrimaryClip(ClipData.newPlainText("KTest CA SHA-1 fingerprint", fingerprint))
                    }, Modifier.fillMaxWidth(), icon = KIcons.Copy)
                }
            }
            s.caReport?.optString("expires")?.takeIf { it.isNotBlank() }?.let {
                KeyValue("Valid until", it, mono = true)
            }
            s.caReport?.optString("detail")?.takeIf { caState != "ready" && it.isNotBlank() }?.let {
                Note(it, if (caState == "invalid" || caState == "outdated") Tone.Danger else Tone.Info)
            }
            if (caState == "missing") {
                SecondaryButton(if (s.caBusy) "Generating…" else "Generate local CA", {
                    s.caBusy = true
                    s.caError = null
                    s.caMessage = null
                    s.caTrust = null
                    scope.launch {
                        try {
                            s.caReport = withContext(Dispatchers.IO) {
                                JSONObject(Mobilebridge.generateFrontCA(privateDir))
                            }
                            s.caTrust = withContext(Dispatchers.IO) { LocalCaTrust.inspect(privateDir) }
                            s.caMessage = "CA generated on this phone. Export the public certificate to install it manually."
                        } catch (e: Exception) {
                            s.caError = e.message ?: "CA generation failed"
                        } finally {
                            s.caBusy = false
                        }
                    }
                }, Modifier.fillMaxWidth(), busy = s.caBusy, icon = KIcons.Key)
            }
            if (caState == "ready") {
                SecondaryButton("Save public certificate (.crt)", {
                    exportCert.launch("ktest-ca.crt")
                }, Modifier.fillMaxWidth(), busy = s.caBusy, icon = KIcons.Download)
            }
            if (caState == "ready") {
                SecondaryButton(if (s.caTrustBusy) "Checking…" else "Check Android CA installation", {
                    s.caTrustBusy = true
                    s.caTrust = null
                    s.caError = null
                    scope.launch {
                        try {
                            s.caTrust = withContext(Dispatchers.IO) { LocalCaTrust.inspect(privateDir) }
                        } catch (e: Exception) {
                            s.caError = e.message ?: "Could not inspect Android CA installation"
                        } finally {
                            s.caTrustBusy = false
                        }
                    }
                }, Modifier.fillMaxWidth(), busy = s.caTrustBusy, icon = KIcons.Shield)
                KeyValue("Android user CA", when {
                    s.caTrustBusy -> "Checking…"
                    s.caTrust?.state == "installed_user" -> "Exact CA installed"
                    s.caTrust?.state == "not_found" -> "Not installed"
                    s.caTrust == null -> "Not checked"
                    else -> "Unable to check"
                })
                s.caTrust?.let { trust ->
                    Note(trust.detail, if (trust.state == "installed_user") Tone.Good else Tone.Warn)
                }
                Note(if (s.caTrust?.state == "installed_user")
                    "App trust is checked separately by each app. Installation does not prove another app accepts user CAs; certificate pinning can still reject this CA."
                    else "App trust is not verified. Generate and manually install this exact CA, then check its installation; each app still decides whether to trust it.")
                if (s.caTrust?.state == "installed_user" || s.frontingEnabled) {
                    SecondaryButton(
                        if (s.frontingEnabled) "Disable optional domain fronting" else "Enable optional domain fronting",
                        {
                            s.frontingEnabled = !s.frontingEnabled
                            preferences.edit().putBoolean("fronting_opt_in", s.frontingEnabled).apply()
                            s.caMessage = if (s.frontingEnabled)
                                "Opted in for the next Balanced/Fast connection. A manual test is optional; live routes stay adaptive."
                            else "Domain fronting disabled for future connections. Run Test while offline to update the saved profile."
                            onTargetsChanged()
                        }, Modifier.fillMaxWidth(), enabled = !manualTesting && !routeTargets.busy, icon = KIcons.Route
                    )
                }
            }
            if (s.frontingEnabled && s.caTrust?.state != "installed_user") {
                Note("Fronting is selected, but Android user CA trust is not confirmed. New fronting sessions will be refused until you check the certificate.", Tone.Warn)
            }
            s.caError?.let { Note(it, Tone.Danger) }
            s.caMessage?.let { Note(it, Tone.Good) }
            Text(
                "After saving: Android Settings → Security & privacy → More security settings → " +
                    "Encryption & credentials → Install a certificate → CA certificate. " +
                    "Menu names depend on device. Android asks for confirmation. " +
                    "Only apps that trust user-installed CAs may accept it; certificate pinning still applies. " +
                    "Installing this CA alone does not activate domain fronting in KTest.",
                color = K.muted, fontSize = 12.sp, lineHeight = 17.sp
            )
            Note("Normal app updates preserve this CA and its private key in app storage. " +
                "A full uninstall or clearing app data removes the private key. " +
                "Remove the user CA manually from Android's trusted credentials too.")
        }

        RouteTargetsPanel(routeTargets, scope, privateDir, targetsEditable,
            s.caReport?.optString("fingerprint").orEmpty(), onTargetsChanged)

        Panel {
            SectionLabel("Privacy")
            PrivacyRow(KIcons.Lock, "No logs leave the device", "Native core output can contain identifiers, so it is discarded rather than shown or written to logcat.")
            Hairline()
            PrivacyRow(KIcons.Key, "No automatic CA installation", "A local certificate can be generated only on request. You export and install its public part manually; private key stays on the phone.")
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
