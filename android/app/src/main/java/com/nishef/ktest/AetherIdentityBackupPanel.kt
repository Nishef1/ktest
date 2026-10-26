package com.nishef.ktest

import android.util.Base64
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.*
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.ui.unit.dp
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import mobilebridge.Mobilebridge
import org.json.JSONObject

// Android's private app files survive ordinary upgrades but not full removal.
// A portable backup is therefore created *only* after a deliberate user
// action, encrypted in Go before its bytes enter a shared SAF document.
@Composable
internal fun AetherIdentityBackupPanel(scope: CoroutineScope, privateDir: String, nativeLibraryDir: String, canRestore: Boolean) {
    val context = androidx.compose.ui.platform.LocalContext.current
    var password by remember { mutableStateOf("") }
    var busy by remember { mutableStateOf(false) }
    var message by remember { mutableStateOf("") }
    var error by remember { mutableStateOf("") }
    var valid by remember { mutableIntStateOf(0) }
    var masqueReady by remember { mutableStateOf(false) }
    var wireguardReady by remember { mutableStateOf(false) }
    var invalidKeys by remember { mutableStateOf("") }
    var via by remember { mutableStateOf("") }

    fun refreshStatus() {
        scope.launch {
            val status = withContext(Dispatchers.IO) {
                runCatching { JSONObject(Mobilebridge.aetherIdentityStatus(privateDir)) }.getOrNull()
            }
            valid = status?.optInt("valid") ?: 0
            masqueReady = status?.optBoolean("masque_ready") ?: false
            wireguardReady = status?.optBoolean("wireguard_ready") ?: false
            invalidKeys = status?.optJSONArray("invalid")?.let { keys ->
                (0 until keys.length()).joinToString(", ") { keys.optString(it) }
            }.orEmpty()
        }
    }
    LaunchedEffect(privateDir) {
        refreshStatus()
    }
    val export = rememberLauncherForActivityResult(
        ActivityResultContracts.CreateDocument("application/json")
    ) { uri ->
        if (uri != null && !busy) {
            val secret = password
            busy = true
            message = ""
            error = ""
            scope.launch {
                try {
                    withContext(Dispatchers.IO) {
                        val encoded = Mobilebridge.exportAetherIdentityBackup(privateDir, secret)
                        val data = Base64.decode(encoded, Base64.DEFAULT)
                        context.contentResolver.openOutputStream(uri, "wt")?.use { it.write(data) }
                            ?: throw IllegalStateException("Cannot open the chosen backup document")
                    }
                    message = "Encrypted WARP backup saved to your selected location. Keep the password separately."
                    refreshStatus()
                } catch (e: CancellationException) {
                    throw e
                } catch (e: Exception) {
                    error = e.message ?: "Backup could not be saved"
                } finally {
                    password = ""
                    busy = false
                }
            }
        }
    }
    val restore = rememberLauncherForActivityResult(
        ActivityResultContracts.OpenDocument()
    ) { uri ->
        if (uri != null && !busy) {
            val secret = password
            busy = true
            message = ""
            error = ""
            scope.launch {
                try {
                    val count = withContext(Dispatchers.IO) {
                        val bytes = context.contentResolver.openInputStream(uri)?.use { stream ->
                            val buffer = java.io.ByteArrayOutputStream()
                            val chunk = ByteArray(8192)
                            while (buffer.size() <= (8 shl 20)) {
                                val count = stream.read(chunk)
                                if (count < 0) break
                                buffer.write(chunk, 0, count)
                            }
                            buffer.toByteArray()
                        } ?: throw IllegalStateException("Cannot open the selected backup document")
                        require(bytes.isNotEmpty() && bytes.size <= (8 shl 20)) {
                            "Invalid or oversized backup document"
                        }
                        val encoded = Base64.encodeToString(bytes, Base64.NO_WRAP)
                        val result = Mobilebridge.importAetherIdentityBackup(privateDir, secret, encoded)
                        JSONObject(result).getJSONArray("imported").length()
                    }
                    message = if (count > 0) "Restored $count valid WARP identity files. Existing valid identities were preserved."
                        else "The same valid identities were already saved. Nothing was overwritten."
                    refreshStatus()
                } catch (e: CancellationException) {
                    throw e
                } catch (e: Exception) {
                    error = e.message ?: "Backup could not be restored"
                } finally {
                    password = ""
                    busy = false
                }
            }
        }
    }

    // PattNG keeps key selection independent of each connection profile.
    // Direct WARP API/edge remains first; ECH and Psiphon CDN are fallbacks.
    fun register(kind: String) {
        if (busy) return
        val proxy = via.trim()
        busy = true
        message = ""
        error = ""
        scope.launch {
            try {
                val result = withContext(Dispatchers.IO) {
                    JSONObject(Mobilebridge.registerAetherIdentityKind(nativeLibraryDir, privateDir, proxy, kind))
                }
                val items = result.getJSONArray("results")
                val failed = (0 until items.length()).map { items.getJSONObject(it) }.filter { !it.optBoolean("ready") }
                if (failed.isEmpty()) {
                    message = "Requested WARP key is ready. Registration success does not prove a working tunnel."
                } else {
                    error = failed.joinToString("\n") { "${it.optString("protocol")}: ${it.optString("error")}" }
                }
                refreshStatus()
            } catch (e: CancellationException) {
                throw e
            } catch (e: Exception) {
                error = e.message ?: "WARP registration failed"
            } finally {
                busy = false
            }
        }
    }

    Panel {
        SectionLabel("WARP keys · Cloudflare device registration")
        Text("Aether uses WARP keys for MASQUE and WireGuard. Psiphon CDN and standalone Tor do not need WARP keys.",
            color = K.muted, fontSize = 12.sp, lineHeight = 17.sp)
        KeyValue("MASQUE H2 / H3", if (masqueReady) "Key saved" else "Missing")
        KeyValue("WireGuard", if (wireguardReady) "Key saved" else "Missing")
        if (invalidKeys.isNotBlank()) Note("Existing invalid key file(s): $invalidKeys. They are preserved, not overwritten; restore a backup or explicitly repair them.", Tone.Warn)
        if (!masqueReady || !wireguardReady) {
            Note("Try with the proxy field empty first. The core uses its direct API/edge fallback, fragmented TLS and optional ECH or Psiphon CDN registration. Getting a key is not the same as connecting.", Tone.Warn)
        }
        OutlinedTextField(
            value = via,
            onValueChange = { via = it },
            modifier = Modifier.fillMaxWidth(),
            label = { Text("Other app's local proxy (optional, SOCKS5 or http://)") },
            singleLine = true,
            enabled = !busy,
            keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Uri)
        )
        SecondaryButton(if (masqueReady) "Check / keep MASQUE key" else "Get MASQUE key",
            { register("masque") }, Modifier.fillMaxWidth(), enabled = canRestore && !busy, busy = busy)
        SecondaryButton(if (wireguardReady) "Check / keep WireGuard key" else "Get WireGuard key",
            { register("wg") }, Modifier.fillMaxWidth(), enabled = canRestore && !busy, busy = busy)
        Note("Keys are handled independently. Existing valid keys are reused and never overwritten. Updates keep private keys, but uninstalling or clearing data removes them; export a backup first.")
        OutlinedTextField(
            value = password,
            onValueChange = { password = it },
            modifier = Modifier.fillMaxWidth(),
            label = { Text("Backup password (at least 12 characters)") },
            singleLine = true,
            enabled = !busy,
            visualTransformation = PasswordVisualTransformation(),
            keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Password)
        )
        SecondaryButton("Save encrypted WARP backup", {
            export.launch("ktest-warp-backup.json")
        }, Modifier.fillMaxWidth(), enabled = !busy && password.length >= 12)
        SecondaryButton("Restore encrypted WARP backup", {
            restore.launch(arrayOf("application/json", "application/octet-stream", "*/*"))
        }, Modifier.fillMaxWidth(), enabled = canRestore && !busy && password.length >= 12)
        if (!canRestore) Note("Disconnect before restoring an identity. Existing connections must not switch identities mid-session.", Tone.Warn)
        if (message.isNotBlank()) Note(message, Tone.Good)
        if (error.isNotBlank()) Note(error, Tone.Danger)
        Note("Only encrypted data is exported. A lost password cannot be recovered. Backups are optional and no credential is silently uploaded.")
    }
}
