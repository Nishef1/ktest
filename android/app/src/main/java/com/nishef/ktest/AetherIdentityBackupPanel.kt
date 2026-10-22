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
    var via by remember { mutableStateOf("") }

    fun refreshStatus() {
        scope.launch {
            valid = withContext(Dispatchers.IO) {
                runCatching { JSONObject(Mobilebridge.aetherIdentityStatus(privateDir)).optInt("valid") }.getOrDefault(0)
            }
        }
    }
    LaunchedEffect(privateDir) {
        valid = withContext(Dispatchers.IO) {
            runCatching { JSONObject(Mobilebridge.aetherIdentityStatus(privateDir)).optInt("valid") }.getOrDefault(0)
        }
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

    // Field reports from 2026-10-21 indicate cloudflare-ech.com may be filtered
    // on some Iranian networks. If ECH bootstrap fails, register through another
    // app's local proxy or another VPN while KTest is disconnected.
    fun register() {
        if (busy) return
        val proxy = via.trim()
        busy = true
        message = ""
        error = ""
        scope.launch {
            try {
                val result = withContext(Dispatchers.IO) {
                    JSONObject(Mobilebridge.registerAetherIdentity(nativeLibraryDir, privateDir, proxy))
                }
                val items = result.getJSONArray("results")
                val failed = (0 until items.length()).map { items.getJSONObject(it) }.filter { !it.optBoolean("ready") }
                if (failed.isEmpty()) {
                    message = "WARP keys are ready. If you turned on another VPN for this, turn it off before connecting KTest."
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
        SectionLabel("WARP identity recovery")
        Text("Valid saved Aether keys: $valid", color = K.text)
        if (valid == 0) {
            Note("No WARP key yet. ECH bootstrap may be filtered on some Iranian networks. " +
                "Get a key once: enter another app's local proxy (e.g. 127.0.0.1:10808 or http://127.0.0.1:10809), " +
                "or leave it empty and turn on another VPN first. Then turn that VPN off and connect.", Tone.Warn)
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
        SecondaryButton("Get WARP key", { register() },
            Modifier.fillMaxWidth(), enabled = canRestore, busy = busy)
        Note("Your WARP identity is generated automatically by Aether on first use and kept in this app's private storage. App updates keep it; uninstalling or clearing app data removes it. Export an encrypted copy before uninstalling.")
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
