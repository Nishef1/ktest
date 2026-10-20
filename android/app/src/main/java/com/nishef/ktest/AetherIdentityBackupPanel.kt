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
import androidx.compose.ui.graphics.Color
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
internal fun AetherIdentityBackupPanel(scope: CoroutineScope, privateDir: String, canRestore: Boolean) {
    val context = androidx.compose.ui.platform.LocalContext.current
    var password by remember { mutableStateOf("") }
    var busy by remember { mutableStateOf(false) }
    var message by remember { mutableStateOf("") }
    var error by remember { mutableStateOf("") }
    var valid by remember { mutableIntStateOf(0) }

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
                            ?: error("Cannot open the chosen backup document")
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
                        val bytes = context.contentResolver.openInputStream(uri)?.use {
                            it.readNBytes((8 shl 20) + 1)
                        } ?: error("Cannot open the selected backup document")
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

    Panel {
        SectionLabel("WARP identity recovery")
        Text("Valid saved Aether keys: $valid", color = K.text)
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
