package com.nishef.ktest

import android.content.SharedPreferences
import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material3.FilterChip
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import mobilebridge.Mobilebridge

internal val aetherFingerprints = listOf("auto", "chrome", "firefox", "semi-python", "go")

// F&F (Fragment + Fingerprint) and the MASQUE server name of Aether's
// handshakes. Auto, the default, is measured per network and saved; a fixed
// value is used as given. Read by ProxyService at each start.
@OptIn(androidx.compose.material3.ExperimentalMaterial3Api::class)
@Composable
internal fun AetherTlsPanel(scope: CoroutineScope, preferences: SharedPreferences, privateDir: String, canMeasure: Boolean) {
    var fingerprint by remember { mutableStateOf(preferences.getString("aether_fingerprint", "auto") ?: "auto") }
    var sni by remember { mutableStateOf(preferences.getString("masque_sni", "auto") ?: "auto") }
    var fragment by remember { mutableStateOf(preferences.getString("aether_fragment", "auto") ?: "auto") }
    var busy by remember { mutableStateOf(false) }
    var message by remember { mutableStateOf("") }
    var error by remember { mutableStateOf("") }

    // Validated by the same Go parser the connection uses.
    fun save(fp: String, name: String, frag: String): Boolean {
        return try {
            Mobilebridge.setAetherTLS(fp, name, frag)
            preferences.edit().putString("aether_fingerprint", fp).putString("masque_sni", name)
                .putString("aether_fragment", frag).apply()
            error = ""
            true
        } catch (e: Exception) {
            error = e.message ?: "Invalid value"
            false
        }
    }

    Panel {
        SectionLabel("F&F and MASQUE SNI")
        Text("Fingerprint", color = K.text, fontSize = 14.sp)
        Row(Modifier.horizontalScroll(rememberScrollState()), horizontalArrangement = Arrangement.spacedBy(6.dp)) {
            aetherFingerprints.forEach { fp ->
                FilterChip(selected = fingerprint == fp, onClick = {
                    if (save(fp, sni, fragment)) fingerprint = fp
                }, label = { Text(fp) }, enabled = !busy)
            }
        }
        OutlinedTextField(
            value = sni, onValueChange = { sni = it }, modifier = Modifier.fillMaxWidth(),
            label = { Text("MASQUE SNI: auto, a name, or names separated by commas") },
            singleLine = true, enabled = !busy, keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Uri)
        )
        OutlinedTextField(
            value = fragment, onValueChange = { fragment = it }, modifier = Modifier.fillMaxWidth(),
            label = { Text("Aether TLS fragmentation: auto, off, or size/delay (e.g. 8-16/2-10)") },
            singleLine = true, enabled = !busy, keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Ascii)
        )
        SecondaryButton("Save", {
            if (save(fingerprint, sni.ifBlank { "auto" }, fragment.ifBlank { "auto" })) message = "Saved · applies on the next connection"
        }, Modifier.fillMaxWidth(), enabled = !busy)
        SecondaryButton("Measure this network now", {
            if (save(fingerprint, sni.ifBlank { "auto" }, fragment.ifBlank { "auto" })) {
                busy = true
                message = ""
                scope.launch {
                    try {
                        message = withContext(Dispatchers.IO) { Mobilebridge.calibrateAetherTLS(privateDir) }
                    } catch (e: CancellationException) {
                        throw e
                    } catch (e: Exception) {
                        error = e.message ?: "Measurement failed"
                    } finally {
                        busy = false
                    }
                }
            }
        }, Modifier.fillMaxWidth(), enabled = canMeasure, busy = busy)
        if (!canMeasure) Note("Disconnect to measure: it must see this network, not the tunnel.", Tone.Warn)
        if (message.isNotBlank()) Note(message, Tone.Good)
        if (error.isNotBlank()) Note(error, Tone.Danger)
        Note("Off disables Aether's own TLS fragmentation. On desktop, KTest also excludes TCP TLS-hello exit-node masks; " +
            "independent local anti-DPI carrier strategies may still shape the outer connection. Auto uses a saved MASQUE " +
            "measurement when available; use Measure this network now to refresh it.")
    }
}
