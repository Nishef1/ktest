package com.nishef.ktest

import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.Button
import androidx.compose.material3.FilterChip
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import mobilebridge.Mobilebridge
import org.json.JSONObject

@Composable
internal fun CDNScanTool() {
    var provider by rememberSaveable { mutableStateOf("cloudflare") }
    var budget by rememberSaveable { mutableStateOf("300") }
    var status by remember { mutableStateOf(JSONObject(Mobilebridge.cdnScanStatus())) }
    var error by remember { mutableStateOf<String?>(null) }
    var starting by remember { mutableStateOf(false) }
    val scope = rememberCoroutineScope()
    val busy = starting || status.optBoolean("running")
    LaunchedEffect(Unit) {
        while (isActive) {
            status = withContext(Dispatchers.IO) { JSONObject(Mobilebridge.cdnScanStatus()) }
            delay(600)
        }
    }
    Surface(shape = RoundedCornerShape(23.dp)) {
        Column(Modifier.fillMaxWidth().padding(18.dp), verticalArrangement = Arrangement.spacedBy(10.dp)) {
            Text("CDN SCAN", color = MaterialTheme.colorScheme.primary)
            Text("Test provider HTTPS routes using the desktop scanner. Up to six checks run at once, for at most 90 seconds.")
            Row(Modifier.horizontalScroll(rememberScrollState()), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                for (name in listOf("cloudflare", "akamai", "fastly", "google")) {
                    FilterChip(selected = provider == name, enabled = !busy,
                        onClick = { provider = name }, label = { Text(name.replaceFirstChar { it.uppercase() }) })
                }
            }
            OutlinedTextField(value = budget, onValueChange = { budget = it }, enabled = !busy,
                label = { Text("Maximum candidates (1–300)") }, singleLine = true, modifier = Modifier.fillMaxWidth())
            Row(horizontalArrangement = Arrangement.spacedBy(10.dp)) {
                Button(enabled = !busy, onClick = {
                    val limit = budget.toIntOrNull()
                    if (limit == null || limit !in 1..300) {
                        error = "Enter a candidate budget between 1 and 300."
                    } else {
                        starting = true
                        error = null
                        scope.launch {
                            try {
                                withContext(Dispatchers.IO) {
                                    Mobilebridge.startCDNScanForProvider(provider, limit.toLong(), minOf(10, limit).toLong())
                                }
                                status = JSONObject(Mobilebridge.cdnScanStatus())
                            } catch (e: Exception) { error = e.message ?: "Scan could not start" }
                            finally { starting = false }
                        }
                    }
                }) { Text("Start scan") }
                if (busy) TextButton(onClick = { Mobilebridge.cancelCDNScan() }) { Text("Cancel") }
            }
            if (busy) LinearProgressIndicator(modifier = Modifier.fillMaxWidth())
            val verified = status.optJSONArray("verified_http")
            Text("${status.optInt("attempted")} checked · ${verified?.length() ?: 0} verified HTTPS")
            if (status.optBoolean("canceled")) Text(if (busy) "Canceling…" else "Canceled; partial results shown")
            if (verified != null) for (index in 0 until verified.length()) Text(verified.getString(index))
            val failure = error ?: status.optString("error").takeIf { it.isNotBlank() }
            if (failure != null) Text(failure, color = MaterialTheme.colorScheme.error)
            Text("A successful provider check does not prove arbitrary fronting, DNS availability or a working VPN.",
                style = MaterialTheme.typography.bodySmall)
        }
    }
}

@Composable
internal fun WindscribeCarrierTool() {
    var address by rememberSaveable { mutableStateOf("") }
    var name by rememberSaveable { mutableStateOf("") }
    var transport by rememberSaveable { mutableStateOf("wstunnel") }
    var busy by remember { mutableStateOf(false) }
    var report by remember { mutableStateOf<JSONObject?>(null) }
    var error by remember { mutableStateOf<String?>(null) }
    val scope = rememberCoroutineScope()
    Surface(shape = RoundedCornerShape(23.dp)) {
        Column(Modifier.fillMaxWidth().padding(18.dp), verticalArrangement = Arrangement.spacedBy(10.dp)) {
            Text("WINDSCRIBE CARRIER TEST", color = MaterialTheme.colorScheme.primary)
            Text("Test an authorized entry or your own CDN route. Use a hostname with a valid certificate. The test uses the current Android network.")
            OutlinedTextField(value = address, onValueChange = { address = it }, enabled = !busy,
                label = { Text("Entry IP:port") }, singleLine = true, modifier = Modifier.fillMaxWidth())
            OutlinedTextField(value = name, onValueChange = { name = it }, enabled = !busy,
                label = { Text("TLS and HTTP hostname") }, singleLine = true, modifier = Modifier.fillMaxWidth())
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                for (method in listOf("wstunnel", "stealth")) {
                    FilterChip(selected = transport == method, enabled = !busy,
                        onClick = { transport = method }, label = { Text(method) })
                }
            }
            Button(enabled = !busy && address.isNotBlank() && name.isNotBlank(), onClick = {
                busy = true; error = null; report = null
                scope.launch {
                    try {
                        report = withContext(Dispatchers.IO) {
                            JSONObject(Mobilebridge.testWindscribeCarrier(address.trim(), name.trim(), name.trim(), transport))
                        }
                    } catch (e: Exception) { error = e.message ?: "Carrier test failed" }
                    finally { busy = false }
                }
            }) { Text(if (busy) "Testing…" else "Test carrier") }
            report?.let {
                Text("TCP: ${it.optBoolean("tcp")} · TLS: ${it.optBoolean("tls_handshake")}")
                Text("Certificate verified: ${it.optBoolean("certificate_verified")} · WebSocket: ${it.optBoolean("websocket")}")
                if (it.optString("failure").isNotBlank()) Text("${it.optString("stage")}: ${it.optString("failure")}")
            }
            if (error != null) Text(error.orEmpty(), color = MaterialTheme.colorScheme.error)
            Text("TLS or WebSocket readiness does not prove OpenVPN authentication or VPN data. No VPN credentials are sent.",
                style = MaterialTheme.typography.bodySmall)
        }
    }
}
