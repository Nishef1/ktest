package com.nishef.ktest

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.selection.SelectionContainer
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Switch
import androidx.compose.material3.SwitchDefaults
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import mobilebridge.Mobilebridge
import org.json.JSONObject

internal class RouteTargetsState {
    var report by mutableStateOf<JSONObject?>(null)
    var loading by mutableStateOf(false)
    var busy by mutableStateOf(false)
    var error by mutableStateOf<String?>(null)
    var message by mutableStateOf<String?>(null)
    var editing by mutableStateOf(false)
    var editId by mutableStateOf("")
    var name by mutableStateOf("")
    var url by mutableStateOf("")
    var fronting by mutableStateOf(false)
    var deleteTarget by mutableStateOf<JSONObject?>(null)
    var refresh by mutableIntStateOf(0)

    fun edit(target: JSONObject? = null) {
        editId = target?.optString("id").orEmpty()
        name = target?.optString("name").orEmpty()
        url = target?.optString("url").orEmpty()
        fronting = target?.optBoolean("fronting") == true
        editing = true
        error = null
        message = null
    }
}

@Composable
internal fun RouteTargetsPanel(
    s: RouteTargetsState, scope: CoroutineScope, privateDir: String,
    editable: Boolean, caFingerprint: String, onChanged: () -> Unit
) {
    LaunchedEffect(privateDir, editable, caFingerprint, s.refresh) {
        s.loading = true
        try {
            s.report = withContext(Dispatchers.IO) { JSONObject(Mobilebridge.routeTargets(privateDir)) }
            s.error = null
        } catch (e: CancellationException) {
            throw e
        } catch (e: Exception) {
            s.error = e.message ?: "Could not read route targets"
        } finally {
            s.loading = false
        }
    }
    val canEdit = editable && !s.busy && !s.loading
    fun mutate(work: () -> String, message: String) {
        if (!canEdit) return
        s.busy = true
        s.error = null
        s.message = null
        scope.launch {
            try {
                s.report = withContext(Dispatchers.IO) { JSONObject(work()) }
                s.editing = false
                s.deleteTarget = null
                s.message = message
                onChanged()
            } catch (e: CancellationException) {
                throw e
            } catch (e: Exception) {
                s.error = e.message ?: "Could not update route targets"
            } finally {
                s.busy = false
            }
        }
    }
    Panel {
        SectionLabel("Balanced / Fast targets")
        Text("Custom HTTPS destinations", color = K.text, fontSize = 16.sp, fontWeight = FontWeight.SemiBold)
        Note("Targets define calibration requests and exact-host fronting preferences. Edit while offline, then run Test before reconnecting. The saved route stays fixed during a connection.")
        if (!editable) Note("Disconnect and finish any startup or manual test before adding, editing or removing targets.", Tone.Warn)
        Row(horizontalArrangement = Arrangement.spacedBy(10.dp)) {
            SecondaryButton("Add target", { s.edit() }, Modifier.weight(1f), enabled = canEdit)
            SecondaryButton("Refresh", { s.refresh++ }, Modifier.weight(1f), enabled = !s.busy, busy = s.loading)
        }
        s.error?.let { Note(it, Tone.Warn) }
        s.message?.let { Note(it) }
        if (s.editing) {
            Column(Modifier.fillMaxWidth().clip(RoundedCornerShape(14.dp)).background(K.bg).padding(14.dp),
                verticalArrangement = Arrangement.spacedBy(12.dp)) {
                Text(if (s.editId.isBlank()) "Add target" else "Edit target", color = K.text,
                    fontSize = 14.sp, fontWeight = FontWeight.SemiBold)
                KField(s.name, { s.name = it }, "Name", enabled = canEdit)
                KField(s.url, { s.url = it }, "HTTPS URL", enabled = canEdit,
                    keyboardType = KeyboardType.Uri, singleLine = false, minLines = 2,
                    supporting = "No credentials or fragments. This path is used only by the test.")
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Text("Request optional fronting for this exact host", modifier = Modifier.weight(1f),
                        color = K.text, fontSize = 13.sp)
                    Switch(s.fronting, { s.fronting = it }, enabled = canEdit,
                        colors = SwitchDefaults.colors(checkedThumbColor = K.bg, checkedTrackColor = K.mint,
                            uncheckedThumbColor = K.muted, uncheckedTrackColor = K.surfaceHigh,
                            uncheckedBorderColor = K.strokeStrong))
                }
                Note("This preference does not enable arbitrary fronting. It requires an existing supported family on port 443, coverage by the current CA, the exact manually installed CA, and the separate fronting opt-in. Saving never expands or regenerates the CA.")
                PrimaryButton("Save target", {
                    val id = s.editId
                    val name = s.name.trim()
                    val url = s.url.trim()
                    val fronting = s.fronting
                    mutate({ Mobilebridge.saveRouteTarget(privateDir, id, name, url, fronting) },
                        "Target saved. Run Test while offline to update the route profile.")
                }, enabled = canEdit && s.name.isNotBlank() && s.url.isNotBlank(), busy = s.busy)
                SecondaryButton("Cancel editing", { s.editing = false }, Modifier.fillMaxWidth(), enabled = !s.busy)
            }
        }
        val targets = s.report?.optJSONArray("targets")
        if (targets != null && targets.length() == 0) Note("No targets configured. Add at least one before testing or connecting.", Tone.Warn)
        if (targets != null) for (i in 0 until targets.length()) {
            val target = targets.optJSONObject(i) ?: continue
            Column(Modifier.fillMaxWidth().clip(RoundedCornerShape(14.dp)).background(K.bg).padding(14.dp),
                verticalArrangement = Arrangement.spacedBy(8.dp)) {
                Text(target.optString("name"), color = K.text, fontSize = 14.sp, fontWeight = FontWeight.Medium)
                SelectionContainer {
                    Text(target.optString("url"), modifier = Modifier.fillMaxWidth(), color = K.muted,
                        fontSize = 12.sp, lineHeight = 17.sp)
                }
                Text("Family: ${target.optString("family").ifBlank { "unsupported" }} · " +
                    "Fronting preference: ${if (target.optBoolean("fronting")) "requested" else "off"}",
                    color = K.muted, fontSize = 12.sp)
                Text(if (target.optBoolean("ca_covered")) "Current CA covers this hostname · app trust checked separately"
                    else "Current CA does not cover this hostname · ordinary HTTPS diagnostics remain available",
                    color = if (target.optBoolean("ca_covered")) K.muted else K.amber, fontSize = 12.sp, lineHeight = 17.sp)
                if (!target.optBoolean("supported")) Text("Fronting unsupported for this host or port",
                    color = K.amber, fontSize = 12.sp)
                target.optString("note").takeIf { it.isNotBlank() }?.let { Note(it) }
                Row(horizontalArrangement = Arrangement.spacedBy(10.dp)) {
                    SecondaryButton("Edit", { s.edit(target) }, Modifier.weight(1f), enabled = canEdit)
                    SecondaryButton("Remove", { s.deleteTarget = target }, Modifier.weight(1f), enabled = canEdit, tint = K.amber)
                }
            }
        }
        s.report?.optString("revision")?.takeIf { it.isNotBlank() }?.let {
            Text("Target revision: ${it.take(12)}", color = K.faint, fontSize = 11.sp, fontFamily = K.mono)
        }
        s.report?.optString("note")?.takeIf { it.isNotBlank() }?.let { Note(it) }
    }
    s.deleteTarget?.let { target ->
        AlertDialog(
            onDismissRequest = { if (!s.busy) s.deleteTarget = null },
            containerColor = K.surface,
            title = { Text("Remove ${target.optString("name")}?", color = K.text) },
            text = { Text("Remove this target from calibration and its exact-host fronting preferences? The CA and protected-domain rules remain in force.", color = K.muted) },
            confirmButton = {
                TextButton(onClick = {
                    val id = target.optString("id")
                    mutate({ Mobilebridge.deleteRouteTarget(privateDir, id) }, "Target removed. Run Test while offline before reconnecting.")
                }, enabled = canEdit) { Text("Remove", color = if (canEdit) K.amber else K.faint) }
            },
            dismissButton = {
                TextButton(onClick = { s.deleteTarget = null }, enabled = !s.busy) { Text("Keep target", color = K.text) }
            }
        )
    }
}
