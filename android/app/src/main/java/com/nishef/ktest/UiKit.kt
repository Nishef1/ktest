package com.nishef.ktest

import androidx.compose.animation.animateColorAsState
import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material3.*
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.unit.Dp
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp

// One dark palette: the app is used at night, on OLED phones, often outdoors.
internal object K {
    val bg = Color(0xFF05080C)
    val bgGlow = Color(0xFF0B1A24)
    val surface = Color(0xFF0D151D)
    val surfaceHigh = Color(0xFF142029)
    val stroke = Color(0xFF1C2A36)
    val strokeStrong = Color(0xFF2A3B4A)
    val text = Color(0xFFEEF3F6)
    val muted = Color(0xFF8C9DAB)
    val faint = Color(0xFF5A6A78)
    val mint = Color(0xFF5EF2C4)
    val cyan = Color(0xFF3FC2F5)
    val amber = Color(0xFFFFC27A)
    val red = Color(0xFFFF8F84)
    val accentBrush = Brush.linearGradient(listOf(mint, cyan))
    val mono = FontFamily.Monospace
}

@Composable
internal fun KTheme(content: @Composable () -> Unit) {
    MaterialTheme(
        colorScheme = darkColorScheme(
            background = K.bg, surface = K.surface, primary = K.mint, onPrimary = K.bg,
            onBackground = K.text, onSurface = K.text, secondary = K.cyan, onSecondary = K.bg,
            secondaryContainer = K.surfaceHigh, onSecondaryContainer = K.text, tertiary = K.mint,
            outline = K.strokeStrong, outlineVariant = K.stroke, surfaceVariant = K.surfaceHigh,
            onSurfaceVariant = K.muted, error = K.red, surfaceContainer = K.surface,
            surfaceContainerHigh = K.surfaceHigh, surfaceContainerHighest = K.surfaceHigh,
            surfaceContainerLow = K.surface, surfaceContainerLowest = K.bg
        ),
        typography = Typography(
            bodyMedium = TextStyle(fontSize = 14.sp, lineHeight = 20.sp),
            bodySmall = TextStyle(fontSize = 12.sp, lineHeight = 17.sp, color = K.muted)
        ),
        content = content
    )
}

@Composable
internal fun Panel(
    modifier: Modifier = Modifier,
    padding: Dp = 18.dp,
    onClick: (() -> Unit)? = null,
    content: @Composable ColumnScope.() -> Unit
) {
    val shape = RoundedCornerShape(24.dp)
    Column(
        modifier.fillMaxWidth().clip(shape).background(K.surface)
            .border(1.dp, K.stroke, shape)
            .then(if (onClick != null) Modifier.clickable(role = Role.Button, onClick = onClick) else Modifier)
            .padding(padding),
        verticalArrangement = Arrangement.spacedBy(12.dp),
        content = content
    )
}

@Composable
internal fun SectionLabel(text: String, color: Color = K.mint) {
    Text(text.uppercase(), color = color, fontSize = 11.sp, letterSpacing = 1.4.sp,
        fontWeight = FontWeight.Bold)
}

@Composable
internal fun ScreenTitle(title: String, subtitle: String) {
    Column(verticalArrangement = Arrangement.spacedBy(4.dp)) {
        Text(title, color = K.text, fontSize = 28.sp, fontWeight = FontWeight.SemiBold,
            letterSpacing = (-0.5).sp)
        Text(subtitle, color = K.muted, fontSize = 13.sp, lineHeight = 18.sp)
    }
}

@Composable
internal fun IconTile(icon: ImageVector, tint: Color = K.mint, size: Dp = 40.dp) {
    Box(
        Modifier.size(size).clip(RoundedCornerShape(size * 0.32f))
            .background(tint.copy(alpha = .12f)),
        contentAlignment = Alignment.Center
    ) { Icon(icon, null, tint = tint, modifier = Modifier.size(size * 0.52f)) }
}

@Composable
internal fun StatusPill(text: String, color: Color, modifier: Modifier = Modifier) {
    Row(
        modifier.clip(CircleShape).background(color.copy(alpha = .12f))
            .border(1.dp, color.copy(alpha = .25f), CircleShape)
            .padding(horizontal = 11.dp, vertical = 6.dp),
        verticalAlignment = Alignment.CenterVertically
    ) {
        Box(Modifier.size(7.dp).background(color, CircleShape))
        Spacer(Modifier.width(7.dp))
        Text(text, color = color, fontSize = 11.sp, fontWeight = FontWeight.SemiBold,
            letterSpacing = 0.4.sp)
    }
}

@Composable
internal fun Tag(text: String, color: Color = K.muted) {
    Text(text, color = color, fontSize = 11.sp, fontWeight = FontWeight.Medium,
        modifier = Modifier.clip(RoundedCornerShape(8.dp)).background(color.copy(alpha = .1f))
            .padding(horizontal = 8.dp, vertical = 4.dp))
}

@Composable
internal fun PrimaryButton(
    text: String, onClick: () -> Unit, modifier: Modifier = Modifier,
    enabled: Boolean = true, busy: Boolean = false
) {
    val shape = RoundedCornerShape(16.dp)
    Box(
        modifier.fillMaxWidth().height(50.dp).clip(shape)
            .background(if (enabled && !busy) K.accentBrush else Brush.linearGradient(listOf(K.surfaceHigh, K.surfaceHigh)))
            .clickable(enabled = enabled && !busy, role = Role.Button, onClick = onClick),
        contentAlignment = Alignment.Center
    ) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            if (busy) {
                CircularProgressIndicator(Modifier.size(16.dp), color = K.mint, strokeWidth = 2.dp)
                Spacer(Modifier.width(10.dp))
            }
            Text(text, color = if (enabled && !busy) K.bg else K.muted, fontWeight = FontWeight.SemiBold,
                fontSize = 15.sp)
        }
    }
}

@Composable
internal fun SecondaryButton(
    text: String, onClick: () -> Unit, modifier: Modifier = Modifier,
    enabled: Boolean = true, icon: ImageVector? = null, busy: Boolean = false,
    tint: Color = K.text
) {
    OutlinedButton(
        onClick = onClick, enabled = enabled && !busy, modifier = modifier.heightIn(min = 46.dp),
        shape = RoundedCornerShape(14.dp), border = BorderStroke(1.dp, K.strokeStrong),
        colors = ButtonDefaults.outlinedButtonColors(containerColor = K.surfaceHigh, contentColor = tint,
            disabledContainerColor = K.surface, disabledContentColor = K.faint)
    ) {
        if (busy) {
            CircularProgressIndicator(Modifier.size(15.dp), color = K.mint, strokeWidth = 2.dp)
            Spacer(Modifier.width(9.dp))
        } else if (icon != null) {
            Icon(icon, null, Modifier.size(17.dp))
            Spacer(Modifier.width(8.dp))
        }
        Text(text, fontWeight = FontWeight.Medium, fontSize = 14.sp)
    }
}

@Composable
internal fun KField(
    value: String, onValueChange: (String) -> Unit, label: String,
    modifier: Modifier = Modifier, enabled: Boolean = true, singleLine: Boolean = true,
    keyboardType: KeyboardType = KeyboardType.Text, mono: Boolean = false,
    supporting: String? = null, minLines: Int = 1
) {
    OutlinedTextField(
        value = value, onValueChange = onValueChange, enabled = enabled,
        singleLine = singleLine, minLines = minLines,
        label = { Text(label) }, modifier = modifier.fillMaxWidth(),
        shape = RoundedCornerShape(14.dp),
        textStyle = TextStyle(fontSize = 14.sp, fontFamily = if (mono) K.mono else FontFamily.Default),
        keyboardOptions = KeyboardOptions(keyboardType = keyboardType, autoCorrectEnabled = false),
        supportingText = supporting?.let { { Text(it, fontSize = 11.sp) } },
        colors = OutlinedTextFieldDefaults.colors(
            focusedBorderColor = K.mint, unfocusedBorderColor = K.stroke,
            disabledBorderColor = K.stroke, focusedLabelColor = K.mint,
            unfocusedLabelColor = K.muted, focusedTextColor = K.text, unfocusedTextColor = K.text,
            disabledTextColor = K.muted, cursorColor = K.mint,
            focusedContainerColor = K.bg, unfocusedContainerColor = K.bg, disabledContainerColor = K.bg
        )
    )
}

/** Compact single-choice control for 2–4 short options. */
@Composable
internal fun Segmented(
    options: List<Pair<String, String>>, selected: String, onSelect: (String) -> Unit,
    enabled: Boolean = true
) {
    val shape = RoundedCornerShape(14.dp)
    Row(
        Modifier.fillMaxWidth().clip(shape).background(K.bg).border(1.dp, K.stroke, shape).padding(4.dp),
        horizontalArrangement = Arrangement.spacedBy(4.dp)
    ) {
        for ((value, label) in options) {
            val active = value == selected
            val bg by animateColorAsState(if (active) K.surfaceHigh else Color.Transparent, label = "seg")
            Box(
                Modifier.weight(1f).clip(RoundedCornerShape(10.dp)).background(bg)
                    .then(if (active) Modifier.border(1.dp, K.strokeStrong, RoundedCornerShape(10.dp)) else Modifier)
                    .clickable(enabled = enabled, role = Role.RadioButton) { onSelect(value) }
                    .padding(vertical = 9.dp),
                contentAlignment = Alignment.Center
            ) {
                Text(label, fontSize = 13.sp, maxLines = 1,
                    fontWeight = if (active) FontWeight.SemiBold else FontWeight.Normal,
                    color = when { !enabled -> K.faint; active -> K.mint; else -> K.muted })
            }
        }
    }
}

internal enum class Tone { Info, Warn, Danger, Good }

@Composable
internal fun Note(text: String, tone: Tone = Tone.Info, modifier: Modifier = Modifier) {
    val color = when (tone) { Tone.Info -> K.muted; Tone.Warn -> K.amber; Tone.Danger -> K.red; Tone.Good -> K.mint }
    val icon = when (tone) { Tone.Info -> KIcons.Info; Tone.Warn, Tone.Danger -> KIcons.Warning; Tone.Good -> KIcons.Check }
    Row(modifier.fillMaxWidth(), verticalAlignment = Alignment.Top) {
        Icon(icon, null, tint = color, modifier = Modifier.padding(top = 1.dp).size(14.dp))
        Spacer(Modifier.width(8.dp))
        Text(text, color = if (tone == Tone.Info) K.muted else color, fontSize = 12.sp, lineHeight = 17.sp)
    }
}

@Composable
internal fun Banner(text: String, tone: Tone, onDismiss: (() -> Unit)? = null) {
    val color = if (tone == Tone.Danger) K.red else if (tone == Tone.Warn) K.amber else K.mint
    val shape = RoundedCornerShape(18.dp)
    Row(
        Modifier.fillMaxWidth().clip(shape).background(color.copy(alpha = .09f))
            .border(1.dp, color.copy(alpha = .28f), shape).padding(start = 14.dp, top = 12.dp, bottom = 12.dp, end = 6.dp),
        verticalAlignment = Alignment.Top
    ) {
        Icon(KIcons.Warning, null, tint = color, modifier = Modifier.padding(top = 1.dp).size(18.dp))
        Spacer(Modifier.width(10.dp))
        Text(text, color = K.text, fontSize = 13.sp, lineHeight = 18.sp, modifier = Modifier.weight(1f).padding(top = 1.dp))
        if (onDismiss != null) IconButton(onClick = onDismiss, modifier = Modifier.size(28.dp)) {
            Icon(KIcons.Close, "Dismiss", tint = K.muted, modifier = Modifier.size(16.dp))
        }
    }
}

@Composable
internal fun KeyValue(label: String, value: String, valueColor: Color = K.text, mono: Boolean = false) {
    Row(Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically) {
        Text(label, color = K.muted, fontSize = 13.sp, modifier = Modifier.weight(1f))
        Text(value, color = valueColor, fontSize = 13.sp, fontWeight = FontWeight.Medium,
            fontFamily = if (mono) K.mono else FontFamily.Default)
    }
}

/** Ok/fail/neutral result badge for diagnostic stages. */
@Composable
internal fun ResultBadge(ok: Boolean?, text: String) {
    val color = when (ok) { true -> K.mint; false -> K.amber; null -> K.faint }
    Tag(text, color)
}

@Composable
internal fun Hairline() = HorizontalDivider(color = K.stroke, thickness = 1.dp)

internal fun formatDuration(seconds: Long): String {
    val h = seconds / 3600
    val m = (seconds % 3600) / 60
    val s = seconds % 60
    return if (h > 0) "%d:%02d:%02d".format(h, m, s) else "%02d:%02d".format(m, s)
}
