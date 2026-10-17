package com.nishef.ktest

import android.content.Intent
import android.net.Uri
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.WindowInsets
import androidx.compose.foundation.layout.asPaddingValues
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.safeDrawing
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.OutlinedTextFieldDefaults
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.darkColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.runtime.CompositionLocalProvider
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.LocalLayoutDirection
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.style.TextDirection
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.unit.LayoutDirection
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import mobilebridge.Mobilebridge
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import org.json.JSONObject

private val ink = Color(0xFF0B141B)
private val panel = Color(0xFF15242D)
private val border = Color(0xFF29404B)
private val mint = Color(0xFF83E0C5)
private val secondary = Color(0xFFA0B3BD)
private val cream = Color(0xFFF3F6F5)
private val caution = Color(0xFFF3C57C)
private val trouble = Color(0xFFFFAFA8)

class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContent {
            MaterialTheme(
                colorScheme = darkColorScheme(
                    background = ink,
                    surface = panel,
                    primary = mint,
                    onPrimary = ink,
                    onBackground = cream,
                    onSurface = cream,
                )
            ) {
                CompositionLocalProvider(LocalLayoutDirection provides LayoutDirection.Rtl) {
                    ConnectionLab()
                }
            }
        }
    }
}

@Composable
private fun ConnectionLab() {
    var section by rememberSaveable { mutableIntStateOf(0) }
    var url by rememberSaveable { mutableStateOf("https://example.com") }
    var working by remember { mutableStateOf(false) }
    var report by remember { mutableStateOf<JSONObject?>(null) }
    var error by remember { mutableStateOf<String?>(null) }
    var checkingUpdate by remember { mutableStateOf(false) }
    var update by remember { mutableStateOf<UpdateInfo?>(null) }
    val scope = rememberCoroutineScope()
    val context = LocalContext.current

    Column(
        modifier = Modifier.fillMaxSize().background(ink)
            .padding(WindowInsets.safeDrawing.asPaddingValues())
    ) {
        Column(
            modifier = Modifier.weight(1f).verticalScroll(rememberScrollState())
                .padding(horizontal = 22.dp, vertical = 26.dp),
            verticalArrangement = Arrangement.spacedBy(18.dp)
        ) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                Text("ktest", color = cream, fontSize = 25.sp, fontWeight = FontWeight.Bold)
                Text("CONNECTION LAB", color = mint, fontSize = 10.sp, letterSpacing = 2.sp)
            }
            if (section == 0) {
                HeaderCard()
                Text("بررسی دسترسی", color = cream, fontSize = 21.sp, fontWeight = FontWeight.SemiBold)
                Text("یک مقصد مشخص را بدون تغییر DNS یا VPN گوشی آزمایش کن.",
                    color = secondary, fontSize = 13.sp)
                CompositionLocalProvider(LocalLayoutDirection provides LayoutDirection.Ltr) {
                    OutlinedTextField(
                        value = url,
                        onValueChange = { url = it },
                        modifier = Modifier.fillMaxWidth(),
                        label = { Text("HTTPS URL") },
                        singleLine = true,
                        textStyle = TextStyle(textDirection = TextDirection.Ltr),
                        keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Uri),
                        colors = OutlinedTextFieldDefaults.colors(
                            focusedBorderColor = mint, unfocusedBorderColor = border,
                            focusedTextColor = cream, unfocusedTextColor = cream,
                            focusedLabelColor = mint, unfocusedLabelColor = secondary
                        ),
                        shape = RoundedCornerShape(16.dp)
                    )
                }
                Button(
                    enabled = !working && url.isNotBlank(),
                    onClick = {
                        working = true
                        report = null
                        error = null
                        scope.launch {
                            try {
                                val json = withContext(Dispatchers.IO) {
                                    Mobilebridge.diagnose(url.trim())
                                }
                                report = JSONObject(json)
                            } catch (e: Exception) {
                                error = e.message ?: "آزمایش انجام نشد."
                            } finally {
                                working = false
                            }
                        }
                    },
                    modifier = Modifier.fillMaxWidth().height(54.dp),
                    colors = ButtonDefaults.buttonColors(containerColor = mint, contentColor = ink),
                    shape = RoundedCornerShape(18.dp)
                ) {
                    Text(if (working) "در حال بررسی..." else "شروع آزمایش",
                        fontWeight = FontWeight.Bold, fontSize = 15.sp)
                }
                Text("نتیجه فقط برای مسیر پیش‌فرض سیستم است؛ در صورت فعال بودن VPN ممکن است از آن عبور کند.",
                    color = secondary, fontSize = 12.sp)
                if (error != null) {
                    Surface(color = panel, shape = RoundedCornerShape(18.dp)) {
                        Text(error.orEmpty(), color = trouble, modifier = Modifier.padding(16.dp))
                    }
                }
                if (report != null) {
                    val data = report!!
                    Text("نتایج واقعی", color = cream, fontSize = 20.sp, fontWeight = FontWeight.SemiBold)
                    StageRow("DNS", data.optString("dns_status", "not_run"))
                    StageRow("TCP", data.optString("tcp_status", "not_run"))
                    StageRow("TLS", data.optString("tls_status", "not_run"))
                    Surface(color = panel, shape = RoundedCornerShape(18.dp)) {
                        Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(6.dp)) {
                            Text("خلاصه", color = mint, fontSize = 12.sp)
                            Text(data.optString("outcome", "unknown"), color = cream,
                                fontWeight = FontWeight.Medium)
                            Text("زمان کل: ${data.optLong("total_duration_ms")} میلی‌ثانیه",
                                color = secondary, fontSize = 12.sp)
                            Text("TCP موفق یا TLS موفق، به‌تنهایی به معنی VPN فعال نیست.",
                                color = secondary, fontSize = 12.sp)
                        }
                    }
                }
            } else {
                Text("تنظیمات", color = cream, fontSize = 24.sp, fontWeight = FontWeight.Bold)
                Surface(color = panel, shape = RoundedCornerShape(23.dp)) {
                    Column(Modifier.padding(19.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
                        Text("به‌روزرسانی برنامه", color = cream, fontSize = 18.sp, fontWeight = FontWeight.SemiBold)
                        Text("نسخهٔ ${BuildConfig.VERSION_NAME} • بررسی دستی فایل‌های APK رسمی GitHub",
                            color = secondary, fontSize = 12.sp)
                        Button(
                            enabled = !checkingUpdate,
                            onClick = {
                                checkingUpdate = true
                                update = null
                                scope.launch {
                                    update = try {
                                        withContext(Dispatchers.IO) { UpdateChecker.check() }
                                    } catch (e: Exception) {
                                        UpdateInfo("به GitHub دسترسی پیدا نشد. اتصال را بررسی کن.")
                                    }
                                    checkingUpdate = false
                                }
                            },
                            colors = ButtonDefaults.buttonColors(containerColor = mint, contentColor = ink),
                            shape = RoundedCornerShape(14.dp)
                        ) { Text(if (checkingUpdate) "در حال بررسی..." else "بررسی نسخهٔ جدید") }
                        if (update != null) {
                            Text(update!!.message, color = cream, fontSize = 13.sp)
                            if (update!!.downloadUrl != null) {
                                TextButton(onClick = {
                                    context.startActivity(
                                        Intent(Intent.ACTION_VIEW, Uri.parse(update!!.downloadUrl))
                                    )
                                }) { Text("دریافت از صفحهٔ انتشار رسمی", color = mint) }
                            }
                        }
                        Text("آپدیت خودکار یا نصب بی‌اجازه انجام نمی‌شود.",
                            color = secondary, fontSize = 12.sp)
                    }
                }
                Surface(color = panel, shape = RoundedCornerShape(23.dp)) {
                    Column(Modifier.padding(19.dp), verticalArrangement = Arrangement.spacedBy(10.dp)) {
                        Text("هستهٔ اتصال", color = cream, fontSize = 18.sp, fontWeight = FontWeight.SemiBold)
                        Text("Go: فعال برای آزمایش‌های DNS / TCP / TLS", color = mint, fontSize = 13.sp)
                        Text("Proxy و VPN: هنوز فعال نشده‌اند؛ اول باید امنیت مسیر کامل تأیید شود.",
                            color = secondary, fontSize = 13.sp)
                        Text("قابلیت‌های اختیاری MITM و CA در کد اصلی نگهداری می‌شوند؛ این نسخه درخواست نصب گواهی نمی‌کند.",
                            color = secondary, fontSize = 12.sp)
                    }
                }
            }
        }
        Row(
            modifier = Modifier.fillMaxWidth().background(panel).padding(6.dp),
            horizontalArrangement = Arrangement.SpaceEvenly
        ) {
            TextButton(onClick = { section = 0 }) {
                Text("خانه", color = if (section == 0) mint else secondary,
                    fontWeight = if (section == 0) FontWeight.Bold else FontWeight.Normal)
            }
            TextButton(onClick = { section = 1 }) {
                Text("تنظیمات", color = if (section == 1) mint else secondary,
                    fontWeight = if (section == 1) FontWeight.Bold else FontWeight.Normal)
            }
        }
    }
}

@Composable
private fun HeaderCard() {
    Surface(color = panel, shape = RoundedCornerShape(27.dp), modifier = Modifier.fillMaxWidth()) {
        Column(Modifier.padding(23.dp), verticalArrangement = Arrangement.spacedBy(13.dp)) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Box(Modifier.size(9.dp).background(mint, CircleShape))
                Spacer(Modifier.size(9.dp))
                Text("RESEARCH MODE", color = mint, fontSize = 11.sp, letterSpacing = 1.sp)
            }
            Text("اول واقعیت شبکه را پیدا می‌کنیم.", color = cream,
                fontSize = 25.sp, fontWeight = FontWeight.SemiBold, lineHeight = 34.sp)
            Text("آزمایش دقیق، بدون ادعای اتصال یا تغییر تنظیمات گوشی.",
                color = secondary, fontSize = 13.sp, lineHeight = 21.sp)
        }
    }
}

@Composable
private fun StageRow(name: String, status: String) {
    val successful = status == "ok"
    val color = when (status) {
        "ok" -> mint
        "failed" -> trouble
        else -> caution
    }
    Surface(color = panel, shape = RoundedCornerShape(17.dp)) {
        Row(
            Modifier.fillMaxWidth().padding(horizontal = 17.dp, vertical = 15.dp),
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.SpaceBetween
        ) {
            Text(name, color = cream, fontWeight = FontWeight.SemiBold)
            Row(verticalAlignment = Alignment.CenterVertically) {
                Box(Modifier.size(8.dp).background(color, CircleShape))
                Spacer(Modifier.size(8.dp))
                Text(
                    if (successful) "موفق" else if (status == "failed") "ناموفق" else status,
                    color = color, fontSize = 12.sp
                )
            }
        }
    }
}
