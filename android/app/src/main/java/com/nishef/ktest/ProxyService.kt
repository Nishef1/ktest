package com.nishef.ktest

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.Service
import android.content.Context
import android.content.Intent
import android.os.IBinder
import android.os.SystemClock
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.launch
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeout
import mobilebridge.Mobilebridge
import org.json.JSONObject
import java.io.File

/**
 * Android lifecycle adapter for the existing Go proxy.
 * No transport, Tor, VPN or routing policy lives in this Kotlin service.
 */
class ProxyService : Service() {
    companion object {
        const val ACTION_CONNECT = "com.nishef.ktest.CONNECT"
        const val ACTION_STOP = "com.nishef.ktest.DISCONNECT"
        const val EXTRA_MODE = "mode"
        const val EXTRA_UPSTREAM = "upstream"
        const val EXTRA_METHOD = "method"
        const val EXTRA_TITLE = "title"
        const val EXTRA_VPN = "vpn"
        private const val CHANNEL = "ktest_proxy"
        private const val NOTIFICATION_ID = 42
        @Volatile var lastError: String? = null
        /** SystemClock.elapsedRealtime() when the current session became active; 0 otherwise. */
        @Volatile var connectedAt: Long = 0

        /** Shared by normal startup and the offline test; never changes Android trust. */
        internal fun checkedFrontingOptIn(context: Context, privateDir: String): Boolean {
            val enabled = context.getSharedPreferences("ktest_android", Context.MODE_PRIVATE)
                .getBoolean("fronting_opt_in", false)
            if (enabled && LocalCaTrust.inspect(privateDir).state != "installed_user") {
                error("Fronting is enabled but the exact KTest CA is not installed. Check the CA in Settings or disable fronting.")
            }
            return enabled
        }
    }

    private val worker = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    private val mutex = Mutex()
    private var startup: Job? = null
    @Volatile private var wanted = false
    @Volatile private var stopping = false

    override fun onBind(intent: Intent?): IBinder? = null

    override fun onCreate() {
        super.onCreate()
        getSystemService(NotificationManager::class.java).createNotificationChannel(
            NotificationChannel(CHANNEL, "Local proxy status", NotificationManager.IMPORTANCE_LOW)
        )
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_CONNECT -> {
                if (wanted || stopping) return START_NOT_STICKY
                val mode = intent.getStringExtra(EXTRA_MODE) ?: "balanced"
                val upstream = intent.getStringExtra(EXTRA_UPSTREAM).orEmpty()
                val method = intent.getStringExtra(EXTRA_METHOD) ?: "auto"
                val title = intent.getStringExtra(EXTRA_TITLE) ?: mode.replaceFirstChar { it.uppercase() }
                val vpn = intent.getBooleanExtra(EXTRA_VPN, false)
                wanted = true
                lastError = null
                connectedAt = 0
                startForeground(NOTIFICATION_ID, notification(title))
                startup = worker.launch {
                    try {
                        mutex.withLock {
                            if (wanted) {
                                if (mode in listOf("aether", "tor", "psiphon") &&
                                    (mode != "aether" || upstream.isBlank())) {
                                    Mobilebridge.startNativeProxy(mode, method,
                                        applicationInfo.nativeLibraryDir,
                                        File(filesDir, "aether").absolutePath)
                                } else if (mode == "balanced" || mode == "fast") {
                                    val privateDir = filesDir.canonicalPath
                                    val enabled = checkedFrontingOptIn(this@ProxyService, privateDir)
                                    if (enabled) {
                                        // The user must explicitly opt in, and the exact CA must
                                        // still be in Android's user store at *each* session start.
                                        // App-specific pinning can still prevent this takeover.
                                        Mobilebridge.startAndroidProxyWithFronting(mode, upstream,
                                            applicationInfo.nativeLibraryDir, privateDir)
                                    } else {
                                        Mobilebridge.startAndroidProxyWithXray(mode, upstream,
                                            applicationInfo.nativeLibraryDir, privateDir)
                                    }
                                } else {
                                    Mobilebridge.startProxyWithUpstream(mode, upstream)
                                }
                            }
                        }
                        if (wanted) {
                            // A live local proxy does not prove a device-wide VPN. Wait
                            // until VpnService actually establishes HEV and attaches its
                            // TUN fd; fail instead of claiming whole-device coverage.
                            if (vpn) {
                                withContext(Dispatchers.Main) { startVpn() }
                                withTimeout(20_000L) {
                                    while (wanted && isActive) {
                                        when (KTestVpnService.state) {
                                            "tun_running_unverified" -> break
                                            "failed", "revoked" -> error(
                                                KTestVpnService.lastError ?: "Android VPN did not start"
                                            )
                                        }
                                        delay(250)
                                    }
                                }
                            }
                            if (!wanted) error("Connection stopped during VPN startup")
                            connectedAt = SystemClock.elapsedRealtime()
                            getSystemService(NotificationManager::class.java)
                                .notify(NOTIFICATION_ID, notification(title, true))
                        }
                        while (wanted && isActive) {
                            val status = JSONObject(Mobilebridge.proxyStatus())
                            if (!status.optBoolean("running")) {
                                lastError = status.optString("error", "Connection stopped")
                                wanted = false
                                break
                            }
                            if (vpn && KTestVpnService.state != "tun_running_unverified") {
                                lastError = KTestVpnService.lastError ?: "Android VPN stopped after startup"
                                wanted = false
                                break
                            }
                            delay(1000)
                        }
                    } catch (_: CancellationException) {
                        // A user-initiated stop is not a connection failure.
                    } catch (e: Exception) {
                        if (wanted) lastError = e.message ?: "Could not start connection"
                        wanted = false
                    } finally {
                        if (!wanted) {
                            connectedAt = 0
                            withContext(NonCancellable + Dispatchers.Main) { stopVpn() }
                            withContext(NonCancellable + Dispatchers.IO) {
                                mutex.withLock { Mobilebridge.stopProxy() }
                                withContext(Dispatchers.Main) {
                                    stopForeground(STOP_FOREGROUND_REMOVE)
                                    stopSelfResult(startId)
                                }
                            }
                        }
                    }
                }
            }
            ACTION_STOP -> {
                wanted = false
                connectedAt = 0
                stopVpn()
                stopping = true
                startup?.cancel()
                // Invalidate a blocked/slow Go startup immediately.
                Mobilebridge.cancelProxyStart()
                worker.launch {
                    mutex.withLock { Mobilebridge.stopProxy() }
                    withContext(Dispatchers.Main) {
                        stopForeground(STOP_FOREGROUND_REMOVE)
                        stopping = false
                        stopSelfResult(startId)
                    }
                }
            }
            else -> stopSelf()
        }
        return START_NOT_STICKY
    }

    override fun onDestroy() {
        wanted = false
        connectedAt = 0
        stopVpn()
        startup?.cancel()
        Mobilebridge.cancelProxyStart()
        worker.launch(NonCancellable) {
            mutex.withLock { Mobilebridge.stopProxy() }
        }
        worker.cancel()
        super.onDestroy()
    }

    private fun startVpn() {
        // Errors must propagate to the active connection, not leave the UI
        // showing a functioning device VPN when only local SOCKS is live.
        startForegroundService(Intent(this, KTestVpnService::class.java).apply {
            action = KTestVpnService.ACTION_START
        })
    }

    private fun stopVpn() {
        if (KTestVpnService.state == "disconnected") return
        runCatching {
            startService(Intent(this, KTestVpnService::class.java).apply { action = KTestVpnService.ACTION_STOP })
        }
    }

    private fun notification(title: String, active: Boolean = false): Notification {
        val open = PendingIntent.getActivity(
            this, 1, Intent(this, MainActivity::class.java)
                .addFlags(Intent.FLAG_ACTIVITY_SINGLE_TOP or Intent.FLAG_ACTIVITY_CLEAR_TOP),
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )
        val stop = PendingIntent.getService(
            this, 2, Intent(this, ProxyService::class.java).apply { action = ACTION_STOP },
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )
        return Notification.Builder(this, CHANNEL)
            .setSmallIcon(R.drawable.ic_stat_ktest)
            .setColor(0xFF5EF2C4.toInt())
            .setContentTitle(if (active) "Connected · $title" else "Connecting · $title")
            .setContentText(if (active) "Local proxy active for apps you configure" else "Starting and verifying the route…")
            .setShowWhen(active)
            .setUsesChronometer(active)
            .setWhen(System.currentTimeMillis())
            .setContentIntent(open)
            .setOngoing(true)
            .setCategory(Notification.CATEGORY_SERVICE)
            .addAction(Notification.Action.Builder(null, if (active) "Disconnect" else "Cancel", stop).build())
            .build()
    }
}
