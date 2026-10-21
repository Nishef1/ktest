package com.nishef.ktest

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.Service
import android.content.Context
import android.content.Intent
import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkCapabilities
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
import kotlinx.coroutines.TimeoutCancellationException
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
        private const val ACTION_RECONNECT = "com.nishef.ktest.RECONNECT_AFTER_NETWORK_CHANGE"
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

        /** Network handles change when Wi-Fi/cellular switches, without exposing SSIDs. */
        internal fun prepareBalancedNetwork(context: Context) {
            val cm = context.getSystemService(android.net.ConnectivityManager::class.java)
            val network = cm.activeNetwork ?: error("No underlying Android network available")
            val caps = cm.getNetworkCapabilities(network)
                ?: error("Android network capabilities are unavailable")
            // Before starting KTest VPN, an existing third-party VPN can be
            // the active network in proxy-only mode. Treat it as a distinct
            // transport instead of forbidding safe layered usage.
            val kind = when {
                caps.hasTransport(android.net.NetworkCapabilities.TRANSPORT_VPN) -> "vpn"
                caps.hasTransport(android.net.NetworkCapabilities.TRANSPORT_WIFI) -> "wifi"
                caps.hasTransport(android.net.NetworkCapabilities.TRANSPORT_CELLULAR) -> "cellular"
                caps.hasTransport(android.net.NetworkCapabilities.TRANSPORT_ETHERNET) -> "ethernet"
                else -> "other"
            }
            Mobilebridge.setRouteNetworkToken("$kind:${network.networkHandle}")
        }

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
    @Volatile private var networkWatch: ConnectivityManager.NetworkCallback? = null
    @Volatile private var networkInvalidated = false
    @Volatile private var activeRequest: Intent? = null
    @Volatile private var pendingReconnect: Intent? = null
    @Volatile private var pendingUnderlyingNetwork: Network? = null
    @Volatile private var reconnectJob: Job? = null
    @Volatile private var reconnectEpoch = 0

    // Reconnect after a network handover to refresh DNS and transport state.
    private fun watchBalancedNetwork(expectedHandle: Long) {
        clearNetworkWatch()
        networkInvalidated = false
        val manager = getSystemService(ConnectivityManager::class.java)
        val cb = object : ConnectivityManager.NetworkCallback() {
            override fun onCapabilitiesChanged(network: Network, capabilities: NetworkCapabilities) {
                // Our own TUN can briefly appear as a new default network on
                // some devices; it is not an underlying Wi-Fi/cellular handover.
                if (capabilities.hasTransport(NetworkCapabilities.TRANSPORT_VPN) &&
                    KTestVpnService.state in setOf("starting", "preparing", "tun_running_unverified", "stopping")) return
                if (network.networkHandle != expectedHandle &&
                    capabilities.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)) {
                    invalidateBalancedNetwork(network)
                }
            }
            override fun onLost(network: Network) {
                if (network.networkHandle != expectedHandle) return
                // onLost can mean "no longer default" rather than physically
                // gone. Check on the service worker, outside the callback.
                worker.launch {
                    delay(350)
                    val stillPresent = manager.allNetworks.any { it.networkHandle == expectedHandle }
                    if (!stillPresent) invalidateBalancedNetwork(null)
                }
            }
        }
        manager.registerDefaultNetworkCallback(cb)
        networkWatch = cb
    }

    /** Debounce network handovers, then rebuild the entire session on the new underlying network. */
    private fun invalidateBalancedNetwork(candidate: Network?) {
        if (!wanted || activeRequest == null) return
        if (candidate != null) {
            val caps = getSystemService(ConnectivityManager::class.java).getNetworkCapabilities(candidate)
                ?: return
            if (!caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)) return
            pendingUnderlyingNetwork = candidate
        }
        networkInvalidated = true
        lastError = "Underlying network changed. KTest is recovering the connection automatically."
        if (reconnectJob?.isActive == true) return
        reconnectJob = worker.launch {
            val manager = getSystemService(ConnectivityManager::class.java)
            val deadline = SystemClock.elapsedRealtime() + 20_000L
            while (wanted && isActive && SystemClock.elapsedRealtime() < deadline) {
                val network = pendingUnderlyingNetwork
                if (network != null) {
                    val caps = manager.getNetworkCapabilities(network)
                    val stillPresent = manager.allNetworks.any { it.networkHandle == network.networkHandle }
                    if (caps != null && stillPresent &&
                        caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)) {
                        delay(700)
                        val stableCaps = manager.getNetworkCapabilities(network)
                        val stable = manager.allNetworks.any { it.networkHandle == network.networkHandle }
                        if (wanted && stable && stableCaps != null &&
                            stableCaps.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)) {
                            val request = activeRequest?.let { Intent(it).apply { action = ACTION_CONNECT } }
                            if (request != null) {
                                pendingReconnect = request
                                startService(Intent(this@ProxyService, ProxyService::class.java).apply {
                                    action = ACTION_RECONNECT
                                })
                            }
                            return@launch
                        }
                    } else {
                        pendingUnderlyingNetwork = null
                    }
                }
                delay(250)
            }
            if (wanted && networkInvalidated) {
                lastError = "No stable replacement internet network appeared within 20 seconds."
                startService(Intent(this@ProxyService, ProxyService::class.java).apply { action = ACTION_STOP })
            }
        }
    }

    private fun clearNetworkWatch() {
        val callback = networkWatch
        networkWatch = null
        if (callback != null) {
            runCatching { getSystemService(ConnectivityManager::class.java).unregisterNetworkCallback(callback) }
        }
    }

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
                reconnectJob?.cancel()
                reconnectJob = null
                pendingReconnect = null
                pendingUnderlyingNetwork = null
                networkInvalidated = false
                activeRequest = Intent(intent)
                wanted = true
                lastError = null
                connectedAt = 0
                startForeground(NOTIFICATION_ID, notification(title))
                startup = worker.launch {
                    try {
                        mutex.withLock {
                            if (wanted) {
                                // The Settings "AI policy" switch, read at each start.
                                Mobilebridge.setAIPolicy(getSharedPreferences("ktest_android", MODE_PRIVATE)
                                    .getBoolean("ai_policy", true))
                                // The F&F and MASQUE SNI settings; a bad saved value falls back to auto.
                                getSharedPreferences("ktest_android", MODE_PRIVATE).let { p ->
                                    runCatching {
                                        Mobilebridge.setAetherTLS(p.getString("aether_fingerprint", "auto"),
                                            p.getString("masque_sni", "auto"), p.getString("aether_fragment", "auto"))
                                    }.onFailure { Mobilebridge.setAetherTLS("auto", "auto", "auto") }
                                }
                                if (mode in listOf("aether", "tor", "psiphon") &&
                                    (mode != "aether" || upstream.isBlank())) {
                                    // Psiphon and Tor need no WARP: by default they dial out
                                    // through Fast's local anti-DPI carrier.
                                    val prefs = getSharedPreferences("ktest_android", MODE_PRIVATE)
                                    val viaFast = if (mode == "aether") prefs.getBoolean("aether_via_fast", false)
                                        else prefs.getBoolean("native_via_fast", true)
                                    if (viaFast) Mobilebridge.startNativeModeViaFast(mode, method,
                                        applicationInfo.nativeLibraryDir,
                                        File(filesDir, "aether").absolutePath, filesDir.canonicalPath)
                                    else Mobilebridge.startNativeProxy(mode, method,
                                        applicationInfo.nativeLibraryDir,
                                        File(filesDir, "aether").absolutePath)
                                } else if (mode == "balanced" || mode == "fast") {
                                    val privateDir = filesDir.canonicalPath
                                    prepareBalancedNetwork(this@ProxyService)
                                    val net = getSystemService(ConnectivityManager::class.java).activeNetwork
                                        ?: error("Underlying network disappeared before connection")
                                    watchBalancedNetwork(net.networkHandle)
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
                                // Clear a previous session's failed/revoked state first, or the
                                // wait loop below can read it before the new start runs.
                                KTestVpnService.markStarting()
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
                    } catch (e: TimeoutCancellationException) {
                        // withTimeout reports expiry as a cancellation; it is a real failure.
                        if (wanted) lastError = "Android VPN did not start within 20 seconds"
                        wanted = false
                    } catch (_: CancellationException) {
                        // A user-initiated stop is not a connection failure.
                    } catch (e: Exception) {
                        if (wanted) lastError = e.message ?: "Could not start connection"
                        wanted = false
                    } finally {
                        if (!wanted) {
                            clearNetworkWatch()
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
            ACTION_RECONNECT -> {
                val request = pendingReconnect
                if (request == null || stopping) return START_NOT_STICKY
                pendingReconnect = null
                val epoch = ++reconnectEpoch
                clearNetworkWatch()
                reconnectJob?.cancel()
                reconnectJob = null
                wanted = false
                connectedAt = 0
                stopVpn()
                stopping = true
                val oldStartup = startup
                oldStartup?.cancel()
                Mobilebridge.cancelProxyStart()
                worker.launch {
                    // Wait for the canceled session's finally block to finish
                    // before starting another Go session; otherwise stale cleanup
                    // could stop the replacement immediately after it connects.
                    oldStartup?.join()
                    mutex.withLock { Mobilebridge.stopProxy() }
                    var vpnStopped = true
                    if (request.getBooleanExtra(EXTRA_VPN, false)) {
                        try {
                            withTimeout(8_000L) {
                                while (KTestVpnService.state !in setOf("disconnected", "failed", "revoked")) {
                                    delay(100)
                                }
                            }
                        } catch (_: TimeoutCancellationException) {
                            vpnStopped = false
                        }
                    }
                    withContext(Dispatchers.Main) {
                        // A user disconnect or newer session invalidates this restart.
                        if (epoch != reconnectEpoch) {
                            stopping = false
                            stopForeground(STOP_FOREGROUND_REMOVE)
                            stopSelfResult(startId)
                            return@withContext
                        }
                        stopping = false
                        if (vpnStopped) {
                            // Keep the foreground service alive until ACTION_CONNECT
                            // refreshes its notification, avoiding background-start
                            // restrictions during an automatic handover.
                            startForegroundService(request)
                        } else {
                            stopForeground(STOP_FOREGROUND_REMOVE)
                            lastError = "The old VPN did not shut down cleanly; automatic reconnect was stopped."
                            activeRequest = null
                            stopSelfResult(startId)
                        }
                    }
                }
            }
            ACTION_STOP -> {
                val wasVpn = activeRequest?.getBooleanExtra(EXTRA_VPN, false) == true
                reconnectEpoch++
                clearNetworkWatch()
                reconnectJob?.cancel()
                reconnectJob = null
                pendingReconnect = null
                pendingUnderlyingNetwork = null
                networkInvalidated = false
                activeRequest = null
                wanted = false
                connectedAt = 0
                stopVpn()
                stopping = true
                val oldStartup = startup
                oldStartup?.cancel()
                // Invalidate a blocked/slow Go startup immediately.
                Mobilebridge.cancelProxyStart()
                worker.launch {
                    // Do not mark the service ready for a new connect until the
                    // canceled startup has completed its own cleanup.
                    oldStartup?.join()
                    mutex.withLock { Mobilebridge.stopProxy() }
                    var vpnStopped = true
                    if (wasVpn) {
                        try {
                            withTimeout(8_000L) {
                                while (KTestVpnService.state !in setOf("disconnected", "failed", "revoked")) {
                                    delay(100)
                                }
                            }
                        } catch (_: TimeoutCancellationException) {
                            vpnStopped = false
                        }
                    }
                    withContext(Dispatchers.Main) {
                        if (vpnStopped) {
                            stopForeground(STOP_FOREGROUND_REMOVE)
                            stopping = false
                            stopSelfResult(startId)
                        } else {
                            // Fail closed: do not accept another session while
                            // Android may still have the old TUN interface open.
                            lastError = "The old VPN did not shut down cleanly; reconnect is blocked."
                            stopping = true
                            getSystemService(NotificationManager::class.java)
                                .notify(NOTIFICATION_ID, notification("VPN shutdown needs attention"))
                        }
                    }
                }
            }
            else -> stopSelf()
        }
        return START_NOT_STICKY
    }

    override fun onDestroy() {
        clearNetworkWatch()
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
        val underlyingHandle = getSystemService(ConnectivityManager::class.java).activeNetwork?.networkHandle ?: -1L
        startForegroundService(Intent(this, KTestVpnService::class.java).apply {
            action = KTestVpnService.ACTION_START
            putExtra(KTestVpnService.EXTRA_UNDERLYING_NETWORK_HANDLE, underlyingHandle)
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
