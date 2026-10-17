package com.nishef.ktest

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Intent
import android.net.VpnService
import android.os.IBinder
import android.os.ParcelFileDescriptor
import hev.htproxy.TProxyService
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import mobilebridge.Mobilebridge
import org.json.JSONObject
import java.io.File

/**
 * Experimental full-device TUN transport. Requires a *separately running*,
 * independently verified, UDP-capable SOCKS5 engine. This is not an embedded
 * Aether/Psiphon/Tor engine. Runtime remains gated until device validation.
 *
 * Critical: our app UID AND the external SOCKS owner's UID are excluded from
 * VPN routing. Otherwise the upstream sockets can tunnel into themselves.
 */
class KTestVpnService : VpnService() {
    companion object {
        const val ACTION_CONNECT = "com.nishef.ktest.VPN_CONNECT"
        const val ACTION_DISCONNECT = "com.nishef.ktest.VPN_DISCONNECT"
        const val EXTRA_SOCKS = "socks_endpoint"
        const val EXTRA_MODE = "mode"
        const val EXTRA_OWNER = "upstream_owner_package"
        private const val CHANNEL = "ktest_vpn"
        private const val NOTIFICATION = 43

        @Volatile var phase = "idle"
            private set
        @Volatile var detail = ""
            private set
    }

    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    private val mutex = Mutex()
    private var runner: Job? = null
    private var tun: ParcelFileDescriptor? = null
    private var config: File? = null
    @Volatile private var requested = false

    override fun onBind(intent: Intent?): IBinder? = super.onBind(intent)

    override fun onCreate() {
        super.onCreate()
        getSystemService(NotificationManager::class.java).createNotificationChannel(
            NotificationChannel(CHANNEL, "KTest VPN status", NotificationManager.IMPORTANCE_LOW)
        )
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (intent?.action == ACTION_CONNECT) {
            // Foreground notification must be posted before any slow Go probe.
            startForeground(NOTIFICATION, notification("Checking verified upstream"))
            if (requested || phase == "blocking") return START_NOT_STICKY
            requested = true
            phase = "verifying"
            detail = "Checking TCP and UDP through selected external SOCKS5"
            val address = intent.getStringExtra(EXTRA_SOCKS).orEmpty()
            val owner = intent.getStringExtra(EXTRA_OWNER).orEmpty()
            val mode = intent.getStringExtra(EXTRA_MODE).orEmpty()
            runner = scope.launch {
                mutex.withLock {
                    try {
                        require(mode in setOf("balanced", "fast", "aether", "psiphon")) {
                            "This backend has not been approved for UDP VPN"
                        }
                        require(owner.isNotBlank() && owner != packageName) {
                            "Enter the actual package owning the external SOCKS5 core"
                        }
                        val (host, port) = validatedLoopback(address)
                        require(owner != packageName) { "The upstream must be a separate app" }
                        val verified = JSONObject(Mobilebridge.verifyExternalSocks(address, mode))
                        require(verified.optBoolean("verified")) { "No verified foreign exit" }
                        val udp = JSONObject(Mobilebridge.checkUDPRelay(address))
                        require(udp.optBoolean("ready") && udp.optBoolean("dns_answered")) {
                            "SOCKS5 UDP DNS roundtrip failed"
                        }
                        check(requested) { "Connection canceled" }
                        check(prepare(this@KTestVpnService) == null) {
                            "VPN permission was revoked"
                        }
                        val builder = Builder()
                            .setSession("KTest Verified SOCKS VPN")
                            .setMtu(1280)
                            .addAddress("198.18.0.1", 30)
                            .addAddress("fd00:198:18::1", 126)
                            .addRoute("0.0.0.0", 0)
                            .addRoute("::", 0)
                            .addDnsServer("1.1.1.1")
                            .addDnsServer("2606:4700:4700::1111")
                        // Scope upstream bypasses strictly to these packages;
                        // do NOT use allowBypass() or remove default routes.
                        builder.addDisallowedApplication(packageName)
                        builder.addDisallowedApplication(owner)
                        val established = builder.establish() ?: error("VPN TUN establish failed")
                        tun = established
                        val yaml = File(filesDir, "ktest-hev-session.yml").apply {
                            writeText(hevConfig(host, port))
                            setReadable(false, false)
                            setWritable(false, false)
                            setReadable(true, true)
                            setWritable(true, true)
                        }
                        config = yaml
                        val ok = try {
                            TProxyService.TProxyStartService(yaml.absolutePath, established.fd)
                        } catch (e: LinkageError) {
                            throw IllegalStateException("Pinned HEV native AAR could not load", e)
                        }
                        check(ok) { "HEV rejected TUN FD or configuration" }
                        var alive = false
                        for (attempt in 1..20) {
                            if (TProxyService.TProxyIsRunning()) { alive = true; break }
                            delay(100)
                        }
                        check(alive) { "HEV did not start its native event loop" }
                        check(requested) { "Connection canceled" }
                        phase = "tun_unverified"
                        detail = "TUN + HEV active; traffic from other apps still needs on-device verification"
                        startForeground(NOTIFICATION, notification(detail))
                    } catch (e: Exception) {
                        failClosed(e.message ?: "Cannot establish VPN")
                    } catch (e: LinkageError) {
                        failClosed("Pinned HEV native library unavailable")
                    }
                }
                var consecutiveFailures = 0
                while (requested && isActive) {
                    delay(15000)
                    val alive = runCatching { TProxyService.TProxyIsRunning() }.getOrDefault(false)
                    val exitHealthy = if (alive) {
                        runCatching {
                            JSONObject(Mobilebridge.verifyExternalSocks(address, mode))
                                .optBoolean("verified")
                        }.getOrDefault(false)
                    } else false
                    consecutiveFailures = if (alive && exitHealthy) 0 else consecutiveFailures + 1
                    if (!alive || consecutiveFailures >= 3) {
                        failClosed(
                            if (!alive) "Native HEV tunnel stopped"
                            else "Verified foreign SOCKS egress repeatedly failed"
                        )
                    }
                }
            }
        } else if (intent?.action == ACTION_DISCONNECT) {
            requested = false
            scope.launch {
                mutex.withLock {
                    phase = "idle"
                    detail = ""
                    shutdownNative()
                    stopForeground(STOP_FOREGROUND_REMOVE)
                    stopSelf()
                }
            }
        } else stopSelf()
        return START_NOT_STICKY
    }

    override fun onRevoke() {
        requested = false
        phase = "revoked"
        detail = "VPN permission revoked by Android"
        shutdownNative()
        stopSelf()
    }

    override fun onDestroy() {
        requested = false
        runner?.cancel()
        shutdownNative()
        scope.cancel()
        super.onDestroy()
    }

    /**
     * If an already-established TUN loses its transport, keep the TUN
     * installed but stop HEV: Android routes device packets into a blackhole
     * instead of implicitly reopening the physical ISP path. This is only
     * best-effort; Always-on/Block-without-VPN must still be user-enabled
     * for OS-level protection against process death or VPN revocation.
     */
    private fun failClosed(reason: String) {
        requested = false
        if (tun != null) {
            runCatching { TProxyService.TProxyStopService() }
            phase = "blocking"
            detail = "$reason. Traffic held by VPN TUN; disconnect explicitly to restore access."
            startForeground(NOTIFICATION, notification(detail))
        } else {
            phase = "failed"
            detail = reason
            shutdownNative()
            stopForeground(STOP_FOREGROUND_REMOVE)
            stopSelf()
        }
    }

    private fun shutdownNative() {
        runCatching { TProxyService.TProxyStopService() }
        runCatching { tun?.close() }
        tun = null
        runCatching { config?.delete() }
        config = null
    }

    private fun validatedLoopback(address: String): Pair<String, Int> {
        val index = address.lastIndexOf(':')
        require(index > 0) { "Expected IPv4 loopback host:port" }
        val host = address.substring(0, index)
        val port = address.substring(index + 1).toIntOrNull()
        require(host == "127.0.0.1" && port != null && port in 1..65535) {
            "VPN requires a verified IPv4 loopback SOCKS5 endpoint"
        }
        return host to port
    }

    private fun hevConfig(host: String, port: Int): String {
        // Mirrors upstream heiher/hev-socks5-tunnel/conf/main.yml.
        // Keep tunnel addresses identical to Builder.addAddress above.
        return """
            tunnel:
              name: tun0
              mtu: 1280
              ipv4: 198.18.0.1
              ipv6: 'fd00:198:18::1'
              icmp: 'off'
            socks5:
              address: $host
              port: $port
              udp: 'udp'
            misc:
              log-level: warn
        """.trimIndent() + "\n"
    }

    private fun notification(message: String): Notification {
        val open = PendingIntent.getActivity(this, 1,
            Intent(this, MainActivity::class.java),
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT)
        val stop = PendingIntent.getService(this, 5,
            Intent(this, KTestVpnService::class.java).apply { action = ACTION_DISCONNECT },
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT)
        return Notification.Builder(this, CHANNEL)
            .setSmallIcon(android.R.drawable.stat_sys_upload)
            .setContentTitle("KTest · Experimental VPN")
            .setContentText(message)
            .setContentIntent(open)
            .setOngoing(true)
            .addAction(Notification.Action.Builder(null, "Disconnect", stop).build())
            .build()
    }
}
