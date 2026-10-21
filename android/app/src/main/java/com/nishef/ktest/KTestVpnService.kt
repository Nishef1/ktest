package com.nishef.ktest

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Intent
import android.net.VpnService
import android.os.IBinder
import android.os.ParcelFileDescriptor
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.CoroutineStart
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive
import mobilebridge.Mobilebridge
import org.json.JSONObject

/**
 * Android-only OS adapter for the existing KTest Go core.
 *
 * All packet-routing decisions remain in Go. In particular, this service
 * MUST NOT claim the VPN is active just because Builder.establish() returned
 * a TUN fd; a real, healthy Go-selected packet adapter is required first.
 *
 * Go owns route policy and SOCKS. The service registers HEV as a fallback;
 * the Go core tries its checksum-pinned Xray TUN inbound first and switches
 * to HEV automatically if Xray cannot start or exits.
 */
class KTestVpnService : VpnService() {
    companion object {
        const val ACTION_START = "com.nishef.ktest.VPN_START"
        const val ACTION_STOP = "com.nishef.ktest.VPN_STOP"
        const val EXTRA_UNDERLYING_NETWORK_HANDLE = "underlying_network_handle"
        private const val CHANNEL = "ktest_system_vpn"
        private const val NOTIFICATION_ID = 43
        @Volatile var state: String = "disconnected"
            private set
        @Volatile var lastError: String? = null
            private set

        /** Called by ProxyService right before ACTION_START so stale state is never observed. */
        fun markStarting() {
            state = "starting"
            lastError = null
        }
    }

    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    @Volatile private var pending: Job? = null
    @Volatile private var startGeneration = 0L
    @Volatile private var tun: ParcelFileDescriptor? = null
    @Volatile private var stopping = false
    private var stopJob: Job? = null
    private var stopTargetState = "disconnected"
    private var stopTargetError: String? = null

    override fun onBind(intent: Intent?): IBinder? = super.onBind(intent)

    override fun onCreate() {
        super.onCreate()
        // Register Xray's app-private/native paths before registering HEV as
        // fallback. Go owns selection and keeps both adapters on the same SOCKS policy.
        Mobilebridge.setAndroidXrayTunPaths(applicationInfo.nativeLibraryDir, filesDir.canonicalPath)
        Mobilebridge.setAndroidVpnPacketAdapter(HevPacketAdapter(this))
        getSystemService(NotificationManager::class.java).createNotificationChannel(
            NotificationChannel(CHANNEL, "KTest VPN", NotificationManager.IMPORTANCE_LOW)
        )
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_START -> {
                if (pending != null || tun != null || stopping) return START_NOT_STICKY
                state = "preparing"
                lastError = null
                // Android requires foreground promotion immediately, before
                // any slow Go/OS operation that could exceed the start limit.
                startForeground(NOTIFICATION_ID, notification("Checking Go core readiness"))
                val underlyingHandle = intent.getLongExtra(EXTRA_UNDERLYING_NETWORK_HANDLE, -1L)
                val runGeneration = ++startGeneration
                val job = scope.launch(start = CoroutineStart.LAZY) {
                    var adapterStopped = false
                    try {
                        val capability = JSONObject(Mobilebridge.vpnCapability())
                        require(capability.optBoolean("available")) {
                            capability.optString("reason", "Go packet transport is not available")
                        }
                        require(prepare(this@KTestVpnService) == null) {
                            "Android VPN permission is required"
                        }

                        // The application owns its own upstream Go sockets.
                        // Excluding only this UID prevents accidental recursion
                        // through its TUN; it does NOT bypass unrelated apps.
                        val plan = JSONObject(Mobilebridge.vpnTunPlan())
                        val builder = Builder()
                            .setSession("KTest")
                            .setMtu(plan.getInt("mtu"))
                            .addAddress(plan.getString("ipv4_address"), plan.getInt("ipv4_prefix"))
                            .addRoute(plan.getString("ipv4_route"), 0)
                            .addDnsServer(plan.getString("ipv4_dns"))
                            .addDisallowedApplication(packageName)
                        // The proxy acknowledges SOCKS CONNECT before dialing, so an IPv6
                        // route without real IPv6 egress makes apps hang on dead v6
                        // destinations. Without a v6 route Android fails IPv6 inside the
                        // VPN immediately (no leak) and apps fall back to IPv4.
                        if (underlyingHasGlobalIpv6()) {
                            builder.addAddress(plan.getString("ipv6_address"), plan.getInt("ipv6_prefix"))
                                .addRoute(plan.getString("ipv6_route"), 0)
                                .addDnsServer(plan.getString("ipv6_dns"))
                        }
                        val tunDevice = builder.establish()
                            ?: error("Android did not establish the TUN interface")
                        if (underlyingHandle > 0) {
                            val underlying = android.net.Network.fromNetworkHandle(underlyingHandle)
                            val manager = getSystemService(android.net.ConnectivityManager::class.java)
                            if (manager.getNetworkCapabilities(underlying)?.hasCapability(
                                    android.net.NetworkCapabilities.NET_CAPABILITY_INTERNET
                                ) == true) {
                                setUnderlyingNetworks(arrayOf(underlying))
                            }
                        }

                        tun = tunDevice
                        // Go prefers the pinned Xray TUN inbound and falls back
                        // to HEV if startup fails. Both feed the same adaptive
                        // Go SOCKS policy; Kotlin never selects site routes.
                        Mobilebridge.attachVpnTun(tunDevice.fd.toLong())
                        if (!isActive || startGeneration != runGeneration) {
                            Mobilebridge.stopVpnTun()
                            throw CancellationException("VPN startup canceled")
                        }
                        val report = JSONObject(Mobilebridge.vpnCapability())
                        check(report.optBoolean("active")) {
                            "Go packet engine did not confirm an active TUN adapter"
                        }
                        withContext(Dispatchers.Main) {
                            if (!isActive || startGeneration != runGeneration) {
                                throw CancellationException("VPN startup canceled")
                            }
                            state = "tun_running_unverified"
                            startForeground(NOTIFICATION_ID, notification(
                                "System tunnel active; destination routes adapt automatically"
                            ))
                        }
                        // Fail closed if the Go proxy or both packet adapters stop.
                        // VpnCapability() attempts automatic Xray -> HEV recovery
                        // before reporting the packet path inactive.
                        while (isActive) {
                            delay(1500)
                            if (!JSONObject(Mobilebridge.vpnCapability()).optBoolean("active")) {
                                adapterStopped = true
                                break
                            }
                        }
                        withContext(NonCancellable + Dispatchers.IO) { closeTunnel() }
                        withContext(NonCancellable + Dispatchers.Main) {
                            if (startGeneration == runGeneration) {
                                if (adapterStopped) lastError = "Connection stopped; VPN packet adapter became unhealthy"
                                state = "disconnected"
                                stopForeground(STOP_FOREGROUND_REMOVE)
                                stopSelfResult(startId)
                            }
                        }
                    } catch (e: CancellationException) {
                        // User or Android revoked the service while checking.
                        throw e
                    } catch (e: Exception) {
                        val errorMessage = e.message ?: "VPN adapter unavailable"
                        withContext(NonCancellable + Dispatchers.IO) { closeTunnel() }
                        withContext(NonCancellable + Dispatchers.Main) {
                            if (startGeneration == runGeneration) {
                                lastError = errorMessage
                                state = "failed"
                                stopForeground(STOP_FOREGROUND_REMOVE)
                                stopSelfResult(startId)
                            }
                        }
                    } finally {
                        if (startGeneration == runGeneration) pending = null
                    }
                }
                pending = job
                job.start()
            }
            ACTION_STOP -> {
                requestTunnelStop("disconnected", null)
            }
            else -> stopSelf()
        }
        return START_NOT_STICKY
    }

    override fun onRevoke() {
        requestTunnelStop("revoked", "Android revoked the VPN permission")
    }

    override fun onDestroy() {
        startGeneration++
        pending?.cancel()
        pending = null
        closeTunnel()
        scope.cancel()
        state = "disconnected"
        super.onDestroy()
    }

    private fun underlyingHasGlobalIpv6(): Boolean = runCatching {
        val cm = getSystemService(android.net.ConnectivityManager::class.java)
        val props = cm.getLinkProperties(cm.activeNetwork) ?: return false
        val global = props.linkAddresses.any { la ->
            val a = la.address
            a is java.net.Inet6Address && !a.isLinkLocalAddress && !a.isSiteLocalAddress &&
                !a.isLoopbackAddress && (a.address[0].toInt() and 0xfe) != 0xfc
        }
        global && props.routes.any { it.isDefaultRoute && it.destination.address is java.net.Inet6Address }
    }.getOrDefault(false)


    /** Stop packet forwarding off the main thread; native process teardown can block. */
    private fun requestTunnelStop(finalState: String, error: String?) {
        startGeneration++
        pending?.cancel()
        pending = null
        stopTargetState = finalState
        stopTargetError = error
        if (stopping) return
        stopping = true
        state = "stopping"
        stopJob = scope.launch {
            closeTunnel()
            withContext(Dispatchers.Main) {
                state = stopTargetState
                stopTargetError?.let { lastError = it }
                stopForeground(STOP_FOREGROUND_REMOVE)
                stopping = false
                stopSelf()
            }
        }
    }

    @Synchronized private fun closeTunnel() {
        // Normal stop already closed the tunnel on Dispatchers.IO before
        // stopSelf(). Avoid repeating native process teardown in onDestroy's
        // main-thread callback when there is no tunnel left to close.
        if (tun == null && state == "disconnected") return
        Mobilebridge.stopVpnTun()
        runCatching { setUnderlyingNetworks(null) }
        runCatching { tun?.close() }
        tun = null
    }

    private fun notification(detail: String): Notification {
        val open = PendingIntent.getActivity(this, 1,
            Intent(this, MainActivity::class.java),
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT)
        val stop = PendingIntent.getService(this, 2,
            Intent(this, KTestVpnService::class.java).apply { action = ACTION_STOP },
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT)
        return Notification.Builder(this, CHANNEL)
            .setSmallIcon(R.drawable.ic_stat_ktest)
            .setContentTitle("KTest VPN")
            .setContentText(detail)
            .setContentIntent(open)
            .setOngoing(true)
            .addAction(Notification.Action.Builder(null, "Stop VPN", stop).build())
            .build()
    }
}
