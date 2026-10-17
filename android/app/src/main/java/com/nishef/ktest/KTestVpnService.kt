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
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import mobilebridge.Mobilebridge
import org.json.JSONObject

/**
 * Android-only OS adapter for the existing KTest Go core.
 *
 * All packet-routing decisions remain in Go. In particular, this service
 * MUST NOT claim the VPN is active just because Builder.establish() returned
 * a TUN fd; a real, healthy Go-selected packet adapter is required first.
 *
 * Until the full Go/HEV UDP/DNS/IPv6 path is validated and a packet adapter
 * is registered, VpnCapability() rejects startup before establishing or
 * rerouting any device traffic. Protocol implementation alone is insufficient.
 */
class KTestVpnService : VpnService() {
    companion object {
        const val ACTION_START = "com.nishef.ktest.VPN_START"
        const val ACTION_STOP = "com.nishef.ktest.VPN_STOP"
        private const val CHANNEL = "ktest_system_vpn"
        private const val NOTIFICATION_ID = 43
        @Volatile var state: String = "disconnected"
            private set
        @Volatile var lastError: String? = null
            private set
    }

    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    private var pending: Job? = null
    private var tun: ParcelFileDescriptor? = null

    override fun onBind(intent: Intent?): IBinder? = super.onBind(intent)

    override fun onCreate() {
        super.onCreate()
        // Register only a packet adapter. Go refuses full VPN until the
        // complete Go/HEV routing path has validated DNS/UDP and IPv6.
        Mobilebridge.setAndroidVpnPacketAdapter(HevPacketAdapter(this))
        getSystemService(NotificationManager::class.java).createNotificationChannel(
            NotificationChannel(CHANNEL, "KTest VPN", NotificationManager.IMPORTANCE_LOW)
        )
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_START -> {
                if (pending != null || tun != null) return START_NOT_STICKY
                state = "preparing"
                lastError = null
                // Android requires foreground promotion immediately, before
                // any slow Go/OS operation that could exceed the start limit.
                startForeground(NOTIFICATION_ID, notification("Checking Go core readiness"))
                pending = scope.launch {
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
                        val tunDevice = Builder()
                            .setSession("KTest")
                            .setMtu(plan.getInt("mtu"))
                            .addAddress(plan.getString("ipv4_address"), plan.getInt("ipv4_prefix"))
                            .addAddress(plan.getString("ipv6_address"), plan.getInt("ipv6_prefix"))
                            .addRoute(plan.getString("ipv4_route"), 0)
                            .addRoute(plan.getString("ipv6_route"), 0)
                            .addDnsServer(plan.getString("ipv4_dns"))
                            .addDnsServer(plan.getString("ipv6_dns"))
                            .addDisallowedApplication(packageName)
                            .establish() ?: error("Android did not establish the TUN interface")

                        tun = tunDevice
                        // Go, not this Android service, must drive a real
                        // TUN-to-network dataplane and reject unsupported UDP.
                        Mobilebridge.attachVpnTun(tunDevice.fd.toLong())
                        val report = JSONObject(Mobilebridge.vpnCapability())
                        check(report.optBoolean("active")) {
                            "Go packet engine did not confirm an active TUN adapter"
                        }
                        state = "tun_running_unverified"
                        startForeground(NOTIFICATION_ID, notification(
                            "Packet adapter running; destination traffic not yet verified"
                        ))
                    } catch (e: CancellationException) {
                        // User or Android revoked the service while checking.
                        throw e
                    } catch (e: Exception) {
                        lastError = e.message ?: "VPN adapter unavailable"
                        state = "failed"
                        withContext(NonCancellable + Dispatchers.Main) {
                            closeTunnel()
                            stopForeground(STOP_FOREGROUND_REMOVE)
                            stopSelfResult(startId)
                        }
                    } finally {
                        pending = null
                    }
                }
            }
            ACTION_STOP -> {
                pending?.cancel()
                closeTunnel()
                state = "disconnected"
                stopForeground(STOP_FOREGROUND_REMOVE)
                stopSelf()
            }
            else -> stopSelf()
        }
        return START_NOT_STICKY
    }

    override fun onRevoke() {
        pending?.cancel()
        closeTunnel()
        state = "revoked"
        lastError = "Android revoked the VPN permission"
        stopSelf()
    }

    override fun onDestroy() {
        pending?.cancel()
        closeTunnel()
        scope.cancel()
        state = "disconnected"
        super.onDestroy()
    }

    private fun closeTunnel() {
        Mobilebridge.stopVpnTun()
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
            .setSmallIcon(android.R.drawable.stat_sys_upload)
            .setContentTitle("KTest · Go VPN adapter")
            .setContentText(detail)
            .setContentIntent(open)
            .setOngoing(true)
            .addAction(Notification.Action.Builder(null, "Disconnect VPN", stop).build())
            .build()
    }
}
