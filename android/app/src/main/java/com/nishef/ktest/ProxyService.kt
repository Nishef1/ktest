package com.nishef.ktest

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.Service
import android.content.Intent
import android.os.IBinder
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.launch
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive
import kotlinx.coroutines.withContext
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import mobilebridge.Mobilebridge

/** Foreground, user-controlled loopback proxy. Never masquerades as a system VPN. */
class ProxyService : Service() {
    companion object {
        const val ACTION_CONNECT = "com.nishef.ktest.CONNECT"
        const val ACTION_STOP = "com.nishef.ktest.DISCONNECT"
        const val EXTRA_MODE = "mode"
        const val EXTRA_UPSTREAM = "upstream"
        private const val CHANNEL = "ktest_proxy"
        private const val NOTIFICATION_ID = 42
        @Volatile var lastError: String? = null
    }

    private val worker = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    private val lock = Mutex()
    private val tor = TorController(this)
    private var startup: Job? = null
    @Volatile private var wanted = false

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
                val mode = intent.getStringExtra(EXTRA_MODE) ?: "balanced"
                val upstream = intent.getStringExtra(EXTRA_UPSTREAM) ?: ""
                wanted = true
                lastError = null
                startForeground(NOTIFICATION_ID, notification(mode))
                startup = worker.launch {
                    lock.withLock {
                        try {
                            val validatedUpstream = if (mode == "tor") tor.start() else upstream
                            if (wanted) Mobilebridge.startProxyWithUpstream(mode, validatedUpstream)
                            if (!wanted) Mobilebridge.stopProxy()
                        } catch (e: Exception) {
                            lastError = e.message ?: "Could not start proxy."
                            wanted = false
                            Mobilebridge.stopProxy()
                        }
                    }
                    if (wanted && mode == "tor") {
                        var failures = 0
                        while (wanted && isActive) {
                            delay(5000)
                            failures = if (tor.isAlive()) 0 else failures + 1
                            if (failures >= 3) {
                                wanted = false
                                lastError = "Tor circuit/service unavailable; proxy stopped"
                                Mobilebridge.stopProxy()
                            }
                        }
                    }
                    if (!wanted) {
                        tor.stop()
                        withContext(Dispatchers.Main) {
                            stopForeground(STOP_FOREGROUND_REMOVE)
                            stopSelf()
                        }
                    }
                }
            }
            ACTION_STOP -> {
                wanted = false
                startup?.cancel()
                tor.stop()
                worker.launch {
                    lock.withLock {
                        Mobilebridge.stopProxy()
                    }
                    withContext(Dispatchers.Main) {
                        stopForeground(STOP_FOREGROUND_REMOVE)
                        stopSelf()
                    }
                }
            }
            else -> stopSelf()
        }
        return START_NOT_STICKY
    }

    override fun onDestroy() {
        wanted = false
        startup?.cancel()
        tor.stop()
        Mobilebridge.stopProxy()
        worker.cancel()
        super.onDestroy()
    }

    private fun notification(mode: String): Notification {
        val open = PendingIntent.getActivity(
            this, 1, Intent(this, MainActivity::class.java),
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )
        val stop = PendingIntent.getService(
            this, 2, Intent(this, ProxyService::class.java).apply { action = ACTION_STOP },
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )
        return Notification.Builder(this, CHANNEL)
            .setSmallIcon(android.R.drawable.stat_sys_upload)
            .setContentTitle("KTest · Local proxy")
            .setContentText("${mode.replaceFirstChar { it.uppercase() }} · App-specific proxy, not VPN")
            .setContentIntent(open)
            .setOngoing(true)
            .addAction(Notification.Action.Builder(null, "Disconnect", stop).build())
            .build()
    }
}
