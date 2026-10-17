package com.nishef.ktest

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.Service
import android.content.Intent
import android.os.IBinder
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext
import mobilebridge.Mobilebridge

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
        private const val CHANNEL = "ktest_proxy"
        private const val NOTIFICATION_ID = 42
        @Volatile var lastError: String? = null
    }

    private val worker = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    private val mutex = Mutex()
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
                if (wanted) return START_NOT_STICKY
                val mode = intent.getStringExtra(EXTRA_MODE) ?: "balanced"
                val upstream = intent.getStringExtra(EXTRA_UPSTREAM).orEmpty()
                wanted = true
                lastError = null
                startForeground(NOTIFICATION_ID, notification(mode))
                startup = worker.launch {
                    try {
                        mutex.withLock {
                            if (wanted) Mobilebridge.startProxyWithUpstream(mode, upstream)
                        }
                    } catch (_: CancellationException) {
                        // A user-initiated stop is not a connection failure.
                    } catch (e: Exception) {
                        if (wanted) lastError = e.message ?: "Could not start Go proxy"
                        wanted = false
                    } finally {
                        if (!wanted) {
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
                startup?.cancel()
                // Invalidate a blocked/slow Go startup immediately.
                Mobilebridge.stopProxy()
                worker.launch {
                    mutex.withLock { Mobilebridge.stopProxy() }
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
            .setContentText("${mode.replaceFirstChar { it.uppercase() }} · Proxy mode")
            .setContentIntent(open)
            .setOngoing(true)
            .addAction(Notification.Action.Builder(null, "Disconnect", stop).build())
            .build()
    }
}
