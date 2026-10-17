package com.nishef.ktest

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.Service
import android.content.Intent
import android.os.IBinder
import mobilebridge.Mobilebridge

/** User-started foreground local proxy. No VPN, routing, or system-wide interception. */
class ProxyService : Service() {
    companion object {
        const val ACTION_CONNECT = "com.nishef.ktest.CONNECT"
        const val ACTION_STOP = "com.nishef.ktest.DISCONNECT"
        const val EXTRA_MODE = "mode"
        private const val CHANNEL = "ktest_proxy"
        private const val NOTIFICATION_ID = 42
        @Volatile var lastError: String? = null
    }

    override fun onBind(intent: Intent?): IBinder? = null

    override fun onCreate() {
        super.onCreate()
        val manager = getSystemService(NotificationManager::class.java)
        manager.createNotificationChannel(NotificationChannel(
            CHANNEL, "Local proxy status", NotificationManager.IMPORTANCE_LOW
        ))
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_CONNECT -> {
                val mode = intent.getStringExtra(EXTRA_MODE) ?: "balanced"
                // Android requires immediate foreground notification after
                // startForegroundService; the Go listener is then started.
                startForeground(NOTIFICATION_ID, notification(mode))
                lastError = null
                try {
                    Mobilebridge.startProxy(mode)
                } catch (e: Exception) {
                    lastError = e.message ?: "Local proxy failed to start."
                    Mobilebridge.stopProxy()
                    stopForeground(STOP_FOREGROUND_REMOVE)
                    stopSelf()
                }
            }
            ACTION_STOP -> {
                Mobilebridge.stopProxy()
                lastError = null
                stopForeground(STOP_FOREGROUND_REMOVE)
                stopSelf()
            }
            else -> stopSelf()
        }
        return START_NOT_STICKY
    }

    override fun onDestroy() {
        Mobilebridge.stopProxy()
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
            .setContentText("${mode.replaceFirstChar { it.uppercase() }} mode · Apps must use the proxy")
            .setContentIntent(open)
            .setOngoing(true)
            .addAction(Notification.Action.Builder(null, "Disconnect", stop).build())
            .build()
    }
}
