package com.nishef.ktest

import android.content.ComponentCallbacks2
import android.os.SystemClock
import mobilebridge.Mobilebridge

/**
 * Hands unused Go heap back to Android when the UI is hidden or the system is
 * short on memory. The Go call forces a collection, so it runs on its own
 * thread and at most once per interval even if the Activity and the services
 * both receive the same trim event.
 */
internal object MemoryTrim {
    private const val MIN_INTERVAL_MS = 30_000L
    @Volatile private var last = 0L

    fun onTrim(level: Int) {
        if (level < ComponentCallbacks2.TRIM_MEMORY_UI_HIDDEN) return
        val now = SystemClock.elapsedRealtime()
        synchronized(this) {
            if (last != 0L && now - last < MIN_INTERVAL_MS) return
            last = now
        }
        Thread({ runCatching { Mobilebridge.trimMemory() } }, "ktest-trim").apply { isDaemon = true }.start()
    }
}
