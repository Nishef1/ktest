package com.nishef.ktest

import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.content.ServiceConnection
import android.os.IBinder
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.suspendCancellableCoroutine
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeout
import org.torproject.jni.TorService
import kotlin.coroutines.resume
import kotlin.coroutines.resumeWithException

/**
 * Embedded Guardian Project Tor 0.4.9.14, NOT an arbitrary user-supplied
 * "Tor" SOCKS port. Tor provides TCP; VPN/HEV UDP must not point at it.
 */
internal class TorController(private val context: Context) {
    private var binding: ServiceConnection? = null
    @Volatile private var serviceInstance: TorService? = null

    fun isAlive(): Boolean {
        val active = serviceInstance ?: return false
        return runCatching {
            active.socksPort in 1..65535 &&
                active.getInfo("status/circuit-established")?.trim() == "1"
        }.getOrDefault(false)
    }

    // The *entire* bind + bootstrap is bounded. Previously the timeout only
    // wrapped the bootstrap loop; a never-fulfilled Android ServiceConnection
    // could leave the foreground notification running indefinitely.
    suspend fun start(): String = withTimeout(120_000L) {
        try {
            val service = withContext(Dispatchers.Main) {
                suspendCancellableCoroutine<TorService> { continuation ->
                    val conn = object : ServiceConnection {
                        override fun onServiceConnected(name: ComponentName?, binder: IBinder?) {
                            if (!continuation.isActive) return
                            val local = binder as? TorService.LocalBinder
                            if (local == null) {
                                continuation.resumeWithException(
                                    IllegalStateException("Tor binder has an unexpected type")
                                )
                            } else {
                                serviceInstance = local.service
                                continuation.resume(local.service)
                            }
                        }

                        override fun onServiceDisconnected(name: ComponentName?) {
                            serviceInstance = null
                        }
                    }
                    binding = conn
                    continuation.invokeOnCancellation { stop() }
                    val bound = try {
                        context.bindService(
                            Intent(context, TorService::class.java),
                            conn,
                            Context.BIND_AUTO_CREATE
                        )
                    } catch (e: Exception) {
                        if (continuation.isActive) continuation.resumeWithException(e)
                        false
                    }
                    if (!bound && continuation.isActive) {
                        continuation.resumeWithException(
                            IllegalStateException("Tor service binding failed")
                        )
                    }
                }
            }
            withContext(Dispatchers.IO) {
                var endpoint: String? = null
                while (endpoint == null) {
                    val port = service.socksPort
                    val established = runCatching {
                        service.getInfo("status/circuit-established")?.trim() == "1"
                    }.getOrDefault(false)
                    if (port in 1..65535 && established) {
                        endpoint = "127.0.0.1:$port"
                    } else {
                        delay(500)
                    }
                }
                endpoint ?: error("Tor bootstrap finished without a usable SOCKS port")
            }
        } catch (e: Throwable) {
            stop()
            throw e
        }
    }

    fun stop() {
        val conn = binding ?: return
        binding = null
        serviceInstance = null
        runCatching { context.unbindService(conn) }
    }
}
