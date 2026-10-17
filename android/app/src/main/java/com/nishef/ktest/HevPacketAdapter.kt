package com.nishef.ktest

import android.content.Context
import hev.htproxy.TProxyService
import mobilebridge.AndroidVpnPacketAdapter
import mobilebridge.Mobilebridge
import org.json.JSONObject
import java.io.File
import java.net.InetAddress

/**
 * HEV is strictly Android's tun2socks platform adapter. Network strategy,
 * proxy destination selection and all exit verification remain inside Go.
 * The Go core keeps VPN disabled until its UDP/DNS/IPv6 path is ready.
 */
internal class HevPacketAdapter(
    private val context: Context
) : AndroidVpnPacketAdapter {
    private var sessionConfig: File? = null
    private var started = false

    @Synchronized
    override fun start(fd: Long, socksAddress: String): Boolean {
        if (started || fd < 0 || fd > Int.MAX_VALUE) return false
        val (host, port) = runCatching {
            require(socksAddress.startsWith("127.0.0.1:"))
            val num = socksAddress.substringAfterLast(':').toInt()
            require(num in 1..65535)
            "127.0.0.1" to num
        }.getOrElse { return false }
        val plan = JSONObject(Mobilebridge.vpnTunPlan())
        val mtu = plan.getInt("mtu")
        require(mtu in 1280..9000)
        // Ensure Go-provided addresses cannot inject lines into a YAML file.
        fun numericAddress(value: String): String {
            require(!value.contains('\n') && !value.contains('\r'))
            require(InetAddress.getByName(value).hostAddress?.isNotBlank() == true)
            return value
        }
        val ipv4 = numericAddress(plan.getString("ipv4_address"))
        val ipv6 = numericAddress(plan.getString("ipv6_address"))
        val yaml = """
            tunnel:
              name: tun0
              mtu: $mtu
              ipv4: '$ipv4'
              ipv6: '$ipv6'
              icmp: 'off'
            socks5:
              address: '$host'
              port: $port
              udp: 'udp'
            misc:
              log-level: warn
        """.trimIndent() + "\n"
        val file = File(context.filesDir, "ktest-tun.yml")
        file.writeText(yaml)
        file.setReadable(false, false)
        file.setWritable(false, false)
        file.setReadable(true, true)
        file.setWritable(true, true)
        sessionConfig = file
        val ok = runCatching {
            TProxyService.TProxyStartService(file.absolutePath, fd.toInt())
        }.getOrDefault(false)
        if (!ok) {
            stop()
            return false
        }
        started = true
        return true
    }

    @Synchronized
    override fun stop() {
        if (started) {
            runCatching { TProxyService.TProxyStopService() }
        }
        started = false
        runCatching { sessionConfig?.delete() }
        sessionConfig = null
    }

    @Synchronized
    override fun isRunning(): Boolean {
        return started && runCatching { TProxyService.TProxyIsRunning() }.getOrDefault(false)
    }

    override fun supportsUDP(): Boolean = true // HEV support; Go still gates forwarding
    override fun supportsIPv6(): Boolean = true // HEV support; Go still gates forwarding
}
