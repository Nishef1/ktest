package com.nishef.ktest

import java.io.ByteArrayInputStream
import java.security.KeyStore
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import mobilebridge.Mobilebridge

/** Detects the EXACT app-created certificate in Android's user trust store.
 *  A match is not proof that Chrome, TikTok, Telegram or other apps trust it.
 *  Do not silently grant user-CA trust to KTest's own TLS connections.
 */
internal object LocalCaTrust {
    internal data class Result(val state: String, val detail: String)

    fun inspect(privateFilesDir: String): Result {
        try {
            val publicPEM = Mobilebridge.frontCAPublicPEM(privateFilesDir)
            val factory = CertificateFactory.getInstance("X.509")
            val wanted = ByteArrayInputStream(publicPEM.toByteArray(Charsets.US_ASCII))
                .use { factory.generateCertificate(it) as X509Certificate }
            val store = KeyStore.getInstance("AndroidCAStore")
            store.load(null)
            val entries = store.aliases()
            while (entries.hasMoreElements()) {
                val alias = entries.nextElement()
                // Only a user-installed trust anchor matches the requested
                // manual installation; never confuse a system CA with it.
                if (!alias.startsWith("user:")) continue
                val item = store.getCertificate(alias) as? X509Certificate ?: continue
                if (item.encoded.contentEquals(wanted.encoded)) {
                    return Result("installed_user",
                        "Exact KTest CA found in Android user certificates. Other apps may reject user CAs or pin certificates.")
                }
            }
            return Result("not_found",
                "This exact CA was not found in the Android user trust store. Export and install ktest-ca.crt, then check again.")
        } catch (e: Exception) {
            return Result("unknown",
                "Unable to verify Android's user certificate store: ${e.javaClass.simpleName}. Do not assume installation or trust.")
        }
    }
}
