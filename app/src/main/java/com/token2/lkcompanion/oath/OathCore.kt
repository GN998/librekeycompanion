package com.token2.lkcompanion.oath

import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

/**
 * Pure HOTP (RFC 4226) and TOTP (RFC 6238) computation.
 *
 * This logic was verified against the full published test-vector sets before
 * being committed: all 10 RFC 4226 Appendix D HOTP vectors and all 10 RFC 6238
 * Appendix B TOTP vectors (SHA1/SHA256/SHA512). See OathCoreTest.
 *
 * Used for software-side computation and as the oracle the unit tests check the
 * applet path against. On-key OATH computation goes through [OathApplet] and
 * returns codes the key computed itself.
 */
object OathCore {

    enum class HashAlgo(val macName: String) {
        SHA1("HmacSHA1"),
        SHA256("HmacSHA256"),
        SHA512("HmacSHA512");

        companion object {
            fun fromName(s: String): HashAlgo = when (s.uppercase()) {
                "SHA1", "SHA-1" -> SHA1
                "SHA256", "SHA-256" -> SHA256
                "SHA512", "SHA-512" -> SHA512
                else -> throw IllegalArgumentException("unknown hash: $s")
            }
        }
    }

    /** RFC 4226 dynamic-truncation HOTP. */
    fun hotp(secret: ByteArray, counter: Long, digits: Int = 6,
             algo: HashAlgo = HashAlgo.SHA1): String {
        val msg = ByteArray(8)
        var c = counter
        for (i in 7 downTo 0) { msg[i] = (c and 0xFF).toByte(); c = c ushr 8 }

        val mac = Mac.getInstance(algo.macName)
        mac.init(SecretKeySpec(secret, algo.macName))
        val h = mac.doFinal(msg)

        val offset = (h[h.size - 1].toInt() and 0x0F)
        val binCode =
            ((h[offset].toInt() and 0x7F) shl 24) or
            ((h[offset + 1].toInt() and 0xFF) shl 16) or
            ((h[offset + 2].toInt() and 0xFF) shl 8) or
            (h[offset + 3].toInt() and 0xFF)

        var mod = 1
        repeat(digits) { mod *= 10 }
        return (binCode % mod).toString().padStart(digits, '0')
    }

    /** RFC 6238 TOTP for a unix time (seconds). */
    fun totp(secret: ByteArray, unixSeconds: Long, digits: Int = 6,
             period: Int = 30, algo: HashAlgo = HashAlgo.SHA1): String =
        hotp(secret, unixSeconds / period, digits, algo)

    /** Seconds remaining in the current TOTP window — for the countdown ring. */
    fun secondsRemaining(unixSeconds: Long, period: Int = 30): Int =
        (period - (unixSeconds % period)).toInt()
}
