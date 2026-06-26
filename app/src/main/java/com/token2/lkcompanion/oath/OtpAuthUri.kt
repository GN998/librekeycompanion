package com.token2.lkcompanion.oath

import android.net.Uri
import com.token2.lkcompanion.oath.OathCore.HashAlgo

/** RFC 4648 base32 (no padding required), as used by otpauth secrets. */
object Base32 {
    private const val ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"

    fun decode(input: String): ByteArray {
        val s = input.trim().trimEnd('=').uppercase().replace(" ", "")
        if (s.isEmpty()) return ByteArray(0)
        val out = ArrayList<Byte>(s.length * 5 / 8)
        var buffer = 0
        var bitsLeft = 0
        for (c in s) {
            val v = ALPHABET.indexOf(c)
            require(v >= 0) { "invalid base32 char: $c" }
            buffer = (buffer shl 5) or v
            bitsLeft += 5
            if (bitsLeft >= 8) {
                bitsLeft -= 8
                out.add(((buffer ushr bitsLeft) and 0xFF).toByte())
            }
        }
        return out.toByteArray()
    }
}

/** One OATH credential, however sourced (otpauth URI, manual entry, on-key). */
data class OathCredential(
    val issuer: String?,
    val account: String,
    val secret: ByteArray,
    val type: Type,
    val algo: HashAlgo = HashAlgo.SHA1,
    val digits: Int = 6,
    val period: Int = 30,
    val counter: Long = 0,
) {
    enum class Type { TOTP, HOTP }

    val label: String get() = if (issuer.isNullOrBlank()) account else "$issuer ($account)"

    /** YKOATH credential-name convention: "issuer:account" (issuer optional). */
    val ykName: String get() = if (issuer.isNullOrBlank()) account else "$issuer:$account"

    override fun equals(other: Any?): Boolean =
        other is OathCredential && issuer == other.issuer && account == other.account &&
        type == other.type && secret.contentEquals(other.secret)
    override fun hashCode(): Int =
        31 * (issuer?.hashCode() ?: 0) + account.hashCode()
}

/** Parser for `otpauth://totp/...` and `otpauth://hotp/...` URIs (Key Uri Format). */
object OtpAuthUri {
    fun parse(raw: String): OathCredential {
        val uri = Uri.parse(raw.trim())
        require(uri.scheme == "otpauth") { "not an otpauth URI" }
        val type = when (uri.host?.lowercase()) {
            "totp" -> OathCredential.Type.TOTP
            "hotp" -> OathCredential.Type.HOTP
            else -> throw IllegalArgumentException("unknown otpauth type: ${uri.host}")
        }
        val path = uri.path?.removePrefix("/").orEmpty()
        val (issuerFromLabel, account) =
            if (path.contains(":")) path.substringBefore(":") to path.substringAfter(":")
            else null to path

        val secretParam = uri.getQueryParameter("secret")
            ?: throw IllegalArgumentException("otpauth URI missing secret")
        val issuer = uri.getQueryParameter("issuer") ?: issuerFromLabel
        val algo = uri.getQueryParameter("algorithm")?.let { HashAlgo.fromName(it) }
            ?: HashAlgo.SHA1
        val digits = uri.getQueryParameter("digits")?.toIntOrNull() ?: 6
        val period = uri.getQueryParameter("period")?.toIntOrNull() ?: 30
        val counter = uri.getQueryParameter("counter")?.toLongOrNull() ?: 0L

        return OathCredential(
            issuer = issuer?.takeIf { it.isNotBlank() },
            account = account,
            secret = Base32.decode(secretParam),
            type = type, algo = algo, digits = digits, period = period, counter = counter,
        )
    }
}
