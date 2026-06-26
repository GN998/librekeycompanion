package com.token2.lkcompanion.token2

import java.security.KeyFactory
import java.security.KeyPairGenerator
import java.security.MessageDigest
import java.security.spec.ECPoint
import java.security.spec.ECPublicKeySpec
import javax.crypto.Cipher
import javax.crypto.KeyAgreement
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec
import java.security.AlgorithmParameters
import java.security.interfaces.ECPublicKey
import java.security.spec.ECGenParameterSpec
import java.security.spec.ECParameterSpec

/**
 * §7 seed encryption: ephemeral ECDH (NIST P-256) → SHA-256(sharedX) →
 * AES-256-CBC with one of two CONSTANT IVs. Uses only Android platform crypto
 * (no external dependency); P-256 + AES-CBC are standard providers.
 *
 * The ECDH+AES round-trip and the §10.2 byte sizing (23-byte cleartext → 32-byte
 * ciphertext) were verified against the spec before this port.
 *
 * SECURITY: the two IVs are fixed by the device protocol — freshness comes from
 * the per-command ephemeral host keypair, NOT the IV. Do not randomize them.
 */
object Token2Crypto {

    /** IV-1 — write/delete OTP entries (WRITE_SEED). */
    val IV_WRITE_SEED = hex("9DD8918E34F3CCAB08CB7518F71938F1")
    /** IV-2 — button-HOTP seed write/delete (WRITE_HOTP_SEED). */
    val IV_HOTP_SEED = ByteArray(16)   // all zeros

    /**
     * Build the on-wire ECDH blob: host ephemeral pubkey (64-byte X||Y, no 0x04
     * prefix) followed by the AES-CBC ciphertext of the PKCS#7-padded cleartext.
     *
     * @param devicePubXy device pubkey as raw X||Y (64 bytes), from GET_ECDH_PUBKEY
     */
    fun encryptPayload(devicePubXy: ByteArray, cleartext: ByteArray, iv: ByteArray): ByteArray {
        require(devicePubXy.size == 64) { "device pubkey must be 64 bytes (X||Y)" }

        val params = AlgorithmParameters.getInstance("EC").apply {
            init(ECGenParameterSpec("secp256r1"))
        }
        val ecSpec = params.getParameterSpec(ECParameterSpec::class.java)

        // host ephemeral keypair
        val kpg = KeyPairGenerator.getInstance("EC").apply {
            initialize(ECGenParameterSpec("secp256r1"))
        }
        val hostKp = kpg.generateKeyPair()
        val hostPub = hostKp.public as ECPublicKey

        // device public key from X||Y
        val x = java.math.BigInteger(1, devicePubXy.copyOfRange(0, 32))
        val y = java.math.BigInteger(1, devicePubXy.copyOfRange(32, 64))
        val devicePub = KeyFactory.getInstance("EC")
            .generatePublic(ECPublicKeySpec(ECPoint(x, y), ecSpec))

        // ECDH shared secret = X coordinate (32 bytes)
        val shared = KeyAgreement.getInstance("ECDH").run {
            init(hostKp.private); doPhase(devicePub, true); generateSecret()
        }
        val sessionKey = MessageDigest.getInstance("SHA-256").digest(shared)

        val ct = Cipher.getInstance("AES/CBC/PKCS5Padding").run {
            init(Cipher.ENCRYPT_MODE, SecretKeySpec(sessionKey, "AES"), IvParameterSpec(iv))
            doFinal(cleartext)
        }

        return hostPubXy(hostPub) + ct
    }

    /** Host pubkey as raw 64-byte X||Y (no leading 0x04). */
    private fun hostPubXy(pub: ECPublicKey): ByteArray {
        val x = to32(pub.w.affineX)
        val y = to32(pub.w.affineY)
        return x + y
    }

    private fun to32(v: java.math.BigInteger): ByteArray {
        val raw = v.toByteArray()                 // may have leading 0x00 sign byte or be short
        val out = ByteArray(32)
        val src = if (raw.size > 32) raw.copyOfRange(raw.size - 32, raw.size) else raw
        System.arraycopy(src, 0, out, 32 - src.size, src.size)
        return out
    }

    private fun hex(s: String): ByteArray =
        ByteArray(s.length / 2) { ((s[it*2].digitToInt(16) shl 4) or s[it*2+1].digitToInt(16)).toByte() }
}
