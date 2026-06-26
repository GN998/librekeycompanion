package com.token2.lkcompanion.fido.ctap

import java.security.KeyFactory
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.MessageDigest
import java.security.SecureRandom
import java.security.spec.ECGenParameterSpec
import javax.crypto.Cipher
import javax.crypto.KeyAgreement
import javax.crypto.Mac
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec
import java.security.interfaces.ECPublicKey
import java.security.spec.ECPoint
import java.security.spec.ECPublicKeySpec
import java.security.AlgorithmParameters
import java.security.spec.ECParameterSpec

/**
 * CTAP2 PIN/UV auth protocol crypto — both v1 and v2.
 *
 * VERIFIED against the published CTAP2.1 test vectors (WebauthnWorks migration
 * guide): the v1 SHA-256 KDF, the v2 HKDF dual-key derivation with info strings
 * "CTAP2 AES key" / "CTAP2 HMAC key", and the v2 HMAC all reproduce the documented
 * outputs byte-for-byte. See PinProtocolTest.
 *
 *  v1: sharedSecret = SHA-256(Z.x); AES-256-CBC, zero IV; auth = HMAC-SHA-256 left 16.
 *  v2: HKDF-SHA-256(salt=32 zero) -> aesKey + hmacKey; AES-256-CBC, random IV
 *      prepended; auth = full 32-byte HMAC-SHA-256.
 */
sealed class PinUvAuthProtocol(val version: Int) {

    /** The platform's ephemeral P-256 key pair for this exchange. */
    protected val keyPair: KeyPair = run {
        val g = KeyPairGenerator.getInstance("EC")
        g.initialize(ECGenParameterSpec("secp256r1"))
        g.generateKeyPair()
    }

    /** Raw shared-secret X coordinate from ECDH with the authenticator key. */
    protected fun sharedX(authKeyX: ByteArray, authKeyY: ByteArray): ByteArray {
        val pub = decodeP256(authKeyX, authKeyY)
        val ka = KeyAgreement.getInstance("ECDH")
        ka.init(keyPair.private)
        ka.doPhase(pub, true)
        return ka.generateSecret()   // 32-byte X coordinate
    }

    /** COSE key (x,y) of the platform public key, for the keyAgreement parameter. */
    fun platformCoseKey(): Map<Int, Any> {
        val pub = keyPair.public as ECPublicKey
        val x = fixed32(pub.w.affineX.toByteArray())
        val y = fixed32(pub.w.affineY.toByteArray())
        // COSE_Key: kty=EC2(2), alg=ECDH-ES+HKDF-256(-25), crv=P256(1), x, y
        return linkedMapOf(1 to 2, 3 to -25, -1 to 1, -2 to x, -3 to y)
    }

    abstract fun encapsulate(authX: ByteArray, authY: ByteArray): SharedSecret

    /** Derived per-session keys + the operations that use them. */
    inner class SharedSecret(
        private val aesKey: ByteArray,
        private val hmacKey: ByteArray,
    ) {
        fun encrypt(plaintext: ByteArray): ByteArray = this@PinUvAuthProtocol.encrypt(aesKey, plaintext)
        fun decrypt(ciphertext: ByteArray): ByteArray = this@PinUvAuthProtocol.decrypt(aesKey, ciphertext)
        fun authenticate(message: ByteArray): ByteArray = this@PinUvAuthProtocol.authenticate(hmacKey, message)
    }

    protected abstract fun encrypt(key: ByteArray, data: ByteArray): ByteArray
    protected abstract fun decrypt(key: ByteArray, data: ByteArray): ByteArray
    protected abstract fun authenticate(key: ByteArray, msg: ByteArray): ByteArray

    // --- v1 ---
    class V1 : PinUvAuthProtocol(1) {
        override fun encapsulate(authX: ByteArray, authY: ByteArray): SharedSecret {
            val z = sharedX(authX, authY)
            val s = MessageDigest.getInstance("SHA-256").digest(z)  // 32 bytes
            return SharedSecret(s, s)                               // same key for enc + mac
        }
        override fun encrypt(key: ByteArray, data: ByteArray): ByteArray {
            val c = Cipher.getInstance("AES/CBC/NoPadding")
            c.init(Cipher.ENCRYPT_MODE, SecretKeySpec(key, "AES"), IvParameterSpec(ByteArray(16)))
            return c.doFinal(data)
        }
        override fun decrypt(key: ByteArray, data: ByteArray): ByteArray {
            val c = Cipher.getInstance("AES/CBC/NoPadding")
            c.init(Cipher.DECRYPT_MODE, SecretKeySpec(key, "AES"), IvParameterSpec(ByteArray(16)))
            return c.doFinal(data)
        }
        override fun authenticate(key: ByteArray, msg: ByteArray): ByteArray {
            val m = Mac.getInstance("HmacSHA256"); m.init(SecretKeySpec(key, "HmacSHA256"))
            return m.doFinal(msg).copyOf(16)                        // left 16 bytes
        }
    }

    // --- v2 ---
    class V2 : PinUvAuthProtocol(2) {
        override fun encapsulate(authX: ByteArray, authY: ByteArray): SharedSecret {
            val z = sharedX(authX, authY)
            val aes = hkdfSha256(z, ByteArray(32), "CTAP2 AES key".toByteArray(), 32)
            val mac = hkdfSha256(z, ByteArray(32), "CTAP2 HMAC key".toByteArray(), 32)
            return SharedSecret(aes, mac)
        }
        override fun encrypt(key: ByteArray, data: ByteArray): ByteArray {
            val iv = ByteArray(16).also { SecureRandom().nextBytes(it) }
            val c = Cipher.getInstance("AES/CBC/NoPadding")
            c.init(Cipher.ENCRYPT_MODE, SecretKeySpec(key, "AES"), IvParameterSpec(iv))
            return iv + c.doFinal(data)                             // IV prepended
        }
        override fun decrypt(key: ByteArray, data: ByteArray): ByteArray {
            val iv = data.copyOfRange(0, 16)
            val c = Cipher.getInstance("AES/CBC/NoPadding")
            c.init(Cipher.DECRYPT_MODE, SecretKeySpec(key, "AES"), IvParameterSpec(iv))
            return c.doFinal(data.copyOfRange(16, data.size))
        }
        override fun authenticate(key: ByteArray, msg: ByteArray): ByteArray {
            val m = Mac.getInstance("HmacSHA256"); m.init(SecretKeySpec(key, "HmacSHA256"))
            return m.doFinal(msg)                                   // full 32 bytes
        }
    }

    companion object {
        /** HKDF-SHA-256 (extract + expand) — small self-contained impl. */
        fun hkdfSha256(ikm: ByteArray, salt: ByteArray, info: ByteArray, length: Int): ByteArray {
            val mac = Mac.getInstance("HmacSHA256")
            mac.init(SecretKeySpec(if (salt.isEmpty()) ByteArray(32) else salt, "HmacSHA256"))
            val prk = mac.doFinal(ikm)                              // extract
            val out = ArrayList<Byte>()
            var t = ByteArray(0)
            var counter = 1
            while (out.size < length) {
                val m2 = Mac.getInstance("HmacSHA256")
                m2.init(SecretKeySpec(prk, "HmacSHA256"))
                m2.update(t); m2.update(info); m2.update(counter.toByte())
                t = m2.doFinal()
                out.addAll(t.toList())
                counter++
            }
            return out.toByteArray().copyOf(length)
        }

        /** Build an ECPublicKey on P-256 from raw 32-byte X and Y. */
        private fun decodeP256(x: ByteArray, y: ByteArray): ECPublicKey {
            val params = AlgorithmParameters.getInstance("EC").apply {
                init(ECGenParameterSpec("secp256r1"))
            }
            val spec = params.getParameterSpec(ECParameterSpec::class.java)
            val point = ECPoint(java.math.BigInteger(1, x), java.math.BigInteger(1, y))
            return KeyFactory.getInstance("EC")
                .generatePublic(ECPublicKeySpec(point, spec)) as ECPublicKey
        }

        /** Left-pad / trim a BigInteger.toByteArray() to a fixed 32 bytes. */
        private fun fixed32(b: ByteArray): ByteArray = when {
            b.size == 32 -> b
            b.size == 33 && b[0].toInt() == 0 -> b.copyOfRange(1, 33)   // strip sign byte
            b.size < 32 -> ByteArray(32 - b.size) + b
            else -> b.copyOfRange(b.size - 32, b.size)
        }
    }
}
