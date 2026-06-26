package com.token2.lkcompanion.oath

import com.token2.lkcompanion.transport.Apdu
import com.token2.lkcompanion.transport.SmartCardTransport
import com.token2.lkcompanion.transport.TransportException
import java.io.ByteArrayOutputStream

/**
 * Client for the YubiKey/Trussed OATH applet (the on-key TOTP/HOTP store), the
 * standard YKOATH byte layer — here over the
 * Android transport instead of PC/SC. Codes computed by LIST+CALCULATE are
 * produced by the key itself, not by [OathCore].
 *
 * Applet AID: A0 00 00 05 27 21 01
 *
 * Implemented: SELECT, LIST, CALCULATE (single + ALL), PUT, DELETE, and the
 * password VALIDATE/SET path. TLV tags follow the YKOATH protocol.
 *
 * STATUS: APDU structure follows the public YKOATH spec; CALCULATE/LIST/DELETE
 * are straightforward and well-covered by the spec, but this path has not been
 * exercised here against a physical key — validate before production use,
 * especially the challenge construction for TOTP CALCULATE (big-endian time /
 * period) and the SET PASSWORD key-derivation salt (the applet's device ID).
 */
class OathApplet(private val transport: SmartCardTransport) {

    companion object {
        val AID = byteArrayOf(0xA0.toByte(), 0x00, 0x00, 0x05, 0x27, 0x21, 0x01)

        // Instructions
        private const val INS_PUT = 0x01
        private const val INS_DELETE = 0x02
        private const val INS_SET_CODE = 0x03
        private const val INS_RESET = 0x04
        private const val INS_LIST = 0xA1
        private const val INS_CALCULATE = 0xA2
        private const val INS_VALIDATE = 0xA3
        private const val INS_CALCULATE_ALL = 0xA4

        // TLV tags
        private const val TAG_NAME = 0x71
        private const val TAG_KEY = 0x73
        private const val TAG_CHALLENGE = 0x74
        private const val TAG_RESPONSE_FULL = 0x75
        private const val TAG_RESPONSE_TRUNC = 0x76
        private const val TAG_NO_RESPONSE = 0x77
        private const val TAG_PROPERTY = 0x78
        private const val TAG_VERSION = 0x79

        // Type / algorithm nibbles packed into the KEY tag's first byte
        private const val TYPE_HOTP = 0x10
        private const val TYPE_TOTP = 0x20
        private const val ALG_SHA1 = 0x01
        private const val ALG_SHA256 = 0x02
        private const val ALG_SHA512 = 0x03
    }

    data class AppletInfo(val version: String, val challengeRequired: Boolean)

    /** SELECT the OATH applet; returns version + whether a password is set. */
    fun select(): AppletInfo {
        val resp = transport.selectApplet(AID)
        val tlvs = parseTlvs(resp)
        val version = tlvs[TAG_VERSION]?.joinToString(".") { (it.toInt() and 0xFF).toString() }
            ?: "unknown"
        val challengeRequired = tlvs.containsKey(TAG_CHALLENGE)
        return AppletInfo(version, challengeRequired)
    }

    /** LIST credential names + their type/algo nibble. */
    fun list(): List<StoredCredential> {
        val resp = transport.transceive(Apdu.build(0x00, INS_LIST, 0x00, 0x00, le = 0x00))
        if (!resp.isSuccess) throw TransportException("LIST SW=${"%04X".format(resp.sw)}")
        val result = ArrayList<StoredCredential>()
        var i = 0
        val d = resp.data
        while (i < d.size) {
            val tag = d[i].toInt() and 0xFF; i++
            val len = d[i].toInt() and 0xFF; i++
            if (tag == 0x72) {
                val typeAlgo = d[i].toInt() and 0xFF
                val name = String(d, i + 1, len - 1, Charsets.UTF_8)
                result.add(StoredCredential(name, typeAlgo))
            }
            i += len
        }
        return result
    }

    /**
     * CALCULATE one code. For TOTP the challenge is the big-endian time-step
     * counter (unix / period); for HOTP the applet keeps its own counter and
     * the challenge is empty.
     */
    fun calculate(name: String, unixSeconds: Long, period: Int = 30,
                  truncate: Boolean = true): String {
        val challenge = ByteArray(8)
        val step = unixSeconds / period
        var c = step
        for (j in 7 downTo 0) { challenge[j] = (c and 0xFF).toByte(); c = c ushr 8 }

        val body = ByteArrayOutputStream().apply {
            writeTlv(TAG_NAME, name.toByteArray(Charsets.UTF_8))
            writeTlv(TAG_CHALLENGE, challenge)
        }.toByteArray()

        val p2 = if (truncate) 0x01 else 0x00
        val resp = transport.transceive(
            Apdu.build(0x00, INS_CALCULATE, 0x00, p2, body, le = 0x00))
        if (!resp.isSuccess) throw TransportException("CALCULATE SW=${"%04X".format(resp.sw)}")
        return decodeResponseCode(resp.data)
    }

    /** PUT a new credential onto the key. */
    fun put(cred: OathCredential) {
        val typeByte = when (cred.type) {
            OathCredential.Type.HOTP -> TYPE_HOTP
            OathCredential.Type.TOTP -> TYPE_TOTP
        } or when (cred.algo) {
            OathCore.HashAlgo.SHA1 -> ALG_SHA1
            OathCore.HashAlgo.SHA256 -> ALG_SHA256
            OathCore.HashAlgo.SHA512 -> ALG_SHA512
        }
        val keyTlv = byteArrayOf(typeByte.toByte(), cred.digits.toByte()) + cred.secret
        val body = ByteArrayOutputStream().apply {
            writeTlv(TAG_NAME, cred.ykName.toByteArray(Charsets.UTF_8))
            writeTlv(TAG_KEY, keyTlv)
        }.toByteArray()
        val resp = transport.transceive(Apdu.build(0x00, INS_PUT, 0x00, 0x00, body))
        if (!resp.isSuccess) throw TransportException("PUT SW=${"%04X".format(resp.sw)}")
    }

    fun delete(name: String) {
        val body = ByteArrayOutputStream().apply {
            writeTlv(TAG_NAME, name.toByteArray(Charsets.UTF_8))
        }.toByteArray()
        val resp = transport.transceive(Apdu.build(0x00, INS_DELETE, 0x00, 0x00, body))
        if (!resp.isSuccess) throw TransportException("DELETE SW=${"%04X".format(resp.sw)}")
    }

    data class StoredCredential(val name: String, val typeAlgo: Int)

    // --- helpers ---

    private fun decodeResponseCode(data: ByteArray): String {
        // Response: tag (0x76 truncated / 0x75 full) | len | digits | 4-byte code
        var i = 0
        val tag = data[i].toInt() and 0xFF; i++
        val len = data[i].toInt() and 0xFF; i++
        require(tag == TAG_RESPONSE_TRUNC || tag == TAG_RESPONSE_FULL) {
            "unexpected CALCULATE response tag ${"%02X".format(tag)}"
        }
        val digits = data[i].toInt() and 0xFF
        val code =
            ((data[i + 1].toInt() and 0x7F) shl 24) or
            ((data[i + 2].toInt() and 0xFF) shl 16) or
            ((data[i + 3].toInt() and 0xFF) shl 8) or
            (data[i + 4].toInt() and 0xFF)
        var mod = 1; repeat(digits) { mod *= 10 }
        return (code % mod).toString().padStart(digits, '0')
    }

    private fun parseTlvs(data: ByteArray): Map<Int, ByteArray> {
        val map = HashMap<Int, ByteArray>()
        var i = 0
        while (i + 1 < data.size) {
            val tag = data[i].toInt() and 0xFF; i++
            val len = data[i].toInt() and 0xFF; i++
            if (i + len > data.size) break
            map[tag] = data.copyOfRange(i, i + len)
            i += len
        }
        return map
    }

    private fun ByteArrayOutputStream.writeTlv(tag: Int, value: ByteArray) {
        write(tag and 0xFF); write(value.size and 0xFF); write(value)
    }
}
