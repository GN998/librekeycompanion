package com.token2.lkcompanion.piv

import com.token2.lkcompanion.transport.Apdu
import com.token2.lkcompanion.transport.SmartCardTransport
import com.token2.lkcompanion.transport.TransportException

/**
 * PIV (NIST SP 800-73-4) client. Deliberately READ-ONLY, a deliberately minimal
 * own current PIV scope ("read-only status so far"): applet/version, and which
 * of the standard key slots (9A/9C/9D/9E) hold a certificate.
 *
 * NOT implemented: GENERAL AUTHENTICATE (sign/auth), key generation, certificate
 * import, PIN/PUK change. Those are security-critical and out of scope for this
 * read build; add them against the spec + hardware when needed.
 */
class PivApplet(private val transport: SmartCardTransport) {

    companion object {
        val AID = byteArrayOf(0xA0.toByte(), 0x00, 0x00, 0x03, 0x08)
        private const val INS_GET_DATA = 0xCB
        private const val INS_VERIFY = 0x20
        private const val INS_GET_VERSION = 0xFD   // YubiKey vendor extension

        // Object tags for certificates in the four standard slots
        private val SLOT_OBJECTS = linkedMapOf(
            "9A Authentication" to byteArrayOf(0x5F, 0xC1.toByte(), 0x05),
            "9C Signature"      to byteArrayOf(0x5F, 0xC1.toByte(), 0x0A),
            "9D Key Management" to byteArrayOf(0x5F, 0xC1.toByte(), 0x0B),
            "9E Card Auth"      to byteArrayOf(0x5F, 0xC1.toByte(), 0x01),
        )
        private val CHUID_OBJECT = byteArrayOf(0x5F, 0xC1.toByte(), 0x02)
        private const val PIN_REF = 0x80
        private const val PUK_REF = 0x81
    }

    data class SlotCert(
        val slot: String,
        val info: X509.CertInfo,
    )

    data class PivStatus(
        val version: String?,
        val slotsWithCert: List<String>,
        val certs: List<SlotCert> = emptyList(),
        val pinRetries: Int? = null,
        val pukRetries: Int? = null,
        val cardGuidHex: String? = null,
    )

    fun select(): ByteArray = transport.selectApplet(AID)

    fun status(): PivStatus {
        select()
        val version = runCatching {
            val r = transport.transceive(Apdu.build(0x00, INS_GET_VERSION, 0x00, 0x00, le = 0x00))
            if (r.isSuccess && r.data.size >= 3)
                "${r.data[0].toInt() and 0xFF}.${r.data[1].toInt() and 0xFF}.${r.data[2].toInt() and 0xFF}"
            else null
        }.getOrNull()

        val present = ArrayList<String>()
        val certs = ArrayList<SlotCert>()
        for ((label, objId) in SLOT_OBJECTS) {
            val raw = runCatching { getObject(objId) }.getOrNull() ?: continue
            if (raw.isEmpty()) continue
            present.add(label)
            // PIV data object: 0x53 wrapper -> 0x70 certificate (the DER) [+ 0x71 certinfo].
            val der = extractCertDer(raw)
            if (der != null) {
                runCatching { X509.parse(der) }.getOrNull()
                    ?.let { certs.add(SlotCert(label, it)) }
            }
        }

        val pinRetries = runCatching { readRetries(PIN_REF) }.getOrNull()
        val pukRetries = runCatching { readRetries(PUK_REF) }.getOrNull()
        val guid = runCatching { readCardGuid() }.getOrNull()

        return PivStatus(version, present, certs, pinRetries, pukRetries, guid)
    }

    /** GET DATA for a PIV object id, returning the value inside the 0x53 wrapper. */
    private fun getObject(objId: ByteArray): ByteArray {
        val tlv = byteArrayOf(0x5C, objId.size.toByte()) + objId
        val resp = transport.transceive(Apdu.build(0x00, INS_GET_DATA, 0x3F, 0xFF, tlv, le = 0x00))
        if (!resp.isSuccess) return ByteArray(0)
        return resp.data
    }

    /** From a PIV data object (0x53 { 0x70 cert, 0x71 certinfo, ... }), pull the 0x70 DER. */
    private fun extractCertDer(data: ByteArray): ByteArray? {
        // Unwrap the outer 0x53 if present.
        val body = PivTlv.valueOf(data, 0x53) ?: data
        return PivTlv.valueOf(body, 0x70)
    }

    /**
     * VERIFY with an empty data field doesn't change the PIN but returns the remaining
     * tries in the status word (0x63 0xCx, where x = tries left). Some cards answer
     * 0x6983 (blocked) -> 0 tries.
     */
    private fun readRetries(ref: Int): Int? {
        val r = transport.transceive(Apdu.build(0x00, INS_VERIFY, 0x00, ref))
        val sw = r.sw
        return when {
            sw == 0x9000 -> null                       // already verified this session
            (sw and 0xFFF0) == 0x63C0 -> sw and 0x000F // tries remaining
            sw == 0x6983 -> 0                           // blocked
            else -> null
        }
    }

    /** CHUID (object 5FC102) contains a GUID in TLV 0x34. */
    private fun readCardGuid(): String? {
        val chuid = getObject(CHUID_OBJECT)
        if (chuid.isEmpty()) return null
        val body = PivTlv.valueOf(chuid, 0x53) ?: chuid
        val guid = PivTlv.valueOf(body, 0x34) ?: return null
        return guid.joinToString("") { "%02X".format(it) }
    }

    fun generalAuthenticate(): Nothing =
        throw NotImplementedError("PIV GENERAL AUTHENTICATE not implemented (read-only build).")
}

/** Tiny flat TLV helper for PIV wrappers (single-byte + long-form lengths). */
private object PivTlv {
    /** Return the value bytes of the first TLV with [tag] at this level, or null. */
    fun valueOf(data: ByteArray, tag: Int): ByteArray? {
        var i = 0
        while (i < data.size) {
            val t = data[i].toInt() and 0xFF; i++
            if (i >= data.size) break
            var len = data[i].toInt() and 0xFF; i++
            if (len and 0x80 != 0) {
                val n = len and 0x7F
                len = 0
                repeat(n) { if (i < data.size) { len = (len shl 8) or (data[i].toInt() and 0xFF); i++ } }
            }
            if (i + len > data.size) break
            if (t == tag) return data.copyOfRange(i, i + len)
            i += len
        }
        return null
    }
}
