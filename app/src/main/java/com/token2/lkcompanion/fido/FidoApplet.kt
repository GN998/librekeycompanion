package com.token2.lkcompanion.fido

import com.token2.lkcompanion.transport.Apdu
import com.token2.lkcompanion.transport.SmartCardTransport

/**
 * FIDO2 / CTAP2 over the smart-card (NFC ISO-DEP / USB CCID) transport.
 *
 * ── SCOPE & HONESTY NOTE ───────────────────────────────────────────────────
 * This is a SKELETON, not a working CTAP2 stack. A correct implementation is a
 * large, security-critical effort (CTAP2 CBOR command/response encoding,
 * clientPin protocols v1 AND v2 with the PIN/UV auth-protocol key agreement,
 * ES256 / ECDH over P-256, credential-management subcommands, the
 * NFCCTAP_MSG / NFCCTAP_GETRESPONSE chaining, and — for a real passkey
 * provider — wiring into Android's CredentialProvider service).
 *
 * Rather than emit invented crypto here, the right path is to build on the
 * existing, audited, MIT-licensed Android implementation that already does
 * exactly this: github.com/mimi89999/Authnkey (CTAP2 over NFC + USB, clientPin,
 * discoverable credentials, credential-provider integration). Study or depend
 * on it; do not regenerate CTAP2 from scratch unless you can validate every
 * step against the FIDO CTAP2 spec and a physical key.
 *
 * What IS real below: the FIDO applet AID and the NFC SELECT, which are stable
 * and standard. Everything past selection is intentionally unimplemented and
 * throws, so nothing silently pretends to work.
 */
class FidoApplet(private val transport: SmartCardTransport) {

    companion object {
        // FIDO applet AID (used for NFC SELECT). U2F/FIDO2 share this AID.
        val AID = byteArrayOf(0xA0.toByte(), 0x00, 0x00, 0x06, 0x47, 0x2F, 0x00, 0x01)

        // CTAP2 command bytes (for reference when implementing):
        const val CMD_MAKE_CREDENTIAL = 0x01
        const val CMD_GET_ASSERTION = 0x02
        const val CMD_GET_INFO = 0x04
        const val CMD_CLIENT_PIN = 0x06
        const val CMD_RESET = 0x07
        const val CMD_CREDENTIAL_MANAGEMENT = 0x0A
    }

    /** SELECT the FIDO applet. Returns the version string ("U2F_V2"/"FIDO_2_0"). */
    fun select(): String {
        val resp = transport.selectApplet(AID)
        return String(resp, Charsets.US_ASCII)
    }

    /**
     * Detect CTAP2 support by sending authenticatorGetInfo (CTAP2 cmd 0x04) over
     * the NFC APDU envelope (NFCCTAP_MSG = 80 10 00 00) and pulling the `versions`
     * strings out of the CBOR map. This is read-only feature detection — NOT the
     * full CTAP2 stack (use Authnkey for that). The SELECT response is always the
     * legacy "U2F_V2" string per the FIDO NFC spec, so it alone can't tell you
     * whether the key is FIDO2; GetInfo is what distinguishes them.
     *
     * Returns the list of version strings, e.g. ["U2F_V2","FIDO_2_0","FIDO_2_1"],
     * or just ["U2F_V2"] for a U2F-only key (which errors GetInfo).
     */
    fun getVersions(): List<String> {
        select()
        // NFCCTAP_MSG envelope: CLA=80 INS=10 P1=00 P2=00, data = CTAP2 command byte.
        // authenticatorGetInfo has no parameters, so the body is the single byte 0x04.
        val resp = transport.transceive(
            Apdu.build(0x80, 0x10, 0x00, 0x00, byteArrayOf(CMD_GET_INFO.toByte())))
        if (!resp.isSuccess || resp.data.isEmpty()) return listOf("U2F_V2")
        // CTAP2 response: first byte is status (0x00 = OK), remainder is CBOR.
        if (resp.data[0].toInt() != 0x00) return listOf("U2F_V2")
        return parseCtapVersions(resp.data.copyOfRange(1, resp.data.size))
    }

    /**
     * Minimal CBOR scan for the GetInfo `versions` array (map key 0x01 -> array of
     * text strings). Not a general CBOR decoder — just enough to read the version
     * tags without pulling in a dependency.
     */
    private fun parseCtapVersions(cbor: ByteArray): List<String> {
        val out = ArrayList<String>()
        var i = 0
        // Expect a map header (major type 5: 0xA0..0xBF). Find key 0x01.
        if (i >= cbor.size) return listOf("U2F_V2")
        val mapHdr = cbor[i].toInt() and 0xFF; i++
        if (mapHdr ushr 5 != 5) return listOf("U2F_V2")   // not a map
        val entries = mapHdr and 0x1F
        var e = 0
        while (e < entries && i < cbor.size) {
            val key = cbor[i].toInt() and 0xFF; i++       // small-int key (0x00..0x17)
            if (key == 0x01) {
                // value is an array of text strings
                if (i >= cbor.size) break
                val arrHdr = cbor[i].toInt() and 0xFF; i++
                if (arrHdr ushr 5 != 4) break             // not an array
                val n = arrHdr and 0x1F
                repeat(n) {
                    if (i >= cbor.size) return@repeat
                    val sHdr = cbor[i].toInt() and 0xFF; i++
                    if (sHdr ushr 5 != 3) return@repeat   // not a text string
                    val len = sHdr and 0x1F
                    if (i + len <= cbor.size) {
                        out.add(String(cbor, i, len, Charsets.US_ASCII)); i += len
                    }
                }
                break
            } else {
                // skip this value: handle the small subset of CBOR we might hit
                i = skipCborValue(cbor, i)
            }
            e++
        }
        return if (out.isEmpty()) listOf("U2F_V2") else out
    }

    /** Skip one CBOR item (covers ints, strings, simple arrays/maps best-effort). */
    private fun skipCborValue(cbor: ByteArray, start: Int): Int {
        var i = start
        if (i >= cbor.size) return i
        val b = cbor[i].toInt() and 0xFF; i++
        val major = b ushr 5
        val info = b and 0x1F
        val count = when (info) {
            in 0..23 -> info
            24 -> { val v = cbor[i].toInt() and 0xFF; i++; v }
            25 -> { i += 2; -1 }
            26 -> { i += 4; -1 }
            else -> 0
        }
        when (major) {
            2, 3 -> if (count >= 0) i += count          // byte/text string: skip bytes
            4 -> { val n = if (count >= 0) count else 0; repeat(n) { i = skipCborValue(cbor, i) } }
            5 -> { val n = if (count >= 0) count else 0; repeat(n) { i = skipCborValue(cbor, i); i = skipCborValue(cbor, i) } }
            else -> {}                                   // ints/simple: already consumed
        }
        return i
    }

    fun getInfo(): Nothing =
        throw NotImplementedError(
            "CTAP2 authenticatorGetInfo not implemented in this skeleton. " +
            "Use/port github.com/mimi89999/Authnkey for the real CTAP2 stack.")

    fun makeCredential(): Nothing =
        throw NotImplementedError("CTAP2 makeCredential not implemented — see Authnkey.")

    fun getAssertion(): Nothing =
        throw NotImplementedError("CTAP2 getAssertion not implemented — see Authnkey.")
}
