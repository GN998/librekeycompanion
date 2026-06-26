package com.token2.lkcompanion.token2

import com.token2.lkcompanion.transport.Apdu
import com.token2.lkcompanion.transport.SmartCardTransport
import com.token2.lkcompanion.transport.TransportException

/**
 * Token2 on-device OTP client (§6/§8). Works over either:
 *   - PC/SC over NFC: pass a [SmartCardTransport] (the app's NfcTransport).
 *   - USB-HID: pass a [Token2HidTransport].
 * Both are funneled through a single [send] lambda so the client logic is shared.
 *
 * The management applet AID (NFC/PC-SC) is F0 00 00 01 4F 74 70 01.
 *
 * Implemented: READ_CONFIG feature detection, GET_ECDH_PUBKEY, enumerate (paged),
 * read-one, write/update (encrypted), delete (encrypted), erase-all.
 *
 * Deliberately guarded: SET_DEVICE_TYPE includes the anti-brick check from §6.8 —
 * it refuses any mask that would disable every interface. (Read the hardware-safety
 * warning in the protocol doc before ever calling it.)
 */
class Token2Client private constructor(
    private val send: (apdu: ByteArray, buttonWait: Boolean) -> ByteArray,
    private val isNfc: Boolean,
) {
    companion object {
        val MGMT_AID = byteArrayOf(0xF0.toByte(), 0x00, 0x00, 0x01, 0x4F, 0x74, 0x70, 0x01)
        val FIDO_AID = byteArrayOf(0xA0.toByte(), 0x00, 0x00, 0x06, 0x47, 0x2F, 0x00, 0x01)

        // CLA INS P1 P2 per §6
        private val WRITE_HOTP_SEED = intArrayOf(0x80, 0xC5, 0x00, 0x00)
        private val GET_ECDH_PUBKEY = intArrayOf(0x80, 0xC5, 0x01, 0x00)
        private val READ_CONFIG = intArrayOf(0x80, 0xC5, 0x02, 0x00)
        private val SET_DEVICE_TYPE = intArrayOf(0x80, 0xC5, 0x02, 0x01)
        private val ENABLE_TOTP = intArrayOf(0x80, 0xC5, 0x02, 0x05)
        private val ENUM_CODES = intArrayOf(0x80, 0xC5, 0x05, 0x00)
        private val ENUM_CODES_CONTINUE = intArrayOf(0x80, 0xC5, 0x05, 0x01)
        private val WRITE_SEED = intArrayOf(0x80, 0xC5, 0x05, 0x02)
        private val GET_INFO = intArrayOf(0x80, 0x33, 0x00, 0x00)

        /** Build over NFC/PC-SC; selects the management applet up front. */
        fun overNfc(transport: SmartCardTransport): Token2Client {
            transport.selectApplet(MGMT_AID)
            return Token2Client({ apdu, _ ->
                val r = transport.transceive(apdu)
                if (!r.isSuccess) mapStatus(r.sw)
                r.data
            }, isNfc = true)
        }

        /** Build over USB-HID. */
        fun overHid(hid: Token2HidTransport): Token2Client =
            Token2Client({ apdu, buttonWait -> hid.sendCommand(apdu, buttonWait) }, isNfc = false)

        private fun mapStatus(sw: Int): Nothing = when (sw) {
            0x6A80, 0x6A83 -> throw Token2Exception.EntryNotFound
            0x6A84 -> throw Token2Exception.NotEnoughSpace
            0x6FF9 -> throw Token2Exception.ButtonPressRequired
            // NOTE: 6A86 is "incorrect P1/P2 / instruction not supported on this
            // model". The spec only ties it to the HOTP-over-HID *config* commands;
            // do NOT relabel it as a HID error on other commands. Surface the SW.
            else -> throw Token2Exception.BadStatus(sw)
        }
    }

    data class DeviceInfo(
        val totpSupported: Boolean,
        val hotpSupported: Boolean,
        val nfcSupported: Boolean,
        val ccidSupported: Boolean,
        val fingerprintPresent: Boolean,
        val fidoHasPin: Boolean,
        val buttonHotpConfigured: Boolean,
        val fidoVersion: String,
        val raw: ByteArray,
    )

    // Extended-length APDU helper (§3): everything but PC/SC SELECT uses extended Lc.
    private fun apduExt(cmd: IntArray, data: ByteArray): ByteArray {
        val out = ArrayList<Byte>(5 + data.size)
        out.add(cmd[0].toByte()); out.add(cmd[1].toByte())
        out.add(cmd[2].toByte()); out.add(cmd[3].toByte())
        out.add(0x00)                                  // extended Lc marker
        out.add(((data.size ushr 8) and 0xFF).toByte())
        out.add((data.size and 0xFF).toByte())
        data.forEach { out.add(it) }
        return out.toByteArray()
    }

    /** §6.9 feature detection. Call first. */
    fun readConfig(numBytes: Int = 10): DeviceInfo {
        val resp = send(apduExt(READ_CONFIG, byteArrayOf(numBytes.coerceIn(10, 64).toByte())), false)
        // Tolerate a shorter-than-expected blob rather than throwing — pad to 10.
        val r = if (resp.size >= 10) resp else resp + ByteArray(10 - resp.size)
        val cfg = r[1].toInt() and 0xFF
        val ext = r[9].toInt() and 0xFF
        val fido = "${r[6].toInt() and 0xFF}.${r[7].toInt() and 0xFF}.${r[8].toInt() and 0xFF}"
        return DeviceInfo(
            totpSupported = ext and 0x01 != 0,
            hotpSupported = cfg and 0x04 != 0,
            nfcSupported = cfg and 0x10 != 0,
            ccidSupported = ext and 0x10 != 0,
            fingerprintPresent = cfg and 0x08 != 0,
            fidoHasPin = cfg and 0x02 != 0,
            buttonHotpConfigured = cfg and 0x80 != 0,
            fidoVersion = fido,
            raw = r,
        )
    }

    fun getEcdhPubkey(): ByteArray {
        val pk = send(apduExt(GET_ECDH_PUBKEY, ByteArray(0)), false)
        require(pk.size == 64) { "expected 64-byte pubkey, got ${pk.size}" }
        return pk
    }

    /** Enumerate all entries, following ENUM_CODES_CONTINUE paging (§6.1). */
    fun enumerate(timestampSeconds: Long): List<Token2Codec.Entry> {
        val all = ArrayList<Token2Codec.Entry>()
        var resp = send(apduExt(ENUM_CODES, Token2Codec.serializeReadAll(timestampSeconds)), false)
        while (true) {
            val (entries, more) = Token2Codec.parseEnumPage(resp, fullDecode = false)
            all.addAll(entries)
            if (!more) break
            resp = send(apduExt(ENUM_CODES_CONTINUE, Token2Codec.serializeContinue(timestampSeconds)), false)
        }
        return all
    }

    /** Read one entry, always including the code (waits for button on HID). */
    fun readEntry(timestampSeconds: Long, app: String, acct: String): Token2Codec.Entry {
        val resp = send(apduExt(ENUM_CODES,
            Token2Codec.serializeReadOne(timestampSeconds, app, acct)), true)
        return Token2Codec.parseEnumPage(resp, fullDecode = true).first.first()
    }

    /** Write or update an entry (encrypted, IV-1). */
    fun writeEntry(entry: Token2Codec.Entry) {
        val cleartext = Token2Codec.serializeWriteEntry(entry)
        val blob = Token2Crypto.encryptPayload(getEcdhPubkey(), cleartext, Token2Crypto.IV_WRITE_SEED)
        send(apduExt(WRITE_SEED, blob), false)
    }

    /** Delete an entry (encrypted empty-seed write, IV-1). */
    fun deleteEntry(app: String, acct: String) {
        val cleartext = Token2Codec.serializeDeleteEntry(app, acct)
        val blob = Token2Crypto.encryptPayload(getEcdhPubkey(), cleartext, Token2Crypto.IV_WRITE_SEED)
        send(apduExt(WRITE_SEED, blob), false)
    }

    /** Erase all — WRITE_SEED with empty data; requires button on HID (§6.5). */
    fun eraseAll() {
        send(apduExt(WRITE_SEED, ByteArray(0)), true)
    }

    fun enableTotp(enabled: Boolean) {
        send(apduExt(ENABLE_TOTP, byteArrayOf(if (enabled) 0x01 else 0x00)), false)
    }

    /**
     * §6.8 — guarded. The mask is "interfaces to DISABLE" (bit1 FIDO, bit2 keyboard,
     * bit3 CCID). We refuse any mask that would leave zero channels, matching the
     * companion app's anti-brick check. Reads current config first.
     */
    fun setDeviceType(disableMask: Int) {
        val info = readConfig()
        // Which channels currently exist:
        val hasFido = true                              // FIDO interface always present on these keys
        val hasKbd = info.hotpSupported
        val hasCcid = info.ccidSupported
        val fidoLeft = hasFido && (disableMask and 0x01 == 0)
        val kbdLeft = hasKbd && (disableMask and 0x02 == 0)
        val ccidLeft = hasCcid && (disableMask and 0x04 == 0)
        require(fidoLeft || kbdLeft || ccidLeft) {
            "refusing SET_DEVICE_TYPE mask 0x%02X — it would disable every interface (brick risk)"
                .format(disableMask)
        }
        send(apduExt(SET_DEVICE_TYPE, byteArrayOf(disableMask.toByte())), false)
    }
}
