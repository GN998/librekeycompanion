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

        // SET_DEVICE_TYPE disable-mask bits (§6.8): a set bit disables that interface.
        const val DEV_FIDO = 0x01
        const val DEV_KEYBOARD = 0x02
        const val DEV_CCID = 0x04

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
        // --- current interface state (byte 0 / transfer-type, §6.9) ---
        // These say which USB interfaces are *disabled right now*, independent of
        // whether the model *supports* them (that's the *Supported flags above).
        // A set bit in byte 0 means "this interface is currently turned off".
        val fidoDisabled: Boolean,
        val keyboardHidDisabled: Boolean,
        val ccidDisabled: Boolean,
        val raw: ByteArray,
    ) {
        /** True when the config blob actually carried byte 1 (the capability byte),
         *  as opposed to a short CCID/NFC stub that only returned byte 0. When
         *  false, the *Supported flags derived from byte 1/9 are not trustworthy. */
        val hasConfigByte: Boolean get() = raw.size >= 2
    }

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
        // §1.11: READ_CONFIG is an ISO case-2 command — 4-byte header + a single
        // Le byte (number of bytes wanted), NO Lc/data. Building it with an
        // extended-Lc *data* body makes the card answer 61 01 (only 1 byte
        // available) over PC/SC — which is why earlier only byte 0 came back and
        // every capability read as "unsupported". keyroost documents the same
        // fix. A plain Le asks for the whole block.
        val le = numBytes.coerceIn(10, 64)
        val apdu = byteArrayOf(
            READ_CONFIG[0].toByte(), READ_CONFIG[1].toByte(),
            READ_CONFIG[2].toByte(), READ_CONFIG[3].toByte(),
            le.toByte(),
        )
        val resp = send(apdu, false)
        if (resp.isEmpty()) throw Token2Exception.BadStatus(0x6A80)
        // The interface-state bits (byte 0) are the only hard requirement; some
        // firmware returns just byte 0 over CCID/NFC while USB-HID returns the
        // full block. Read whatever came back, defaulting absent fields to 0, but
        // keep `raw` at its true length so hasConfigByte can tell a real value
        // from zero-padding (matching keyroost's raw_len handling).
        fun at(i: Int): Int = if (i < resp.size) resp[i].toInt() and 0xFF else 0
        val iface = at(0)                     // byte 0: transfer-type / interface state
        val cfg = at(1)                       // byte 1: capability flags
        val ext = at(9)                       // byte 9: extension flags
        val fido = "${at(6)}.${at(7)}.${at(8)}"
        return DeviceInfo(
            totpSupported = ext and 0x01 != 0,
            hotpSupported = cfg and 0x04 != 0,
            nfcSupported = cfg and 0x10 != 0,
            ccidSupported = ext and 0x10 != 0,
            fingerprintPresent = cfg and 0x08 != 0,
            fidoHasPin = cfg and 0x02 != 0,
            buttonHotpConfigured = cfg and 0x80 != 0,
            fidoVersion = fido,
            // byte 0: bit1 FIDO off, bit2 keyboard-HID off, bit3 CCID off (§6.9).
            fidoDisabled = iface and 0x01 != 0,
            keyboardHidDisabled = iface and 0x02 != 0,
            ccidDisabled = iface and 0x04 != 0,
            raw = resp,
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
     * Enable/disable the key's USB interfaces by *which ones to keep on* — the
     * ergonomic front door to [setDeviceType].
     *
     * `fido` / `keyboard` / `ccid` are the desired ENABLED state of each
     * interface; this builds the §6.8 disable-mask (a set bit disables) from them.
     *
     * Safety: like the keyroost reference tool, this requires **at least two**
     * interfaces to remain enabled. Disabling all three bricks the key; leaving
     * only one is fragile — if that single interface can't be reached (e.g. you
     * keep FIDO only, but this phone talks to the key over CCID/NFC) you'd be
     * locked out with no way to undo it. Two-interface minimum keeps a margin.
     *
     * @throws IllegalArgumentException if fewer than two interfaces would remain.
     */
    fun setInterfaces(fido: Boolean, keyboard: Boolean, ccid: Boolean) {
        val enabledCount = listOf(fido, keyboard, ccid).count { it }
        require(enabledCount >= 2) {
            "at least two interfaces must stay enabled (FIDO / keyboard-HID / CCID); " +
                "reducing to one or zero risks locking you out of the key"
        }
        var disable = 0
        if (!fido) disable = disable or DEV_FIDO
        if (!keyboard) disable = disable or DEV_KEYBOARD
        if (!ccid) disable = disable or DEV_CCID
        setDeviceType(disable)
    }

    /**
     * §6.8 — guarded. The mask is "interfaces to DISABLE" (bit1 FIDO, bit2 keyboard,
     * bit3 CCID). We refuse any mask that would leave zero channels, matching the
     * companion app's anti-brick check. Reads current config first.
     */
    fun setDeviceType(disableMask: Int) {
        // Anti-brick guard based purely on the mask: refuse only a mask that
        // disables all three interfaces at once (0x07). Deriving "which
        // interfaces exist" from the capability bytes is unreliable here because
        // over CCID/NFC some firmware returns only byte 0 (interface state) and
        // no capability byte, which would make every capability read as false.
        require(disableMask and 0x07 != 0x07) {
            "refusing SET_DEVICE_TYPE mask 0x%02X — it would disable every interface (brick risk)"
                .format(disableMask)
        }
        // Short-form Lc (single 0x01) for the 1-byte mask body: 80 C5 02 01 01 <mask>.
        // T=0 contact (CCID) readers reject the extended-Lc (00 hi lo) form with
        // 6700/6A86; short form is valid over CCID, NFC, and USB-HID alike, so it
        // is the universal encoding keyroost uses for this command.
        val apdu = byteArrayOf(
            SET_DEVICE_TYPE[0].toByte(), SET_DEVICE_TYPE[1].toByte(),
            SET_DEVICE_TYPE[2].toByte(), SET_DEVICE_TYPE[3].toByte(),
            0x01, disableMask.toByte(),
        )
        send(apdu, false)
    }
}
