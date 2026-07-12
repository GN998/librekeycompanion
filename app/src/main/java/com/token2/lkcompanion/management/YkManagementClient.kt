package com.token2.lkcompanion.management

import com.token2.lkcompanion.transport.Apdu
import com.token2.lkcompanion.transport.SmartCardTransport
import com.token2.lkcompanion.transport.TransportException

/**
 * YubiKey 5 Series **Management applet** client — reads and writes the
 * per-application "Enabled Capabilities" that decide which USB/NFC interfaces a
 * key exposes. This is the YubiKey analogue of the Token2 SET_DEVICE_TYPE
 * feature, but works at *application* granularity (OTP / U2F / FIDO2 / PIV /
 * OATH / OpenPGP) rather than raw interface bits, exactly as Yubico's
 * Configuration Reference specifies.
 *
 * Protocol (Yubico "YubiKey 5 Series Configuration Reference"):
 *   - Management applet AID: A0 00 00 05 27 47 11 17.
 *   - GET DEVICE INFO  = CCID INS 0x1D; response is TOTAL-LEN then TAG-LEN-VALUE
 *     triplets (supported/enabled USB caps, serial, form factor, firmware,
 *     lock flag, NFC caps…).
 *   - SET DEVICE INFO  = CCID INS 0x1C; body is one length byte then a list of
 *     TLVs. Appending a Reset TLV (0x0C, empty) makes the key reboot so the new
 *     interface set takes effect ("remove and reinsert your YubiKey").
 *   - Configuration Lock: if set, every SET must carry an Unlock TLV (0x0B) with
 *     the 16-byte code, or the write is refused.
 *
 * This client is transport-neutral: it drives the same [SmartCardTransport] the
 * app already uses over NFC (IsoDep) and USB CCID, so it works on whichever the
 * Token2 path uses. FIDO-HID delivery of these commands (HID 0xC2/0xC3) is a
 * separate wire and intentionally NOT implemented here — over USB the app
 * reaches the Management applet through CCID like PIV/OATH/OpenPGP do.
 *
 * Read path is safe. The write path reconfigures hardware; callers must confirm
 * with the user and must not disable the transport they're currently on.
 */
class YkManagementClient(private val transport: SmartCardTransport) {

    companion object {
        // Management applet AID (Configuration Reference / yubikit).
        val AID = byteArrayOf(
            0xA0.toByte(), 0x00, 0x00, 0x05, 0x27, 0x47, 0x11, 0x17
        )

        private const val INS_GET_DEVICE_INFO = 0x1D
        private const val INS_SET_DEVICE_INFO = 0x1C

        // --- Response tags (GET DEVICE INFO) ---
        private const val TAG_USB_SUPPORTED = 0x01
        private const val TAG_SERIAL = 0x02
        private const val TAG_USB_ENABLED = 0x03
        private const val TAG_FORM_FACTOR = 0x04
        private const val TAG_FIRMWARE = 0x05
        private const val TAG_AUTO_EJECT = 0x06
        private const val TAG_CHALRESP_TIMEOUT = 0x07
        private const val TAG_DEVICE_FLAGS = 0x08
        private const val TAG_CONFIG_LOCKED = 0x0A
        private const val TAG_NFC_SUPPORTED = 0x0D
        private const val TAG_NFC_ENABLED = 0x0E

        // --- Write tags (SET DEVICE INFO) ---
        private const val WTAG_USB_ENABLED = 0x03
        private const val WTAG_NFC_ENABLED = 0x0E
        private const val WTAG_UNLOCK = 0x0B          // supply existing lock code
        private const val WTAG_REBOOT = 0x0C          // force reboot after write

        // --- Capability (application) bits, USB & NFC alike ---
        const val CAPA_OTP = 0x0001
        const val CAPA_U2F = 0x0002
        const val CAPA_CCID = 0x0004                  // interface bit, not settable
        const val CAPA_OPENPGP = 0x0008
        const val CAPA_PIV = 0x0010
        const val CAPA_OATH = 0x0020
        const val CAPA_CTAP2 = 0x0200

        /** Config-lock length required by the applet. */
        const val LOCK_LEN = 16

        /** The applications a user can toggle, in display order, with labels. */
        val APPLICATIONS: List<Application> = listOf(
            Application(CAPA_OTP, "OTP", "Yubico OTP, static password, challenge-response"),
            Application(CAPA_U2F, "FIDO U2F", "legacy U2F sign-in"),
            Application(CAPA_CTAP2, "FIDO2", "passkeys / WebAuthn"),
            Application(CAPA_OATH, "OATH", "TOTP / HOTP accounts"),
            Application(CAPA_PIV, "PIV", "smart-card certificates"),
            Application(CAPA_OPENPGP, "OpenPGP", "GnuPG signing / decryption"),
        )
    }

    /** A user-toggleable application and its capability bit. */
    data class Application(val bit: Int, val name: String, val description: String)

    /**
     * Parsed device info. `usbSupported` / `nfcSupported` are the immutable
     * factory capability masks; the `*Enabled` masks are what's currently on and
     * what the user edits. `nfcAvailable` is false on non-NFC keys (the NFC tags
     * are simply absent from the response then).
     */
    data class DeviceInfo(
        val usbSupported: Int,
        val usbEnabled: Int,
        val nfcSupported: Int,
        val nfcEnabled: Int,
        val nfcAvailable: Boolean,
        val serial: Long?,
        val formFactor: Int,
        val firmware: String,
        val configLocked: Boolean,
    ) {
        fun usbHas(bit: Int) = usbSupported and bit != 0
        fun usbOn(bit: Int) = usbEnabled and bit != 0
        fun nfcHas(bit: Int) = nfcSupported and bit != 0
        fun nfcOn(bit: Int) = nfcEnabled and bit != 0
    }

    fun select(): ByteArray = transport.selectApplet(AID)

    /** GET DEVICE INFO (INS 0x1D), parsed. Selects the applet first. */
    fun readDeviceInfo(): DeviceInfo {
        select()
        val r = transport.transceive(Apdu.build(0x00, INS_GET_DEVICE_INFO, 0x00, 0x00, le = 0x00))
        if (!r.isSuccess)
            throw TransportException("GET DEVICE INFO failed, SW=${"%04X".format(r.sw)}")
        return parseDeviceInfo(r.data)
    }

    /**
     * SET DEVICE INFO (INS 0x1C): write new enabled-capability masks and reboot.
     *
     * @param usbEnabled desired USB capability mask (masked to supported by firmware).
     * @param nfcEnabled desired NFC capability mask, or null to leave NFC untouched.
     * @param lockCode   the current 16-byte config lock, required iff a lock is set.
     * @param reboot     append the reset TLV so the change takes effect immediately.
     */
    fun writeCapabilities(
        usbEnabled: Int,
        nfcEnabled: Int? = null,
        lockCode: ByteArray? = null,
        reboot: Boolean = true,
    ) {
        select()
        val body = ArrayList<Byte>()

        // Unlock TLV first if a code was supplied (may appear anywhere; first is
        // simplest). The applet requires it when a lock is set.
        if (lockCode != null) {
            require(lockCode.size == LOCK_LEN) { "config lock must be $LOCK_LEN bytes" }
            body.add(WTAG_UNLOCK.toByte()); body.add(LOCK_LEN.toByte())
            lockCode.forEach { body.add(it) }
        }

        // USB enabled capabilities: 2-byte big-endian mask.
        body.add(WTAG_USB_ENABLED.toByte()); body.add(0x02)
        body.add(((usbEnabled ushr 8) and 0xFF).toByte())
        body.add((usbEnabled and 0xFF).toByte())

        if (nfcEnabled != null) {
            body.add(WTAG_NFC_ENABLED.toByte()); body.add(0x02)
            body.add(((nfcEnabled ushr 8) and 0xFF).toByte())
            body.add((nfcEnabled and 0xFF).toByte())
        }

        if (reboot) {
            body.add(WTAG_REBOOT.toByte()); body.add(0x00)   // empty reset TLV
        }

        // SET DEVICE INFO payload is one length byte + the TLV list.
        require(body.size <= 0xFF) { "SET DEVICE INFO payload too long: ${body.size}" }
        val payload = ByteArray(1 + body.size)
        payload[0] = body.size.toByte()
        for (i in body.indices) payload[i + 1] = body[i]

        val r = transport.transceive(Apdu.build(0x00, INS_SET_DEVICE_INFO, 0x00, 0x00, payload))
        // On reboot some transports never see a clean 0x9000 because the key
        // resets mid-exchange; treat a transport drop after a reboot request as
        // success and let the caller prompt for re-insert.
        if (!r.isSuccess && !(reboot && r.sw == 0x0000))
            throw ManagementException.fromSw(r.sw)
    }

    private fun parseDeviceInfo(data: ByteArray): DeviceInfo {
        if (data.isEmpty()) throw TransportException("empty device-info response")
        // First byte is the total length of the TLV list that follows.
        val total = data[0].toInt() and 0xFF
        val end = (1 + total).coerceAtMost(data.size)
        val tlvs = HashMap<Int, ByteArray>()
        var i = 1
        while (i + 1 < end) {
            val tag = data[i].toInt() and 0xFF
            val len = data[i + 1].toInt() and 0xFF
            val vStart = i + 2
            val vEnd = (vStart + len).coerceAtMost(end)
            tlvs[tag] = data.copyOfRange(vStart, vEnd)
            i = vEnd
        }

        fun int(tag: Int, default: Int = 0): Int {
            val v = tlvs[tag] ?: return default
            var acc = 0
            for (b in v) acc = (acc shl 8) or (b.toInt() and 0xFF)
            return acc
        }

        val usbSupported = int(TAG_USB_SUPPORTED)
        val usbEnabled = int(TAG_USB_ENABLED)
        val nfcSupported = int(TAG_NFC_SUPPORTED, -1)
        val nfcAvailable = nfcSupported >= 0
        val nfcEnabled = int(TAG_NFC_ENABLED)
        val serialTlv = tlvs[TAG_SERIAL]
        val serial = serialTlv?.let {
            var acc = 0L; for (b in it) acc = (acc shl 8) or (b.toLong() and 0xFF); acc
        }
        val ff = int(TAG_FORM_FACTOR)
        val fwTlv = tlvs[TAG_FIRMWARE]
        val fw = if (fwTlv != null && fwTlv.size >= 3)
            "${fwTlv[0].toInt() and 0xFF}.${fwTlv[1].toInt() and 0xFF}.${fwTlv[2].toInt() and 0xFF}"
        else "?"
        val locked = int(TAG_CONFIG_LOCKED) != 0

        return DeviceInfo(
            usbSupported = usbSupported,
            usbEnabled = usbEnabled,
            nfcSupported = if (nfcAvailable) nfcSupported else 0,
            nfcEnabled = nfcEnabled,
            nfcAvailable = nfcAvailable,
            serial = serial,
            formFactor = ff,
            firmware = fw,
            configLocked = locked,
        )
    }
}

/** Errors specific to the Management applet write path. */
sealed class ManagementException(message: String) : Exception(message) {
    /** SET refused because a config lock is set and no/incorrect code was given. */
    object LockedOrWrongCode : ManagementException(
        "the key's configuration is locked; the correct 16-byte lock code is required"
    )
    class BadStatus(val sw: Int) : ManagementException("management command failed, SW=${"%04X".format(sw)}")

    companion object {
        fun fromSw(sw: Int): ManagementException = when (sw) {
            // 6982 security status not satisfied; 6985 conditions not satisfied —
            // both are what the applet returns when the lock gate isn't cleared.
            0x6982, 0x6985 -> LockedOrWrongCode
            else -> BadStatus(sw)
        }
    }
}
