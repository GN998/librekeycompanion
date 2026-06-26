package com.token2.lkcompanion.transport

/**
 * A duplex byte channel to a hardware security key, abstracting over the two
 * Android transports: NFC (ISO 14443-4 / IsoDep) and USB (CCID over the USB
 * Host API). Both deliver ISO 7816-4 APDUs; this interface hides the framing
 * differences so the OATH / OpenPGP / PIV / FIDO applet layers stay transport
 * agnostic — a transport/applet split between the byte layer and
 * its protocol crates.
 *
 * Implementations MUST handle:
 *  - APDU response chaining (status 0x61xx -> issue GET RESPONSE)
 *  - command chaining for payloads exceeding the negotiated frame size
 *  - extended vs short Lc/Le encoding
 */
interface SmartCardTransport {

    /** Human-facing description, e.g. "YubiKey 5 NFC (NFC)". */
    val displayName: String

    /** True once a card/applet channel is open and ready for [transceive]. */
    val isConnected: Boolean

    /**
     * Select an applet by its AID and return the raw selection response
     * (without the trailing SW1SW2), or throw [TransportException] if the
     * applet is absent / selection fails.
     */
    fun selectApplet(aid: ByteArray): ByteArray

    /**
     * Send one command APDU, transparently performing GET RESPONSE chaining,
     * and return the full response body. The two status bytes are stripped
     * from [ResponseApdu.data] and exposed via [ResponseApdu.sw].
     */
    fun transceive(command: ByteArray): ResponseApdu

    fun close()
}

/** Parsed ISO 7816-4 response: payload plus the 16-bit status word. */
data class ResponseApdu(val data: ByteArray, val sw: Int) {
    val sw1: Int get() = (sw ushr 8) and 0xFF
    val sw2: Int get() = sw and 0xFF
    val isSuccess: Boolean get() = sw == 0x9000

    override fun equals(other: Any?): Boolean =
        other is ResponseApdu && sw == other.sw && data.contentEquals(other.data)

    override fun hashCode(): Int = 31 * data.contentHashCode() + sw
}

class TransportException(message: String, cause: Throwable? = null) :
    Exception(message, cause)
