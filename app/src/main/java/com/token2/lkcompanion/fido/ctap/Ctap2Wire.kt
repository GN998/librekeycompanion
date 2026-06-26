package com.token2.lkcompanion.fido.ctap

import android.hardware.usb.UsbDeviceConnection
import android.hardware.usb.UsbEndpoint
import android.hardware.usb.UsbInterface
import com.token2.lkcompanion.transport.Apdu
import com.token2.lkcompanion.transport.SmartCardTransport

/**
 * Abstracts "send one CTAP2 command, get the response body back" so [Ctap2Client]
 * can run over either transport family:
 *
 *  - [ApduWire]    — NFC ISO-DEP and USB CCID, where CTAP rides the ISO7816 APDU
 *                    envelope (NFCCTAP_MSG, 80 10 00 00).
 *  - [CtapHidWire] — USB HID, where CTAP is framed directly with the CTAPHID
 *                    protocol (64-byte reports, channel negotiation). FIDO over
 *                    USB is HID-only on essentially all keys; the CCID interface
 *                    refuses the FIDO applet (SW 6A81).
 *
 * Return value is the raw response: first byte is the CTAP status, remainder is
 * CBOR. [Ctap2Client] interprets it.
 */
interface Ctap2Wire {
    /** Send a CTAP2 command byte + CBOR params; return status byte + CBOR body. */
    fun send(command: Int, data: ByteArray): ByteArray
    /** Select the FIDO application if the transport needs it (APDU does; HID doesn't). */
    fun selectFido()
    fun close() {}
}

/** APDU-framed CTAP for NFC ISO-DEP and USB CCID. */
class ApduWire(private val transport: SmartCardTransport) : Ctap2Wire {
    private val fidoAid = byteArrayOf(
        0xA0.toByte(), 0x00, 0x00, 0x06, 0x47, 0x2F, 0x00, 0x01)

    override fun selectFido() { transport.selectApplet(fidoAid) }

    override fun send(command: Int, data: ByteArray): ByteArray {
        val payload = byteArrayOf(command.toByte()) + data
        val resp = transport.transceive(Apdu.build(0x80, 0x10, 0x00, 0x00, payload))
        if (!resp.isSuccess) throw CtapError(0xFF)
        return resp.data
    }

    override fun close() = transport.close()
}

/**
 * CTAPHID-framed CTAP for USB HID. Implements channel allocation (CTAPHID_INIT)
 * and the init/continuation packet framing for CTAPHID_CBOR.
 *
 * Framing VERIFIED against the FIDO CTAP spec (see ctaphid_frame.py): 64-byte
 * reports, 57 data bytes in the init packet, 59 in each continuation, BCNT in the
 * init header.
 */
class CtapHidWire(
    private val connection: UsbDeviceConnection,
    private val hidInterface: UsbInterface,
    private val outEp: UsbEndpoint,
    private val inEp: UsbEndpoint,
) : Ctap2Wire {

    private var channelId = byteArrayOf(0xFF.toByte(), 0xFF.toByte(), 0xFF.toByte(), 0xFF.toByte())

    init {
        connection.claimInterface(hidInterface, true)
        drainStaleReports()
        allocateChannel()
    }

    /**
     * After claiming the interface, the endpoint may have a stale report buffered
     * (observed on Pico-FIDO: the first read returns leftover data like "...PINLen"
     * rather than our response). Drain whatever is already queued before we start,
     * with a short timeout, so the first real read matches our command.
     */
    private fun drainStaleReports() {
        val buf = ByteArray(REPORT)
        var guard = 0
        while (guard++ < 8) {
            val n = connection.bulkTransfer(inEp, buf, buf.size, 50)
            if (n <= 0) break   // nothing left queued
        }
    }

    /** CTAPHID_INIT on the broadcast channel; read until we see the INIT reply that
     *  echoes our nonce (draining any unrelated/stale frames in between). */
    private fun allocateChannel() {
        val nonce = ByteArray(8).also { java.security.SecureRandom().nextBytes(it) }
        val bcast = byteArrayOf(0xFF.toByte(), 0xFF.toByte(), 0xFF.toByte(), 0xFF.toByte())
        writeMessage(bcast, CTAPHID_INIT, nonce)

        val deadline = System.currentTimeMillis() + 3_000
        while (System.currentTimeMillis() < deadline) {
            val pkt = readReportRaw() ?: continue
            // INIT replies on the broadcast channel; command byte must be 0x80|INIT.
            val cmd = pkt[4].toInt() and 0xFF
            if (cmd != (0x80 or CTAPHID_INIT)) continue       // stale/other frame; skip
            // payload starts at offset 7: nonce(8) | newCID(4) | ...
            var match = true
            for (k in 0 until 8) if (pkt[7 + k] != nonce[k]) { match = false; break }
            if (!match) continue                              // not our INIT echo; skip
            channelId = byteArrayOf(pkt[15], pkt[16], pkt[17], pkt[18])
            return
        }
        throw CtapError(0xFF)   // no valid INIT response within timeout
    }

    /** One raw 64-byte report, or null on a (transient) empty/timeout read. */
    private fun readReportRaw(): ByteArray? {
        if (useInterrupt) return readReportInterrupt(READ_POLL_TIMEOUT)
        val buf = ByteArray(REPORT)
        val n = connection.bulkTransfer(inEp, buf, buf.size, READ_POLL_TIMEOUT)
        return if (n > 0) buf else null
    }

    override fun selectFido() { /* not needed for CTAPHID */ }

    override fun send(command: Int, data: ByteArray): ByteArray {
        // CTAPHID_CBOR carries: <ctap command byte> <cbor...> as the message body.
        val body = byteArrayOf(command.toByte()) + data
        val resp = transact(channelId, CTAPHID_CBOR, body)
        // resp[0] is the CTAP status byte, rest is CBOR — same shape ApduWire returns.
        return resp
    }

    /** Send one CTAPHID message and read the matching response message. */
    private fun transact(cid: ByteArray, cmd: Int, data: ByteArray): ByteArray {
        writeMessage(cid, cmd, data)
        return readMessage(cid)
    }

    private fun writeMessage(cid: ByteArray, cmd: Int, data: ByteArray) {
        // init packet
        val first = ByteArray(REPORT)
        System.arraycopy(cid, 0, first, 0, 4)
        first[4] = (0x80 or cmd).toByte()
        first[5] = ((data.size ushr 8) and 0xFF).toByte()
        first[6] = (data.size and 0xFF).toByte()
        val firstChunk = minOf(57, data.size)
        System.arraycopy(data, 0, first, 7, firstChunk)
        writeReport(first)
        // continuation packets
        var offset = firstChunk
        var seq = 0
        while (offset < data.size) {
            val p = ByteArray(REPORT)
            System.arraycopy(cid, 0, p, 0, 4)
            p[4] = (seq and 0x7F).toByte()
            val chunk = minOf(59, data.size - offset)
            System.arraycopy(data, offset, p, 5, chunk)
            writeReport(p)
            offset += chunk
            seq++
        }
    }

    private fun readMessage(cid: ByteArray): ByteArray {
        // Read the init packet for OUR channel, skipping KEEPALIVE frames (the key
        // sends these while waiting for user presence during PIN ops) and ignoring
        // packets addressed to other channels.
        var first: ByteArray
        while (true) {
            first = readReport()
            // Must be for our channel; ignore anything else.
            if (!(first[0] == cid[0] && first[1] == cid[1] &&
                  first[2] == cid[2] && first[3] == cid[3])) continue
            val cmd = first[4].toInt() and 0xFF
            if (cmd == (0x80 or CTAPHID_KEEPALIVE)) continue       // busy/UP-needed; wait
            if (cmd == (0x80 or CTAPHID_ERROR)) throw CtapError(0xFF)
            break
        }
        val bcnt = ((first[5].toInt() and 0xFF) shl 8) or (first[6].toInt() and 0xFF)
        val out = ByteArray(bcnt)
        var got = minOf(57, bcnt)
        if (got > 0) System.arraycopy(first, 7, out, 0, got)
        // continuation packets (for our channel)
        while (got < bcnt) {
            val p = readReport()
            if (!(p[0] == cid[0] && p[1] == cid[1] &&
                  p[2] == cid[2] && p[3] == cid[3])) continue       // not ours; skip
            val take = minOf(59, bcnt - got)
            System.arraycopy(p, 5, out, got, take)
            got += take
        }
        return out
    }

    // Interrupt endpoints (FIDO HID is interrupt, not bulk) are best driven with
    // UsbRequest.queue()/requestWait(); bulkTransfer() on an interrupt endpoint works
    // on lenient stacks (Pico/YubiKey) but fails on stricter ones (e.g. Feitian).
    private val useInterrupt =
        inEp.type == android.hardware.usb.UsbConstants.USB_ENDPOINT_XFER_INT ||
        outEp.type == android.hardware.usb.UsbConstants.USB_ENDPOINT_XFER_INT

    private fun writeReport(report: ByteArray) {
        if (useInterrupt) {
            val req = android.hardware.usb.UsbRequest()
            try {
                if (!req.initialize(connection, outEp)) throw CtapError(0xFF)
                val bb = java.nio.ByteBuffer.allocate(report.size)
                bb.put(report); bb.flip()
                if (!req.queue(bb, report.size)) throw CtapError(0xFF)
                if (connection.requestWait() == null) throw CtapError(0xFF)
            } finally { req.close() }
        } else {
            val n = connection.bulkTransfer(outEp, report, report.size, TIMEOUT)
            if (n < 0) throw CtapError(0xFF)
        }
    }

    /** One interrupt IN report via UsbRequest, or null on timeout. */
    private fun readReportInterrupt(timeoutMs: Int): ByteArray? {
        val req = android.hardware.usb.UsbRequest()
        try {
            if (!req.initialize(connection, inEp)) return null
            val bb = java.nio.ByteBuffer.allocate(REPORT)
            if (!req.queue(bb, REPORT)) return null
            val done = try { connection.requestWait(timeoutMs.toLong()) }
                catch (_: Throwable) { connection.requestWait() }
            if (done == null) return null
            // bb.position() is the number of bytes received; reports are REPORT-sized.
            val count = bb.position()
            if (count <= 0) return null
            val out = ByteArray(REPORT)
            bb.flip()
            bb.get(out, 0, minOf(count, REPORT))
            return out
        } finally { req.close() }
    }

    /**
     * Read one 64-byte HID report. Interrupt endpoints can return 0 (no data
     * ready) — retry rather than treating that as a packet. A negative return is a
     * real error/timeout. The longer overall timeout covers PIN operations where
     * the key waits for a finger touch.
     */
    private fun readReport(): ByteArray {
        val deadline = System.currentTimeMillis() + READ_TOTAL_TIMEOUT
        while (true) {
            if (useInterrupt) {
                val r = readReportInterrupt(READ_POLL_TIMEOUT)
                if (r != null) return r
                if (System.currentTimeMillis() > deadline) throw CtapError(0xFF)
                continue
            }
            val buf = ByteArray(REPORT)
            val n = connection.bulkTransfer(inEp, buf, buf.size, READ_POLL_TIMEOUT)
            if (n > 0) return buf
            if (n == 0) {                                          // no data yet; keep polling
                if (System.currentTimeMillis() > deadline) throw CtapError(0xFF)
                continue
            }
            // n < 0: timeout for this poll. Keep polling until the overall deadline.
            if (System.currentTimeMillis() > deadline) throw CtapError(0xFF)
        }
    }

    override fun close() {
        try { connection.releaseInterface(hidInterface) } catch (_: Exception) {}
    }

    companion object {
        private const val REPORT = 64
        private const val TIMEOUT = 5_000
        private const val READ_POLL_TIMEOUT = 500      // per bulkTransfer poll
        private const val READ_TOTAL_TIMEOUT = 30_000  // overall; covers user-presence touch
        private const val CTAPHID_INIT = 0x06
        private const val CTAPHID_CBOR = 0x10
        private const val CTAPHID_ERROR = 0x3F
        private const val CTAPHID_KEEPALIVE = 0x3B

        /** Diagnostic variant of [find]: returns a human-readable report of what each
         *  HID interface does when probed, instead of a wire. For the USB diag screen. */
        fun findDiagnostic(connection: UsbDeviceConnection, device: android.hardware.usb.UsbDevice): String {
            val sb = StringBuilder()
            var any = false
            for (i in 0 until device.interfaceCount) {
                val iface = device.getInterface(i)
                if (iface.interfaceClass != android.hardware.usb.UsbConstants.USB_CLASS_HID) continue
                any = true
                var inEp: UsbEndpoint? = null
                var outEp: UsbEndpoint? = null
                for (e in 0 until iface.endpointCount) {
                    val ep = iface.getEndpoint(e)
                    if (ep.type != android.hardware.usb.UsbConstants.USB_ENDPOINT_XFER_INT) continue
                    if (ep.direction == android.hardware.usb.UsbConstants.USB_DIR_IN) inEp = ep
                    else outEp = ep
                }
                sb.append("HID if id=${iface.id}: ")
                if (inEp == null || outEp == null) { sb.append("no INT in/out eps\n"); continue }
                val desc = isFidoHidInterface(connection, iface)
                sb.append("descFIDO=$desc ")
                val claimed = connection.claimInterface(iface, true)
                if (!claimed) { sb.append("claim=FAIL\n"); continue }
                try {
                    val nonce = ByteArray(8).also { java.security.SecureRandom().nextBytes(it) }
                    val pkt = ByteArray(64)
                    pkt[0] = 0xFF.toByte(); pkt[1] = 0xFF.toByte(); pkt[2] = 0xFF.toByte(); pkt[3] = 0xFF.toByte()
                    pkt[4] = (0x80 or 0x06).toByte(); pkt[5] = 0; pkt[6] = 8
                    System.arraycopy(nonce, 0, pkt, 7, 8)
                    val w = connection.bulkTransfer(outEp, pkt, pkt.size, 1_000)
                    sb.append("write=$w ")
                    if (w < 0) { sb.append("\n"); continue }
                    // Drain any stale buffered report first, counting how many.
                    var drained = 0
                    run {
                        val d = ByteArray(64)
                        while (drained < 8 && connection.bulkTransfer(inEp, d, d.size, 50) > 0) drained++
                    }
                    // Re-send INIT after draining (the stale frame may have eaten it).
                    connection.bulkTransfer(outEp, pkt, pkt.size, 1_000)
                    val buf = ByteArray(64)
                    var got = -2
                    var matched = false
                    val deadline = System.currentTimeMillis() + 2_000
                    while (System.currentTimeMillis() < deadline) {
                        val n = connection.bulkTransfer(inEp, buf, buf.size, 500)
                        if (n <= 0) continue
                        got = n
                        val cmd = buf[4].toInt() and 0xFF
                        if (cmd == (0x80 or 0x06) && (0 until 8).all { buf[7 + it] == nonce[it] }) {
                            matched = true; break
                        }
                    }
                    sb.append("drained=$drained ")
                    if (matched) {
                        sb.append("INIT-OK newCID=%02X%02X%02X%02X\n".format(
                            buf[15], buf[16], buf[17], buf[18]))
                    } else if (got > 0) {
                        val cmd = buf[4].toInt() and 0xFF
                        sb.append("last cmd=%02X (no INIT echo)\n".format(cmd))
                        val hex = StringBuilder()
                        for (k in 0 until minOf(20, 64)) hex.append("%02X ".format(buf[k].toInt() and 0xFF))
                        sb.append("  raw: $hex\n")
                    } else {
                        sb.append("read=timeout\n")
                    }
                } finally {
                    try { connection.releaseInterface(iface) } catch (_: Exception) {}
                }
            }
            if (!any) sb.append("(no HID interfaces found)\n")
            return sb.toString()
        }

        /**
         * Find the FIDO/CTAPHID interface + its interrupt IN/OUT endpoints.
         *
         * Composite keys (e.g. Pico-FIDO) expose several HID interfaces — keyboard,
         * OTP, FIDO. Picking the first HID interface can grab the wrong one, and the
         * CTAPHID INIT then never gets a reply (the read hangs).
         *
         * Strategy, most reliable first:
         *  1. Match the HID report descriptor's FIDO usage page (0xF1D0).
         *  2. If that yields nothing, actively probe each candidate HID interface with
         *     a real CTAPHID_INIT and keep whichever one answers with our nonce. This
         *     is firmware-agnostic — the FIDO interface is the one that speaks CTAPHID.
         *  3. As a last resort, the first usable HID interface.
         */
        fun find(connection: UsbDeviceConnection, device: android.hardware.usb.UsbDevice): CtapHidWire? {
            data class Cand(val iface: UsbInterface, val inEp: UsbEndpoint, val outEp: UsbEndpoint)
            val candidates = ArrayList<Cand>()
            for (i in 0 until device.interfaceCount) {
                val iface = device.getInterface(i)
                if (iface.interfaceClass != android.hardware.usb.UsbConstants.USB_CLASS_HID) continue
                var inEp: UsbEndpoint? = null
                var outEp: UsbEndpoint? = null
                for (e in 0 until iface.endpointCount) {
                    val ep = iface.getEndpoint(e)
                    if (ep.type != android.hardware.usb.UsbConstants.USB_ENDPOINT_XFER_INT) continue
                    if (ep.direction == android.hardware.usb.UsbConstants.USB_DIR_IN) inEp = ep
                    else outEp = ep
                }
                if (inEp != null && outEp != null) candidates.add(Cand(iface, inEp, outEp))
            }
            if (candidates.isEmpty()) return null

            // 1. Report-descriptor match.
            for (c in candidates)
                if (isFidoHidInterface(connection, c.iface))
                    return CtapHidWire(connection, c.iface, c.outEp, c.inEp)

            // 2. Active INIT probe — the FIDO interface answers, others don't.
            if (candidates.size > 1) {
                for (c in candidates)
                    if (respondsToInit(connection, c.iface, c.inEp, c.outEp))
                        return CtapHidWire(connection, c.iface, c.outEp, c.inEp)
            }

            // 3. Last resort: first usable HID interface.
            val c = candidates.first()
            return CtapHidWire(connection, c.iface, c.outEp, c.inEp)
        }

        /** Quick CTAPHID_INIT handshake test: does this interface speak CTAPHID? */
        private fun respondsToInit(
            connection: UsbDeviceConnection, iface: UsbInterface,
            inEp: UsbEndpoint, outEp: UsbEndpoint,
        ): Boolean {
            if (!connection.claimInterface(iface, true)) return false
            try {
                // Drain any stale buffered report first (Pico-FIDO queues leftover data).
                run {
                    val d = ByteArray(64); var g = 0
                    while (g++ < 8 && connection.bulkTransfer(inEp, d, d.size, 50) > 0) {}
                }
                val nonce = ByteArray(8).also { java.security.SecureRandom().nextBytes(it) }
                val pkt = ByteArray(64)
                // broadcast CID ff ff ff ff, cmd = INIT (0x80|0x06), bcnt = 8, nonce
                pkt[0] = 0xFF.toByte(); pkt[1] = 0xFF.toByte(); pkt[2] = 0xFF.toByte(); pkt[3] = 0xFF.toByte()
                pkt[4] = (0x80 or 0x06).toByte()
                pkt[5] = 0; pkt[6] = 8
                System.arraycopy(nonce, 0, pkt, 7, 8)
                if (connection.bulkTransfer(outEp, pkt, pkt.size, 1_000) < 0) return false
                // Read a few reports looking for an INIT reply echoing our nonce.
                val buf = ByteArray(64)
                val deadline = System.currentTimeMillis() + 1_500
                while (System.currentTimeMillis() < deadline) {
                    val n = connection.bulkTransfer(inEp, buf, buf.size, 500)
                    if (n <= 0) continue
                    val cmd = buf[4].toInt() and 0xFF
                    if (cmd == (0x80 or 0x06)) {
                        // INIT response: nonce(8) starts at offset 7
                        var match = true
                        for (k in 0 until 8) if (buf[7 + k] != nonce[k]) { match = false; break }
                        if (match) return true
                    }
                }
                return false
            } catch (_: Exception) {
                return false
            } finally {
                try { connection.releaseInterface(iface) } catch (_: Exception) {}
            }
        }

        /** Read the interface's HID report descriptor and check for FIDO usage page 0xF1D0. */
        private fun isFidoHidInterface(
            connection: UsbDeviceConnection, iface: UsbInterface,
        ): Boolean {
            val buf = ByteArray(256)
            val n = connection.controlTransfer(
                0x81, 0x06, 0x22 shl 8, iface.id, buf, buf.size, 1_000,
            )
            if (n <= 0) return false
            var i = 0
            while (i < n - 2) {
                if ((buf[i].toInt() and 0xFF) == 0x06 &&
                    (buf[i + 1].toInt() and 0xFF) == 0xD0 &&
                    (buf[i + 2].toInt() and 0xFF) == 0xF1) return true
                i++
            }
            return false
        }
    }
}
