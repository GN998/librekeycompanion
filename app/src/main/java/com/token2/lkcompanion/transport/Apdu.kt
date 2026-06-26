package com.token2.lkcompanion.transport

import java.io.ByteArrayOutputStream

/**
 * ISO 7816-4 APDU construction and response-chaining helpers, shared by every
 * applet module. Implements the byte-layer responsibilities normally kept in
 * its per-protocol crates, but kept transport-neutral here.
 *
 * Only short-form encoding is implemented for command bodies <= 255 bytes, with
 * command chaining (CLA bit 0x10) for longer payloads. GET RESPONSE handling
 * for 0x61xx is centralised in [drainChaining].
 */
object Apdu {

    const val CLA_CHAIN = 0x10

    /** Build a short-form APDU. data may be empty; le=0 requests max 256 bytes. */
    fun build(cla: Int, ins: Int, p1: Int, p2: Int,
              data: ByteArray = ByteArray(0), le: Int? = null): ByteArray {
        val out = ByteArrayOutputStream()
        out.write(cla and 0xFF)
        out.write(ins and 0xFF)
        out.write(p1 and 0xFF)
        out.write(p2 and 0xFF)
        if (data.isNotEmpty()) {
            require(data.size <= 255) { "use buildChained for bodies > 255 bytes" }
            out.write(data.size)
            out.write(data)
        }
        if (le != null) out.write(le and 0xFF)
        return out.toByteArray()
    }

    /**
     * Split a long body into chained command APDUs (CLA |= 0x10 on all but the
     * last). The caller transceives each in order; only the final response
     * carries the meaningful SW.
     */
    fun buildChained(cla: Int, ins: Int, p1: Int, p2: Int,
                     data: ByteArray, le: Int? = null): List<ByteArray> {
        if (data.size <= 255) return listOf(build(cla, ins, p1, p2, data, le))
        val frames = data.toList().chunked(255)
        return frames.mapIndexed { i, chunk ->
            val last = i == frames.lastIndex
            val claByte = if (last) cla else (cla or CLA_CHAIN)
            build(claByte, ins, p1, p2, chunk.toByteArray(), if (last) le else null)
        }
    }

    fun parseResponse(raw: ByteArray): ResponseApdu {
        require(raw.size >= 2) { "APDU response too short: ${raw.size} bytes" }
        val sw = ((raw[raw.size - 2].toInt() and 0xFF) shl 8) or
                 (raw[raw.size - 1].toInt() and 0xFF)
        return ResponseApdu(raw.copyOfRange(0, raw.size - 2), sw)
    }

    /**
     * Centralised GET RESPONSE loop. Given a freshly parsed response and a
     * function that sends a raw APDU and returns the raw bytes, accumulate the
     * body across all 0x61xx continuations and return the assembled response.
     */
    fun drainChaining(first: ResponseApdu, send: (ByteArray) -> ByteArray): ResponseApdu {
        var acc = first.data
        var sw = first.sw
        while ((sw ushr 8) == 0x61) {
            val remaining = sw and 0xFF          // 0 means "256 or unknown"
            val le = if (remaining == 0) 0x00 else remaining
            val next = parseResponse(send(build(0x00, 0xC0, 0x00, 0x00, le = le)))
            acc += next.data
            sw = next.sw
        }
        return ResponseApdu(acc, sw)
    }
}
