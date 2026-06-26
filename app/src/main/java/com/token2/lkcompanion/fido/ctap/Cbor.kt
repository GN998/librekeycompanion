package com.token2.lkcompanion.fido.ctap

import java.io.ByteArrayOutputStream

/**
 * Minimal CBOR codec for CTAP2. Supports the subset CTAP uses: unsigned/negative
 * ints, byte strings, text strings, arrays, and maps (with int or text keys).
 * Encoding follows CTAP's canonical form (CTAP2 canonical CBOR): map keys sorted,
 * definite lengths, shortest-form integers.
 *
 * This is deliberately small and not a general CBOR library — just enough to talk
 * to an authenticator correctly.
 */
object Cbor {

    // ---- Decoding ----

    data class Decoded(val value: Any?, val next: Int)

    fun decode(bytes: ByteArray): Any? = decodeAt(bytes, 0).value

    fun decodeAt(b: ByteArray, start: Int): Decoded {
        var i = start
        val ib = b[i].toInt() and 0xFF; i++
        val major = ib ushr 5
        val info = ib and 0x1F
        val (len, ni) = readLength(b, i, info)
        i = ni
        return when (major) {
            0 -> Decoded(len, i)                                  // unsigned int
            1 -> Decoded(-1L - len, i)                            // negative int
            2 -> { val v = b.copyOfRange(i, i + len.toInt()); Decoded(v, i + len.toInt()) }  // byte string
            3 -> { val v = String(b, i, len.toInt(), Charsets.UTF_8); Decoded(v, i + len.toInt()) }  // text
            4 -> {                                                // array
                val out = ArrayList<Any?>()
                var j = i
                repeat(len.toInt()) { val d = decodeAt(b, j); out.add(d.value); j = d.next }
                Decoded(out, j)
            }
            5 -> {                                                // map
                val out = LinkedHashMap<Any?, Any?>()
                var j = i
                repeat(len.toInt()) {
                    val k = decodeAt(b, j); val v = decodeAt(b, k.next)
                    out[normalizeKey(k.value)] = v.value; j = v.next
                }
                Decoded(out, j)
            }
            7 -> when (info) {                                    // simple/float
                20 -> Decoded(false, i)
                21 -> Decoded(true, i)
                22 -> Decoded(null, i)
                else -> Decoded(null, i)
            }
            else -> throw IllegalArgumentException("Unsupported CBOR major type $major")
        }
    }

    private fun normalizeKey(k: Any?): Any? = when (k) {
        is Long -> k.toInt()
        else -> k
    }

    private fun readLength(b: ByteArray, i: Int, info: Int): Pair<Long, Int> = when {
        info < 24 -> info.toLong() to i
        info == 24 -> (b[i].toLong() and 0xFF) to (i + 1)
        info == 25 -> readUInt(b, i, 2)
        info == 26 -> readUInt(b, i, 4)
        info == 27 -> readUInt(b, i, 8)
        else -> throw IllegalArgumentException("bad CBOR length info $info")
    }

    private fun readUInt(b: ByteArray, i: Int, n: Int): Pair<Long, Int> {
        var v = 0L
        for (k in 0 until n) v = (v shl 8) or (b[i + k].toLong() and 0xFF)
        return v to (i + n)
    }

    // ---- Encoding ----

    fun encode(value: Any?): ByteArray {
        val out = ByteArrayOutputStream()
        encodeInto(out, value)
        return out.toByteArray()
    }

    private fun encodeInto(out: ByteArrayOutputStream, value: Any?) {
        when (value) {
            null -> out.write(0xF6)
            is Boolean -> out.write(if (value) 0xF5 else 0xF4)
            is Int -> encodeInt(out, value.toLong())
            is Long -> encodeInt(out, value)
            is ByteArray -> { writeHead(out, 2, value.size.toLong()); out.write(value) }
            is String -> { val u = value.toByteArray(Charsets.UTF_8); writeHead(out, 3, u.size.toLong()); out.write(u) }
            is List<*> -> { writeHead(out, 4, value.size.toLong()); value.forEach { encodeInto(out, it) } }
            is Map<*, *> -> encodeMap(out, value)
            else -> throw IllegalArgumentException("Cannot CBOR-encode ${value.javaClass}")
        }
    }

    private fun encodeInt(out: ByteArrayOutputStream, v: Long) {
        if (v >= 0) writeHead(out, 0, v)
        else writeHead(out, 1, -1L - v)
    }

    private fun encodeMap(out: ByteArrayOutputStream, map: Map<*, *>) {
        // CTAP canonical: keys sorted. Int keys sort by value; we keep insertion
        // order for already-correct callers but sort int-keyed maps to be safe.
        val entries = map.entries.toList()
        val allInt = entries.all { it.key is Int }
        val ordered = if (allInt) entries.sortedBy { (it.key as Int) } else entries
        writeHead(out, 5, ordered.size.toLong())
        for (e in ordered) { encodeInto(out, e.key); encodeInto(out, e.value) }
    }

    private fun writeHead(out: ByteArrayOutputStream, major: Int, len: Long) {
        val m = major shl 5
        when {
            len < 24 -> out.write(m or len.toInt())
            len < 0x100 -> { out.write(m or 24); out.write(len.toInt()) }
            len < 0x10000 -> { out.write(m or 25); out.write((len ushr 8).toInt()); out.write(len.toInt()) }
            len < 0x100000000 -> { out.write(m or 26)
                for (s in intArrayOf(24, 16, 8, 0)) out.write((len ushr s).toInt() and 0xFF) }
            else -> { out.write(m or 27)
                for (s in intArrayOf(56, 48, 40, 32, 24, 16, 8, 0)) out.write((len ushr s).toInt() and 0xFF) }
        }
    }
}
