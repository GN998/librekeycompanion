package com.token2.lkcompanion.token2

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Locks the Token2 codec to the protocol spec. The entry parser is checked against
 * the §10.1 worked trace (using the type byte the spec's prose mandates — see the
 * note in Token2Codec about the example's editorial slip), and write/delete
 * serialization against §10.2 / §6.4.
 */
class Token2CodecTest {

    private fun hex(s: String) = ByteArray(s.length / 2) {
        ((s[it*2].digitToInt(16) shl 4) or s[it*2+1].digitToInt(16)).toByte()
    }

    @Test fun parseEnumPage_single_totp_entry() {
        // §10.1 with the prose-correct leading type byte 0x01 (TOTP), partial flag clear.
        val page = hex("01C1001E0600045465737405616C69636506313233343536")
        val (entries, more) = Token2Codec.parseEnumPage(page, fullDecode = false)
        assertFalse(more)
        assertEquals(1, entries.size)
        val e = entries[0]
        assertEquals(Token2Codec.TYPE_TOTP, e.type)
        assertEquals(Token2Codec.ALG_SHA1, e.algorithm)
        assertEquals(30, e.timestep)
        assertEquals(6, e.codeLength)
        assertFalse(e.buttonRequired)
        assertEquals("Test", e.appName)
        assertEquals("alice", e.accountName)
        assertEquals("123456", e.otpCode)
    }

    @Test fun parseEnumPage_partial_flag_set() {
        // High bit of first byte set => more pages; type underneath is still TOTP.
        val page = hex("81C1001E0600045465737405616C69636506313233343536")
        val (entries, more) = Token2Codec.parseEnumPage(page, fullDecode = false)
        assertTrue(more)
        assertEquals("123456", entries[0].otpCode)
    }

    @Test fun parseEnumPage_hotp_has_no_code_tail() {
        // type=00 (HOTP) => no otp_code tail; parser must not read one.
        val page = hex("00C1001E0600045465737405616C696365")
        val (entries, _) = Token2Codec.parseEnumPage(page, fullDecode = false)
        assertEquals(Token2Codec.TYPE_HOTP, entries[0].type)
        assertEquals(null, entries[0].otpCode)
    }

    @Test fun serializeWriteEntry_matches_trace() {
        // §10.2 cleartext for ("Test","alice", seed="Hello", SHA1, TOTP, 30, 6, no btn)
        val e = Token2Codec.Entry(
            type = Token2Codec.TYPE_TOTP, algorithm = Token2Codec.ALG_SHA1,
            timestep = 30, codeLength = 6, buttonRequired = false,
            appName = "Test", accountName = "alice", seed = "Hello".toByteArray())
        val expected = hex("01C1001E060004") + "Test".toByteArray() +
            byteArrayOf(5) + "alice".toByteArray() + byteArrayOf(5) + "Hello".toByteArray()
        assertArrayEquals(expected, Token2Codec.serializeWriteEntry(e))
    }

    @Test fun serializeReadAll_format() {
        val req = Token2Codec.serializeReadAll(0L)
        assertArrayEquals(hex("030000000000000000"), req)  // 0x03 || u64_be(0)
    }

    @Test(expected = IllegalArgumentException::class)
    fun validateWrite_rejects_bad_code_length() {
        val e = Token2Codec.Entry(Token2Codec.TYPE_TOTP, Token2Codec.ALG_SHA1,
            30, 12, false, "a", "b", seed = "x".toByteArray())
        Token2Codec.serializeWriteEntry(e)
    }
}
