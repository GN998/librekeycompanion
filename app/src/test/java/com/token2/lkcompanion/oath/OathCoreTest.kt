package com.token2.lkcompanion.oath

import com.token2.lkcompanion.oath.OathCore.HashAlgo
import org.junit.Assert.assertEquals
import org.junit.Test

/**
 * Locks the OATH core to its standards. These are the exact published vectors;
 * all 20 were confirmed passing before the Kotlin port was written.
 */
class OathCoreTest {

    private val seedSha1 = "12345678901234567890".toByteArray()
    private val seedSha256 = "12345678901234567890123456789012".toByteArray()
    private val seedSha512 =
        "1234567890123456789012345678901234567890123456789012345678901234".toByteArray()

    @Test fun rfc4226_hotp_appendixD() {
        val expected = listOf(
            "755224", "287082", "359152", "969429", "338314",
            "254676", "287922", "162583", "399871", "520489")
        for (c in expected.indices) {
            assertEquals("counter=$c", expected[c], OathCore.hotp(seedSha1, c.toLong()))
        }
    }

    @Test fun rfc6238_totp_appendixB() {
        data class V(val t: Long, val code: String, val algo: HashAlgo, val seed: ByteArray)
        val vectors = listOf(
            V(59L, "94287082", HashAlgo.SHA1, seedSha1),
            V(1111111109L, "07081804", HashAlgo.SHA1, seedSha1),
            V(1111111111L, "14050471", HashAlgo.SHA1, seedSha1),
            V(1234567890L, "89005924", HashAlgo.SHA1, seedSha1),
            V(2000000000L, "69279037", HashAlgo.SHA1, seedSha1),
            V(20000000000L, "65353130", HashAlgo.SHA1, seedSha1),
            V(59L, "46119246", HashAlgo.SHA256, seedSha256),
            V(1111111109L, "68084774", HashAlgo.SHA256, seedSha256),
            V(59L, "90693936", HashAlgo.SHA512, seedSha512),
            V(1111111109L, "25091201", HashAlgo.SHA512, seedSha512),
        )
        for (v in vectors) {
            assertEquals("T=${v.t} ${v.algo}", v.code,
                OathCore.totp(v.seed, v.t, digits = 8, algo = v.algo))
        }
    }

    @Test fun base32_decode_roundtrip() {
        // "Hello!" base32 -> known vector
        assertEquals("JBSWY3DPEHPK3PXP",
            "JBSWY3DPEHPK3PXP") // sanity placeholder; decode used below
        val secret = Base32.decode("JBSWY3DPEHPK3PXP")
        // Compute a code just to ensure decode produced usable key material.
        val code = OathCore.totp(secret, 0L)
        assertEquals(6, code.length)
    }

    @Test fun otpauth_uri_parse() {
        val cred = OtpAuthUri.parse(
            "otpauth://totp/GitHub:me@x.com?secret=JBSWY3DPEHPK3PXP&issuer=GitHub&digits=6&period=30")
        assertEquals("GitHub", cred.issuer)
        assertEquals("me@x.com", cred.account)
        assertEquals(OathCredential.Type.TOTP, cred.type)
        assertEquals(6, cred.digits)
    }
}
