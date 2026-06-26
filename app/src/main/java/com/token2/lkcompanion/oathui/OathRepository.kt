package com.token2.lkcompanion.oathui

import com.token2.lkcompanion.oath.OathApplet
import com.token2.lkcompanion.oath.OathCredential
import com.token2.lkcompanion.transport.SmartCardTransport
import com.token2.lkcompanion.transport.TransportException

/**
 * Arm-then-tap repository for the standard OATH applet (YKOATH protocol), used by
 * keys like Pico-FIDO and YubiKeys. Mirrors [com.token2.lkcompanion.token2ui.Token2Repository]
 * so the OTP tab can drive either applet through the same UI.
 *
 * TOTP only for now (HOTP enumerates fine but we don't surface a live code for it).
 */
class OathRepository {

    sealed class PendingOp {
        object Refresh : PendingOp()
        data class Add(val cred: OathCredential, val allowOverwrite: Boolean = false) : PendingOp()
        data class Delete(val name: String) : PendingOp()
    }

    /** Unified display row the OTP adapter can render (same shape for both applets). */
    data class Display(
        val name: String,        // raw applet name (issuer:account), used for delete
        val issuer: String,      // shown as title
        val account: String,     // shown as subtitle
        val code: String?,       // live TOTP code, or null
        val isTotp: Boolean,
    )

    sealed class OpResult {
        data class Success(val message: String, val entries: List<Display>) : OpResult()
        data class Failure(val message: String) : OpResult()
        data class DuplicateExists(val existingLabel: String, val cred: OathCredential,
                                   val entries: List<Display>) : OpResult()
        object NotAnOathKey : OpResult()
    }

    @Volatile private var pending: PendingOp = PendingOp.Refresh
    @Volatile private var cached: List<Display> = emptyList()

    fun arm(op: PendingOp) { pending = op }
    val cachedEntries get() = cached

    fun executeOn(transport: SmartCardTransport): OpResult {
        val applet = OathApplet(transport)
        try {
            applet.select()
        } catch (e: Exception) {
            return OpResult.NotAnOathKey
        }
        return try {
            when (val op = pending) {
                is PendingOp.Refresh -> OpResult.Success("Read OATH", readAll(applet))
                is PendingOp.Add -> {
                    val existing = readAll(applet)
                    if (!op.allowOverwrite) {
                        val dup = existing.firstOrNull {
                            it.issuer.equals(op.cred.issuer ?: "", true) &&
                                it.account.equals(op.cred.account, true)
                        }
                        if (dup != null)
                            return OpResult.DuplicateExists(dup.issuer + " / " + dup.account, op.cred, existing)
                    }
                    applet.put(op.cred)
                    pending = PendingOp.Refresh
                    OpResult.Success("Added ${op.cred.account}", readAll(applet))
                }
                is PendingOp.Delete -> {
                    applet.delete(op.name)
                    pending = PendingOp.Refresh
                    OpResult.Success("Deleted", readAll(applet))
                }
            }
        } catch (e: TransportException) {
            OpResult.Failure(e.message ?: "OATH error")
        } catch (e: Exception) {
            OpResult.Failure(e.message ?: e.javaClass.simpleName)
        }
    }

    /** List credentials and compute a live TOTP code for each time-based one. */
    private fun readAll(applet: OathApplet): List<Display> {
        val now = System.currentTimeMillis() / 1000
        val out = ArrayList<Display>()
        for (c in applet.list()) {
            val isTotp = (c.typeAlgo and 0xF0) == 0x20   // 0x20 = TOTP, 0x10 = HOTP
            val (issuer, account) = splitName(c.name)
            val code = if (isTotp)
                runCatching { applet.calculate(c.name, now) }.getOrNull()
            else null
            out.add(Display(c.name, issuer, account, code, isTotp))
        }
        cached = out
        return out
    }

    /** YKOATH names are "issuer:account" (issuer optional). */
    private fun splitName(name: String): Pair<String, String> {
        val idx = name.indexOf(':')
        return if (idx >= 0) name.substring(0, idx) to name.substring(idx + 1)
        else "" to name
    }
}
