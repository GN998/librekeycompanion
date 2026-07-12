package com.token2.lkcompanion.token2ui

import com.token2.lkcompanion.token2.Token2Client
import com.token2.lkcompanion.token2.Token2Codec
import com.token2.lkcompanion.token2.Token2Exception
import com.token2.lkcompanion.transport.SmartCardTransport

/**
 * Bridges the momentary NFC tap to a browsable UI.
 *
 * NFC sessions exist only for the ~1s the key is on the reader, so we can't keep
 * a live handle while the user reads the screen. Instead the UI ARMS an operation
 * (refresh / add / delete), the user taps the key, and [executeOn] runs the armed
 * op against that transient transport and refreshes the cached entry list.
 *
 * This is the same "arm then tap" model the Token2 reference and YubiKey
 * Authenticator use for NFC.
 */
class Token2Repository {

    sealed class PendingOp {
        object Refresh : PendingOp()
        data class Add(val entry: Token2Codec.Entry, val allowOverwrite: Boolean = false) : PendingOp()
        data class Delete(val app: String, val account: String) : PendingOp()
        /** Read the key's current interface configuration (§6.9). */
        object ReadConfig : PendingOp()
        /**
         * Enable/disable USB interfaces (§6.8). Fields are the desired ENABLED
         * state of each interface; the client enforces the two-interface minimum.
         */
        data class SetInterfaces(
            val fido: Boolean,
            val keyboard: Boolean,
            val ccid: Boolean,
        ) : PendingOp()
    }

    /** Snapshot of which USB interfaces the key currently exposes (§6.9). */
    data class IfaceState(
        val fido: Boolean,
        val keyboard: Boolean,
        val ccid: Boolean,
        /** Model support, so the UI can grey out toggles the key can't offer. */
        val keyboardSupported: Boolean,
        val ccidSupported: Boolean,
    )

    /** Result of executing an op against a tapped key. */
    sealed class OpResult {
        data class Success(val message: String, val entries: List<Token2Codec.Entry>) : OpResult()
        data class Failure(val message: String) : OpResult()
        /** Current interface configuration, for the enable/disable dialog. */
        data class Config(val iface: IfaceState) : OpResult()
        /** The key already has an entry with this issuer/account; ask before overwriting. */
        data class DuplicateExists(
            val entry: Token2Codec.Entry,
            val existingLabel: String,
            val entries: List<Token2Codec.Entry>,
        ) : OpResult()
        object NotAToken2Key : OpResult()
    }

    @Volatile var pending: PendingOp = PendingOp.Refresh
        private set

    @Volatile var cachedEntries: List<Token2Codec.Entry> = emptyList()
        private set

    fun arm(op: PendingOp) { pending = op }

    /**
     * Run the armed op against a freshly-tapped transport. Returns a user-facing
     * result and updates [cachedEntries]. Always re-enumerates afterward so the UI
     * reflects the device's true state.
     */
    fun executeOn(transport: SmartCardTransport): OpResult {
        val client = try {
            Token2Client.overNfc(transport)
        } catch (e: Exception) {
            return OpResult.NotAToken2Key
        }

        val op = pending
        return try {
            when (op) {
                is PendingOp.Refresh -> {
                    val entries = enumerateSafe(client)
                    cachedEntries = entries
                    pending = PendingOp.Refresh
                    OpResult.Success("Refreshed", entries)
                }
                is PendingOp.Add -> {
                    // Authoritative duplicate check: enumerate the key NOW (not the
                    // cache, which may be stale) and match on issuer+account.
                    val current = enumerateSafe(client)
                    val dup = current.firstOrNull { sameIdentity(it, op.entry) }
                    if (dup != null && !op.allowOverwrite) {
                        // Don't write; surface it so the UI can confirm overwrite.
                        cachedEntries = current
                        OpResult.DuplicateExists(op.entry, dup.label, current)
                    } else {
                        if (dup != null) {
                            // Overwrite = delete the existing identity, then write.
                            client.deleteEntry(dup.appName, dup.accountName)
                        }
                        client.writeEntry(op.entry)
                        val entries = enumerateSafe(client)
                        cachedEntries = entries
                        pending = PendingOp.Refresh
                        val verb = if (dup != null) "Replaced" else "Added"
                        OpResult.Success("$verb ${op.entry.label}", entries)
                    }
                }
                is PendingOp.Delete -> {
                    client.deleteEntry(op.app, op.account)
                    val entries = enumerateSafe(client)
                    cachedEntries = entries
                    pending = PendingOp.Refresh
                    OpResult.Success("Deleted ${op.app}/${op.account}", entries)
                }
                is PendingOp.ReadConfig -> {
                    val info = client.readConfig()
                    pending = PendingOp.Refresh
                    OpResult.Config(
                        IfaceState(
                            fido = !info.fidoDisabled,
                            keyboard = !info.keyboardHidDisabled,
                            ccid = !info.ccidDisabled,
                            // FIDO is always present on these keys; keyboard/CCID
                            // support come from the capability bytes.
                            keyboardSupported = info.hotpSupported,
                            ccidSupported = info.ccidSupported,
                        )
                    )
                }
                is PendingOp.SetInterfaces -> {
                    client.setInterfaces(op.fido, op.keyboard, op.ccid)
                    pending = PendingOp.Refresh
                    OpResult.Success(
                        "Interface configuration updated. Re-plug or re-tap the key for it to take effect.",
                        cachedEntries,
                    )
                }
            }
        } catch (e: Token2Exception.ButtonPressRequired) {
            OpResult.Failure("Touch the key's button to confirm, then tap again.")
        } catch (e: Token2Exception.NotEnoughSpace) {
            OpResult.Failure("No space left on the key for another entry.")
        } catch (e: Exception) {
            OpResult.Failure(e.message ?: e.javaClass.simpleName)
        }
    }

    /** Two entries are "the same" if issuer and account match (case-insensitive, trimmed). */
    private fun sameIdentity(a: Token2Codec.Entry, b: Token2Codec.Entry): Boolean =
        a.appName.trim().equals(b.appName.trim(), ignoreCase = true) &&
        a.accountName.trim().equals(b.accountName.trim(), ignoreCase = true)

    /** Cache-based advisory check for the UI before arming (may be stale). */
    fun cachedDuplicateOf(entry: Token2Codec.Entry): Token2Codec.Entry? =
        cachedEntries.firstOrNull { sameIdentity(it, entry) }

    private val Token2Codec.Entry.label: String
        get() = if (appName.isBlank()) accountName else "$appName / $accountName"

    private fun enumerateSafe(client: Token2Client): List<Token2Codec.Entry> =
        try {
            client.enumerate(System.currentTimeMillis() / 1000)
        } catch (e: Token2Exception.EntryNotFound) {
            emptyList()                          // empty token
        }
}
