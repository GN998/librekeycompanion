package com.token2.lkcompanion.management

import com.token2.lkcompanion.transport.SmartCardTransport

/**
 * Arms a Management-applet operation, runs it against a freshly tapped/plugged
 * key, and returns a user-facing result — the same "arm then tap" model the
 * Token2 and OATH repositories use, since an NFC session only lives for the tap.
 */
class ManagementRepository {

    sealed class PendingOp {
        /** Read current capabilities (for the toggle dialog). */
        object ReadInfo : PendingOp()
        /**
         * Write new enabled-capability masks. `lockCode` is the 16-byte config
         * lock, required only if the key is locked.
         */
        data class SetCapabilities(
            val usbEnabled: Int,
            val nfcEnabled: Int?,
            val lockCode: ByteArray?,
        ) : PendingOp()
    }

    sealed class OpResult {
        data class Info(val info: YkManagementClient.DeviceInfo) : OpResult()
        data class Success(val message: String) : OpResult()
        data class Failure(val message: String) : OpResult()
        /** The write was refused because the configuration lock wasn't cleared. */
        data class Locked(val message: String) : OpResult()
        /** Not a YubiKey / no Management applet on this key. */
        object NoManagementApplet : OpResult()
    }

    @Volatile var pending: PendingOp = PendingOp.ReadInfo
        private set

    @Volatile var lastInfo: YkManagementClient.DeviceInfo? = null
        private set

    fun arm(op: PendingOp) { pending = op }

    fun executeOn(transport: SmartCardTransport): OpResult {
        val client = YkManagementClient(transport)
        // Selecting the applet is the "is this a YubiKey?" probe. A select
        // failure (SW 6A82 / 6D00 etc.) means no Management applet here.
        try {
            client.select()
        } catch (e: Exception) {
            return OpResult.NoManagementApplet
        }

        return try {
            when (val op = pending) {
                is PendingOp.ReadInfo -> {
                    val info = client.readDeviceInfo()
                    lastInfo = info
                    OpResult.Info(info)
                }
                is PendingOp.SetCapabilities -> {
                    client.writeCapabilities(
                        usbEnabled = op.usbEnabled,
                        nfcEnabled = op.nfcEnabled,
                        lockCode = op.lockCode,
                        reboot = true,
                    )
                    pending = PendingOp.ReadInfo
                    OpResult.Success(
                        "Applications updated. If the key didn't reset itself, remove and reinsert it."
                    )
                }
            }
        } catch (e: ManagementException.LockedOrWrongCode) {
            OpResult.Locked(e.message ?: "configuration locked")
        } catch (e: ManagementException.BadStatus) {
            OpResult.Failure(e.message ?: "management command failed")
        } catch (e: Exception) {
            OpResult.Failure(e.message ?: e.javaClass.simpleName)
        }
    }
}
