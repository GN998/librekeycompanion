package com.token2.lkcompanion.fidoui

import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.net.Uri
import android.provider.Settings

/**
 * FIDO2 "wiring" — Authnkey integration.
 *
 * Authnkey is a CredentialProvider app: it registers with Android's Credential
 * Manager and the OS routes passkey create/get requests to it. There is no
 * in-process API to call — by design, the OS owns the passkey flow — so the
 * correct integration is to (a) detect whether Authnkey is installed, (b) help
 * the user install it if not, and (c) point them at the system setting where it's
 * enabled as a credential provider.
 *
 * This is the honest, complete FIDO2 wiring for an app that is NOT itself a
 * CTAP2 stack. The full passkey create/authenticate flow lives in Authnkey.
 */
object AuthnkeyIntegration {

    const val AUTHNKEY_PACKAGE = "pl.lebihan.authnkey"

    enum class State { INSTALLED, NOT_INSTALLED }

    fun state(context: Context): State =
        if (isInstalled(context)) State.INSTALLED else State.NOT_INSTALLED

    fun isInstalled(context: Context): Boolean = try {
        context.packageManager.getPackageInfo(AUTHNKEY_PACKAGE, 0)
        true
    } catch (e: PackageManager.NameNotFoundException) {
        false
    }

    /** Open Authnkey if installed (e.g. to manage passkeys), else null. */
    fun launchIntent(context: Context): Intent? =
        context.packageManager.getLaunchIntentForPackage(AUTHNKEY_PACKAGE)

    /** Open the F-Droid listing (or browser fallback) to install Authnkey. */
    fun installIntent(): Intent {
        val fdroid = Intent(Intent.ACTION_VIEW,
            Uri.parse("https://f-droid.org/packages/$AUTHNKEY_PACKAGE"))
        return fdroid
    }

    /**
     * System screen where the user enables a credential provider. There's no
     * stable public action across all versions; this opens the closest settings
     * surface, falling back to general Settings.
     */
    fun providerSettingsIntent(): Intent =
        Intent(Settings.ACTION_SETTINGS)   // see note in UI: guide user to
                                           // Passwords, passkeys & autofill

    /** One-line human summary for the status panel. */
    fun statusLine(context: Context): String = when (state(context)) {
        State.INSTALLED ->
            "Authnkey installed — enable it under Settings ▸ Passwords, passkeys & " +
            "autofill to use NFC passkeys (CTAP2)."
        State.NOT_INSTALLED ->
            "Authnkey not installed. It provides full CTAP2 passkeys over NFC/USB. " +
            "Tap to install from F-Droid."
    }
}
