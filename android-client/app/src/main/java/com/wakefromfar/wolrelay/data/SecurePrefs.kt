package com.wakefromfar.wolrelay.data

import android.content.Context
import android.content.SharedPreferences
import android.util.Log
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKey
import java.security.KeyStore
import javax.crypto.AEADBadTagException

class SecurePrefs(context: Context) {
    private val prefs: SharedPreferences

    init {
        prefs = createPrefsWithRecovery(context.applicationContext)
    }

    fun getToken(): String? = prefs.getString(KEY_TOKEN, null)

    fun setToken(token: String?) {
        prefs.edit().putString(KEY_TOKEN, token).apply()
    }

    fun getBackendUrl(): String = prefs.getString(KEY_BACKEND_URL, DEFAULT_BACKEND_URL) ?: DEFAULT_BACKEND_URL

    fun setBackendUrl(url: String) {
        prefs.edit().putString(KEY_BACKEND_URL, url).apply()
    }

    fun getLastSeenAdminActivityEventId(): Int = prefs.getInt(KEY_LAST_SEEN_ADMIN_ACTIVITY_EVENT_ID, 0)

    fun setLastSeenAdminActivityEventId(value: Int) {
        prefs.edit().putInt(KEY_LAST_SEEN_ADMIN_ACTIVITY_EVENT_ID, value.coerceAtLeast(0)).apply()
    }

    fun getLastNotifiedShutdownEventId(): Int = prefs.getInt(KEY_LAST_NOTIFIED_SHUTDOWN_EVENT_ID, 0)

    fun setLastNotifiedShutdownEventId(value: Int) {
        prefs.edit().putInt(KEY_LAST_NOTIFIED_SHUTDOWN_EVENT_ID, value.coerceAtLeast(0)).apply()
    }

    fun isAdminBackgroundAlertsEnabled(): Boolean = prefs.getBoolean(KEY_ADMIN_BACKGROUND_ALERTS_ENABLED, true)

    fun setAdminBackgroundAlertsEnabled(enabled: Boolean) {
        prefs.edit().putBoolean(KEY_ADMIN_BACKGROUND_ALERTS_ENABLED, enabled).apply()
    }

    fun getThemeMode(): ThemeMode = ThemeMode.fromStorage(prefs.getString(KEY_THEME_MODE, null))

    fun setThemeMode(mode: ThemeMode) {
        prefs.edit().putString(KEY_THEME_MODE, mode.storageValue).apply()
    }

    fun isFirstRunOnboardingAcknowledged(): Boolean = prefs.getBoolean(KEY_FIRST_RUN_ONBOARDING_ACK, false)

    fun setFirstRunOnboardingAcknowledged(value: Boolean) {
        prefs.edit().putBoolean(KEY_FIRST_RUN_ONBOARDING_ACK, value).apply()
    }

    fun clearSession() {
        prefs.edit().remove(KEY_TOKEN).apply()
    }

    private fun createPrefsWithRecovery(context: Context): SharedPreferences {
        val masterKey = buildMasterKey(context)
        return try {
            createEncryptedPrefs(context, masterKey)
        } catch (ex: Exception) {
            if (!isRecoverableCryptoFailure(ex)) {
                throw ex
            }
            Log.w(TAG, "Secure prefs corrupted, resetting encrypted storage", ex)
            context.deleteSharedPreferences(PREFS_FILE)
            clearMasterKeyIfPresent(MASTER_KEY_ALIAS)
            val recreatedMasterKey = buildMasterKey(context)
            createEncryptedPrefs(context, recreatedMasterKey)
        }
    }

    private fun buildMasterKey(context: Context): MasterKey {
        return MasterKey.Builder(context)
            .setKeyScheme(MasterKey.KeyScheme.AES256_GCM)
            .build()
    }

    private fun createEncryptedPrefs(
        context: Context,
        masterKey: MasterKey,
    ): SharedPreferences {
        return EncryptedSharedPreferences.create(
            context,
            PREFS_FILE,
            masterKey,
            EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
            EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM,
        )
    }

    private fun clearMasterKeyIfPresent(alias: String) {
        try {
            val keyStore = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
            if (keyStore.containsAlias(alias)) {
                keyStore.deleteEntry(alias)
            }
        } catch (ex: Exception) {
            Log.w(TAG, "Unable to clear master key alias=$alias", ex)
        }
    }

    private fun isRecoverableCryptoFailure(ex: Exception): Boolean {
        var cause: Throwable? = ex
        while (cause != null) {
            if (
                cause is AEADBadTagException ||
                cause.javaClass.simpleName.contains("KeyStoreException", ignoreCase = true)
            ) {
                return true
            }
            cause = cause.cause
        }
        return false
    }

    private companion object {
        const val TAG = "SecurePrefs"
        const val PREFS_FILE = "wolrelay_secure_prefs"
        const val MASTER_KEY_ALIAS = "_androidx_security_master_key_"
        const val KEY_TOKEN = "token"
        const val KEY_BACKEND_URL = "backend_url"
        const val KEY_LAST_SEEN_ADMIN_ACTIVITY_EVENT_ID = "last_seen_admin_activity_event_id"
        const val KEY_LAST_NOTIFIED_SHUTDOWN_EVENT_ID = "last_notified_shutdown_event_id"
        const val KEY_ADMIN_BACKGROUND_ALERTS_ENABLED = "admin_background_alerts_enabled"
        const val KEY_THEME_MODE = "theme_mode"
        const val KEY_FIRST_RUN_ONBOARDING_ACK = "first_run_onboarding_ack"
        const val DEFAULT_BACKEND_URL = "http://100.100.100.100:8080"
    }
}
