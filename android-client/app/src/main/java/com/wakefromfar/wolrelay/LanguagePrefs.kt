package com.wakefromfar.wolrelay

import android.content.Context
import java.util.Locale

object LanguagePrefs {
    private const val PREFS_NAME = "wolrelay_ui_prefs"
    private const val KEY_APP_LANGUAGE = "app_language"

    fun get(context: Context): AppLanguage {
        val prefs = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
        val stored = AppLanguage.fromStorage(prefs.getString(KEY_APP_LANGUAGE, null))
        if (stored != null) {
            return stored
        }

        val systemLanguage = context.resources.configuration.locales[0]?.language ?: Locale.getDefault().language
        return if (systemLanguage.equals("de", ignoreCase = true)) {
            AppLanguage.GERMAN
        } else {
            AppLanguage.ENGLISH
        }
    }

    fun set(context: Context, language: AppLanguage) {
        context
            .getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
            .edit()
            .putString(KEY_APP_LANGUAGE, language.storageValue)
            .apply()
    }
}
