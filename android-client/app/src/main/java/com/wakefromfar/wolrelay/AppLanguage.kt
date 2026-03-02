package com.wakefromfar.wolrelay

enum class AppLanguage(
    val storageValue: String,
    val languageTag: String,
) {
    ENGLISH("en", "en"),
    GERMAN("de", "de"),
    ;

    companion object {
        fun fromStorage(value: String?): AppLanguage? = entries.firstOrNull { it.storageValue == value }
    }
}
