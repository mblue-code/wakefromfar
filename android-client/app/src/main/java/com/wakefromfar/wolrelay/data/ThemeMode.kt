package com.wakefromfar.wolrelay.data

enum class ThemeMode(val storageValue: String) {
    SYSTEM("system"),
    LIGHT("light"),
    DARK("dark"),
    ;

    companion object {
        fun fromStorage(value: String?): ThemeMode {
            return values().firstOrNull { it.storageValue == value } ?: SYSTEM
        }
    }
}
