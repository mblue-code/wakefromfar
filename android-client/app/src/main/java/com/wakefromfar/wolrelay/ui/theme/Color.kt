package com.wakefromfar.wolrelay.ui.theme

import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.ui.graphics.Color

// Light scheme — sky-blue primary + amber tertiary
private val LightPrimary = Color(0xFF1A56C4)
private val LightOnPrimary = Color(0xFFFFFFFF)
private val LightPrimaryContainer = Color(0xFFD7E3FF)
private val LightOnPrimaryContainer = Color(0xFF001A41)
private val LightSecondary = Color(0xFF4A6BB5)
private val LightOnSecondary = Color(0xFFFFFFFF)
private val LightSecondaryContainer = Color(0xFFD9E3FF)
private val LightOnSecondaryContainer = Color(0xFF101C33)
private val LightTertiary = Color(0xFFB06B00)
private val LightOnTertiary = Color(0xFFFFFFFF)
private val LightTertiaryContainer = Color(0xFFFFDDB3)
private val LightOnTertiaryContainer = Color(0xFF361900)
private val LightError = Color(0xFFBA1A1A)
private val LightOnError = Color(0xFFFFFFFF)
private val LightErrorContainer = Color(0xFFFFDAD6)
private val LightOnErrorContainer = Color(0xFF410002)
private val LightBackground = Color(0xFFF0F4FF)
private val LightOnBackground = Color(0xFF171C25)
private val LightSurface = Color(0xFFFFFFFF)
private val LightOnSurface = Color(0xFF171C25)
private val LightSurfaceVariant = Color(0xFFDFE6F5)
private val LightOnSurfaceVariant = Color(0xFF44546E)
private val LightOutline = Color(0xFF73829C)
private val LightOutlineVariant = Color(0xFFC3CFDF)

// Dark scheme — deep navy background + sky blue primary + amber tertiary
private val DarkPrimary = Color(0xFF4F8EF7)
private val DarkOnPrimary = Color(0xFF0A1E45)
private val DarkPrimaryContainer = Color(0xFF1B3566)
private val DarkOnPrimaryContainer = Color(0xFFBAD0FF)
private val DarkSecondary = Color(0xFF5B8BF5)
private val DarkOnSecondary = Color(0xFF0E2050)
private val DarkSecondaryContainer = Color(0xFF1A3060)
private val DarkOnSecondaryContainer = Color(0xFFB8CCFF)
private val DarkTertiary = Color(0xFFF0B429)
private val DarkOnTertiary = Color(0xFF3D2A00)
private val DarkTertiaryContainer = Color(0xFF4A3500)
private val DarkOnTertiaryContainer = Color(0xFFFFD97A)
private val DarkError = Color(0xFFFF6B6B)
private val DarkOnError = Color(0xFF690005)
private val DarkErrorContainer = Color(0xFF93000A)
private val DarkOnErrorContainer = Color(0xFFFFDAD6)
private val DarkBackground = Color(0xFF0F1623)
private val DarkOnBackground = Color(0xFFE8EEF7)
private val DarkSurface = Color(0xFF182236)
private val DarkOnSurface = Color(0xFFE8EEF7)
private val DarkSurfaceVariant = Color(0xFF1E2E47)
private val DarkOnSurfaceVariant = Color(0xFF9BABC7)
private val DarkOutline = Color(0xFF2D3A52)
private val DarkOutlineVariant = Color(0xFF253048)

internal val AppLightColorScheme = lightColorScheme(
    primary = LightPrimary,
    onPrimary = LightOnPrimary,
    primaryContainer = LightPrimaryContainer,
    onPrimaryContainer = LightOnPrimaryContainer,
    secondary = LightSecondary,
    onSecondary = LightOnSecondary,
    secondaryContainer = LightSecondaryContainer,
    onSecondaryContainer = LightOnSecondaryContainer,
    tertiary = LightTertiary,
    onTertiary = LightOnTertiary,
    tertiaryContainer = LightTertiaryContainer,
    onTertiaryContainer = LightOnTertiaryContainer,
    error = LightError,
    onError = LightOnError,
    errorContainer = LightErrorContainer,
    onErrorContainer = LightOnErrorContainer,
    background = LightBackground,
    onBackground = LightOnBackground,
    surface = LightSurface,
    onSurface = LightOnSurface,
    surfaceVariant = LightSurfaceVariant,
    onSurfaceVariant = LightOnSurfaceVariant,
    outline = LightOutline,
    outlineVariant = LightOutlineVariant,
)

internal val AppDarkColorScheme = darkColorScheme(
    primary = DarkPrimary,
    onPrimary = DarkOnPrimary,
    primaryContainer = DarkPrimaryContainer,
    onPrimaryContainer = DarkOnPrimaryContainer,
    secondary = DarkSecondary,
    onSecondary = DarkOnSecondary,
    secondaryContainer = DarkSecondaryContainer,
    onSecondaryContainer = DarkOnSecondaryContainer,
    tertiary = DarkTertiary,
    onTertiary = DarkOnTertiary,
    tertiaryContainer = DarkTertiaryContainer,
    onTertiaryContainer = DarkOnTertiaryContainer,
    error = DarkError,
    onError = DarkOnError,
    errorContainer = DarkErrorContainer,
    onErrorContainer = DarkOnErrorContainer,
    background = DarkBackground,
    onBackground = DarkOnBackground,
    surface = DarkSurface,
    onSurface = DarkOnSurface,
    surfaceVariant = DarkSurfaceVariant,
    onSurfaceVariant = DarkOnSurfaceVariant,
    outline = DarkOutline,
    outlineVariant = DarkOutlineVariant,
)
