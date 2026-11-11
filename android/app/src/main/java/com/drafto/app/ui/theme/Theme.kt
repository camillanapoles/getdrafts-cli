package com.drafto.app.ui.theme

import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.ui.graphics.Color

private val White = Color(0xFFFFFFFF)

private val DarkColors = darkColorScheme(
    background = DraftoBg,
    surface = DraftoSurface,
    surfaceVariant = DraftoSurfaceVariant,
    onBackground = DraftoPrimary,
    onSurface = DraftoPrimary,
    onSurfaceVariant = DraftoPrimary.copy(alpha = 0.6f),
    primary = DraftoAccent,
    onPrimary = White,
)

private val LightColors = lightColorScheme(
    background = White,
    surface = White,
    primary = DraftoAccent,
    onPrimary = DraftoOnPrimary,
)

@Composable
fun DraftoTheme(darkTheme: Boolean = isSystemInDarkTheme(), content: @Composable () -> Unit) {
    MaterialTheme(
        colorScheme = if (darkTheme) DarkColors else LightColors,
        content = content,
    )
}
