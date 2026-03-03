package com.wakefromfar.wolrelay

import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.appcompat.app.AppCompatDelegate
import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.core.os.LocaleListCompat
import androidx.lifecycle.viewmodel.compose.viewModel
import com.wakefromfar.wolrelay.data.ThemeMode
import com.wakefromfar.wolrelay.ui.MainViewModel
import com.wakefromfar.wolrelay.ui.WolRelayApp
import com.wakefromfar.wolrelay.ui.theme.WakeFromFarTheme
import kotlinx.coroutines.flow.MutableStateFlow

class MainActivity : ComponentActivity() {
    private val pendingDeepLink = MutableStateFlow<String?>(null)

    override fun onCreate(savedInstanceState: Bundle?) {
        applySelectedLanguage()
        super.onCreate(savedInstanceState)
        pendingDeepLink.value = intent?.dataString
        enableEdgeToEdge()
        setContent {
            val vm: MainViewModel = viewModel(factory = MainViewModel.factory)
            val deepLink by pendingDeepLink.collectAsState()
            val systemDarkTheme = isSystemInDarkTheme()
            val darkTheme = when (vm.state.themeMode) {
                ThemeMode.SYSTEM -> systemDarkTheme
                ThemeMode.LIGHT -> false
                ThemeMode.DARK -> true
            }
            LaunchedEffect(deepLink) {
                deepLink?.let {
                    vm.handleDeepLink(it)
                    pendingDeepLink.value = null
                }
            }
            LaunchedEffect(vm.state.appLanguage) {
                val targetLocales = LocaleListCompat.forLanguageTags(vm.state.appLanguage.languageTag)
                if (AppCompatDelegate.getApplicationLocales() != targetLocales) {
                    AppCompatDelegate.setApplicationLocales(targetLocales)
                }
            }
            WakeFromFarTheme(darkTheme = darkTheme) {
                WolRelayApp(vm = vm)
            }
        }
    }

    override fun onNewIntent(intent: android.content.Intent) {
        super.onNewIntent(intent)
        setIntent(intent)
        pendingDeepLink.value = intent.dataString
    }

    private fun applySelectedLanguage() {
        val languageTag = LanguagePrefs.get(this).languageTag
        AppCompatDelegate.setApplicationLocales(LocaleListCompat.forLanguageTags(languageTag))
    }
}
