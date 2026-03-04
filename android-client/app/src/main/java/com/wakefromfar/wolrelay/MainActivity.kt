package com.wakefromfar.wolrelay

import android.content.Context
import android.content.res.Configuration
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.lifecycle.viewmodel.compose.viewModel
import com.wakefromfar.wolrelay.data.ThemeMode
import com.wakefromfar.wolrelay.ui.MainViewModel
import com.wakefromfar.wolrelay.ui.WolRelayApp
import com.wakefromfar.wolrelay.ui.theme.WakeFromFarTheme
import java.util.Locale
import kotlinx.coroutines.flow.MutableStateFlow

class MainActivity : ComponentActivity() {
    private val pendingDeepLink = MutableStateFlow<String?>(null)
    private var appliedLanguageTag: String = AppLanguage.ENGLISH.languageTag

    override fun attachBaseContext(newBase: Context) {
        super.attachBaseContext(localizedContext(newBase))
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        appliedLanguageTag = LanguagePrefs.get(this).languageTag
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
                applyRuntimeLanguage(vm.state.appLanguage.languageTag)
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

    private fun applyRuntimeLanguage(languageTag: String) {
        if (appliedLanguageTag != languageTag) {
            appliedLanguageTag = languageTag
            recreate()
        }
    }

    private fun localizedContext(context: Context): Context {
        val languageTag = LanguagePrefs.get(context).languageTag
        val locale = Locale.forLanguageTag(languageTag)
        Locale.setDefault(locale)
        val config = Configuration(context.resources.configuration)
        config.setLocale(locale)
        return context.createConfigurationContext(config)
    }
}
