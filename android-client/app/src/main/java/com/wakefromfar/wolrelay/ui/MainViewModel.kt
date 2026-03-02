package com.wakefromfar.wolrelay.ui

import android.app.Application
import androidx.annotation.StringRes
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.ViewModelProvider
import androidx.lifecycle.viewmodel.CreationExtras
import androidx.lifecycle.viewModelScope
import com.wakefromfar.wolrelay.AppLanguage
import com.wakefromfar.wolrelay.LanguagePrefs
import com.wakefromfar.wolrelay.R
import com.wakefromfar.wolrelay.data.ApiClient
import com.wakefromfar.wolrelay.data.ApiException
import com.wakefromfar.wolrelay.data.MyDeviceDto
import com.wakefromfar.wolrelay.data.InviteLinkParser
import com.wakefromfar.wolrelay.data.SecurePrefs
import com.wakefromfar.wolrelay.data.ThemeMode
import kotlinx.coroutines.launch

data class AppUiState(
    val backendUrl: String = "",
    val username: String = "",
    val password: String = "",
    val inviteToken: String? = null,
    val claimPassword: String = "",
    val token: String? = null,
    val themeMode: ThemeMode = ThemeMode.SYSTEM,
    val appLanguage: AppLanguage = AppLanguage.ENGLISH,
    val devices: List<MyDeviceDto> = emptyList(),
    val isLoading: Boolean = false,
    val error: String? = null,
    val info: String? = null,
) {
    val isAuthenticated: Boolean
        get() = !token.isNullOrBlank()
    val hasInviteToken: Boolean
        get() = !inviteToken.isNullOrBlank()
}

class MainViewModel(application: Application) : AndroidViewModel(application) {
    private val prefs = SecurePrefs(application)
    private val api = ApiClient()

    var state by mutableStateOf(
        AppUiState(
            backendUrl = prefs.getBackendUrl(),
            token = prefs.getToken(),
            themeMode = prefs.getThemeMode(),
            appLanguage = LanguagePrefs.get(application),
        ),
    )
        private set

    init {
        if (state.isAuthenticated) {
            refreshDevices()
        }
    }

    private fun tr(@StringRes resId: Int, vararg args: Any): String = getApplication<Application>().getString(resId, *args)

    private fun messageOr(@StringRes fallbackResId: Int, ex: Exception): String {
        if (ex is ApiException) {
            return tr(fallbackResId)
        }
        return ex.message ?: tr(fallbackResId)
    }

    fun updateBackendUrl(value: String) {
        state = state.copy(backendUrl = value)
    }

    fun updateUsername(value: String) {
        state = state.copy(username = value)
    }

    fun updatePassword(value: String) {
        state = state.copy(password = value)
    }

    fun updateClaimPassword(value: String) {
        state = state.copy(claimPassword = value)
    }

    fun updateThemeMode(mode: ThemeMode) {
        prefs.setThemeMode(mode)
        state = state.copy(themeMode = mode)
    }

    fun updateAppLanguage(language: AppLanguage) {
        LanguagePrefs.set(getApplication(), language)
        state = state.copy(appLanguage = language)
    }

    fun handleDeepLink(uriString: String?) {
        val parsed = InviteLinkParser.parse(uriString) ?: return
        state = state.copy(
            inviteToken = parsed.token,
            backendUrl = parsed.backendUrlHint ?: state.backendUrl,
            info = tr(R.string.info_invite_link_detected),
            error = null,
        )
    }

    fun clearInviteToken() {
        state = state.copy(inviteToken = null, claimPassword = "")
    }

    fun dismissMessages() {
        state = state.copy(error = null, info = null)
    }

    fun login() {
        if (state.username.isBlank() || state.password.isBlank() || state.backendUrl.isBlank()) {
            state = state.copy(error = tr(R.string.error_login_required_fields))
            return
        }

        state = state.copy(isLoading = true, error = null, info = null)
        viewModelScope.launch {
            try {
                val response = api.login(
                    baseUrl = state.backendUrl,
                    username = state.username,
                    password = state.password,
                )
                prefs.setToken(response.token)
                prefs.setBackendUrl(state.backendUrl)
                state = state.copy(
                    token = response.token,
                    password = "",
                    isLoading = false,
                    info = tr(R.string.info_login_success),
                )
                refreshDevices()
            } catch (ex: Exception) {
                state = state.copy(isLoading = false, error = messageOr(R.string.error_login_failed, ex))
            }
        }
    }

    fun claimInvite() {
        val inviteToken = state.inviteToken
        if (inviteToken.isNullOrBlank()) {
            state = state.copy(error = tr(R.string.error_invite_token_missing))
            return
        }
        if (state.backendUrl.isBlank()) {
            state = state.copy(error = tr(R.string.error_backend_required))
            return
        }
        if (state.claimPassword.length < 12) {
            state = state.copy(error = tr(R.string.error_password_min_length, 12))
            return
        }

        state = state.copy(isLoading = true, error = null, info = null)
        viewModelScope.launch {
            try {
                val response = api.claimOnboarding(
                    baseUrl = state.backendUrl,
                    token = inviteToken,
                    password = state.claimPassword,
                )
                prefs.setToken(response.token)
                prefs.setBackendUrl(state.backendUrl)
                state = state.copy(
                    token = response.token,
                    username = response.username,
                    password = "",
                    claimPassword = "",
                    inviteToken = null,
                    isLoading = false,
                    info = tr(R.string.info_onboarding_success, response.username),
                )
                refreshDevices()
            } catch (ex: Exception) {
                state = state.copy(isLoading = false, error = messageOr(R.string.error_onboarding_failed, ex))
            }
        }
    }

    fun logout() {
        prefs.clearSession()
        state = state.copy(token = null, devices = emptyList(), info = tr(R.string.info_logged_out))
    }

    fun refreshDevices() {
        val token = state.token ?: return
        state = state.copy(isLoading = true, error = null)
        viewModelScope.launch {
            try {
                val devices = api.listMyDevices(baseUrl = state.backendUrl, token = token)
                state = state.copy(devices = devices, isLoading = false)
            } catch (ex: Exception) {
                state = state.copy(isLoading = false, error = messageOr(R.string.error_devices_load_failed, ex))
            }
        }
    }

    fun wakeDevice(deviceId: String) {
        val token = state.token ?: return
        state = state.copy(isLoading = true, error = null)
        viewModelScope.launch {
            try {
                val res = api.wakeDevice(baseUrl = state.backendUrl, token = token, hostId = deviceId)
                val msg = when (res.result) {
                    "already_on" -> tr(R.string.info_wake_already_on)
                    "sent" -> tr(
                        R.string.info_wake_signal_sent,
                        res.sent_to?.let { tr(R.string.info_wake_signal_target, it) } ?: "",
                    )
                    "failed" -> tr(
                        R.string.info_wake_failed,
                        res.error_detail?.let { tr(R.string.info_wake_failed_detail, it) }
                            ?: tr(R.string.info_wake_failed_no_detail),
                    )
                    else -> res.message
                }
                state = state.copy(isLoading = false, info = msg)
                refreshDevices()
            } catch (ex: Exception) {
                state = state.copy(isLoading = false, error = messageOr(R.string.error_wake_failed, ex))
            }
        }
    }

    companion object {
        val factory: ViewModelProvider.Factory = object : ViewModelProvider.Factory {
            override fun <T : androidx.lifecycle.ViewModel> create(
                modelClass: Class<T>,
                extras: CreationExtras,
            ): T {
                val application = checkNotNull(extras[ViewModelProvider.AndroidViewModelFactory.APPLICATION_KEY])
                return MainViewModel(application) as T
            }
        }
    }
}
