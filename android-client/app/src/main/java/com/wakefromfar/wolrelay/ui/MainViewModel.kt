package com.wakefromfar.wolrelay.ui

import android.app.Application
import android.net.Uri
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.ViewModelProvider
import androidx.lifecycle.viewmodel.CreationExtras
import androidx.lifecycle.viewModelScope
import com.wakefromfar.wolrelay.data.ApiClient
import com.wakefromfar.wolrelay.data.MyDeviceDto
import com.wakefromfar.wolrelay.data.SecurePrefs
import kotlinx.coroutines.launch

data class AppUiState(
    val backendUrl: String = "",
    val username: String = "",
    val password: String = "",
    val inviteToken: String? = null,
    val claimPassword: String = "",
    val token: String? = null,
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
        ),
    )
        private set

    init {
        if (state.isAuthenticated) {
            refreshDevices()
        }
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

    fun handleDeepLink(uriString: String?) {
        if (uriString.isNullOrBlank()) return
        val uri = runCatching { Uri.parse(uriString) }.getOrNull() ?: return
        val token = uri.getQueryParameter("token")?.trim().orEmpty()
        if (token.isBlank()) return
        val backendHint = uri.getQueryParameter("backend_url_hint")
            ?: uri.getQueryParameter("backend_url")
        state = state.copy(
            inviteToken = token,
            backendUrl = backendHint?.takeIf { it.isNotBlank() } ?: state.backendUrl,
            info = "Invite-Link erkannt. Passwort setzen und Konto aktivieren.",
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
            state = state.copy(error = "Backend URL, Username und Passwort sind Pflichtfelder.")
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
                    info = "Login erfolgreich.",
                )
                refreshDevices()
            } catch (ex: Exception) {
                state = state.copy(isLoading = false, error = ex.message ?: "Login fehlgeschlagen")
            }
        }
    }

    fun claimInvite() {
        val inviteToken = state.inviteToken
        if (inviteToken.isNullOrBlank()) {
            state = state.copy(error = "Kein Invite-Token vorhanden.")
            return
        }
        if (state.backendUrl.isBlank()) {
            state = state.copy(error = "Backend URL ist erforderlich.")
            return
        }
        if (state.claimPassword.length < 12) {
            state = state.copy(error = "Passwort muss mindestens 12 Zeichen haben.")
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
                    info = "Onboarding erfolgreich. Willkommen ${response.username}.",
                )
                refreshDevices()
            } catch (ex: Exception) {
                state = state.copy(isLoading = false, error = ex.message ?: "Onboarding fehlgeschlagen")
            }
        }
    }

    fun logout() {
        prefs.clearSession()
        state = state.copy(token = null, devices = emptyList(), info = "Ausgeloggt")
    }

    fun refreshDevices() {
        val token = state.token ?: return
        state = state.copy(isLoading = true, error = null)
        viewModelScope.launch {
            try {
                val devices = api.listMyDevices(baseUrl = state.backendUrl, token = token)
                state = state.copy(devices = devices, isLoading = false)
            } catch (ex: Exception) {
                state = state.copy(isLoading = false, error = ex.message ?: "Geräte konnten nicht geladen werden")
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
                    "already_on" -> "Gerät ist bereits eingeschaltet."
                    "sent" -> "Wake-Signal gesendet${res.sent_to?.let { " ($it)" } ?: ""}."
                    "failed" -> "Wake fehlgeschlagen${res.error_detail?.let { ": $it" } ?: "."}"
                    else -> res.message
                }
                state = state.copy(isLoading = false, info = msg)
                refreshDevices()
            } catch (ex: Exception) {
                state = state.copy(isLoading = false, error = ex.message ?: "Wake fehlgeschlagen")
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
