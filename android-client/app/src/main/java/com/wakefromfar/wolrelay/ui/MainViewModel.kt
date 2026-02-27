package com.wakefromfar.wolrelay.ui

import android.app.Application
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.ViewModelProvider
import androidx.lifecycle.viewmodel.CreationExtras
import androidx.lifecycle.viewModelScope
import com.wakefromfar.wolrelay.data.ApiClient
import com.wakefromfar.wolrelay.data.HostDto
import com.wakefromfar.wolrelay.data.SecurePrefs
import kotlinx.coroutines.launch

data class AppUiState(
    val backendUrl: String = "",
    val username: String = "",
    val password: String = "",
    val token: String? = null,
    val hosts: List<HostDto> = emptyList(),
    val isLoading: Boolean = false,
    val error: String? = null,
    val info: String? = null,
) {
    val isAuthenticated: Boolean
        get() = !token.isNullOrBlank()
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
            refreshHosts()
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
                refreshHosts()
            } catch (ex: Exception) {
                state = state.copy(isLoading = false, error = ex.message ?: "Login fehlgeschlagen")
            }
        }
    }

    fun logout() {
        prefs.clearSession()
        state = state.copy(token = null, hosts = emptyList(), info = "Ausgeloggt")
    }

    fun refreshHosts() {
        val token = state.token ?: return
        state = state.copy(isLoading = true, error = null)
        viewModelScope.launch {
            try {
                val hosts = api.listHosts(baseUrl = state.backendUrl, token = token)
                state = state.copy(hosts = hosts, isLoading = false)
            } catch (ex: Exception) {
                state = state.copy(isLoading = false, error = ex.message ?: "Hosts konnten nicht geladen werden")
            }
        }
    }

    fun wakeHost(hostId: String) {
        val token = state.token ?: return
        state = state.copy(isLoading = true, error = null)
        viewModelScope.launch {
            try {
                val res = api.wakeHost(baseUrl = state.backendUrl, token = token, hostId = hostId)
                state = state.copy(isLoading = false, info = "Magic packet sent: ${res.sent_to}")
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
