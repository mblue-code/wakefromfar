package com.wakefromfar.wolrelay.ui

import android.app.Activity
import android.app.Application
import android.content.Context
import android.content.SharedPreferences
import android.util.Base64
import androidx.annotation.StringRes
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.ViewModelProvider
import androidx.lifecycle.viewModelScope
import androidx.lifecycle.viewmodel.CreationExtras
import com.android.billingclient.api.AcknowledgePurchaseParams
import com.android.billingclient.api.BillingClient
import com.android.billingclient.api.BillingClientStateListener
import com.android.billingclient.api.BillingFlowParams
import com.android.billingclient.api.BillingResult
import com.android.billingclient.api.ProductDetails
import com.android.billingclient.api.Purchase
import com.android.billingclient.api.PurchasesUpdatedListener
import com.android.billingclient.api.QueryProductDetailsParams
import com.android.billingclient.api.QueryPurchasesParams
import com.wakefromfar.wolrelay.AppLanguage
import com.wakefromfar.wolrelay.LanguagePrefs
import com.wakefromfar.wolrelay.R
import com.wakefromfar.wolrelay.data.AndroidAppProofCoordinator
import com.wakefromfar.wolrelay.data.ApiClient
import com.wakefromfar.wolrelay.data.ApiException
import com.wakefromfar.wolrelay.data.ActivityEventDto
import com.wakefromfar.wolrelay.data.InviteLinkParser
import com.wakefromfar.wolrelay.data.InstallationIdStore
import com.wakefromfar.wolrelay.data.MyDeviceDto
import com.wakefromfar.wolrelay.data.PlayIntegrityStandardTokenProvider
import com.wakefromfar.wolrelay.data.SecurePrefs
import com.wakefromfar.wolrelay.data.ThemeMode
import com.wakefromfar.wolrelay.BuildConfig
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import org.json.JSONObject

data class DeviceSectionUiModel(
    val key: String,
    val title: String,
    val devices: List<MyDeviceDto>,
    val isFavorites: Boolean = false,
)

data class AppUiState(
    val backendUrl: String = "",
    val username: String = "",
    val password: String = "",
    val inviteToken: String? = null,
    val claimPassword: String = "",
    val token: String? = null,
    val userRole: String? = null,
    val firstRunOnboardingAcknowledged: Boolean = false,
    val themeMode: ThemeMode = ThemeMode.SYSTEM,
    val appLanguage: AppLanguage = AppLanguage.ENGLISH,
    val devices: List<MyDeviceDto> = emptyList(),
    val deviceSections: List<DeviceSectionUiModel> = emptyList(),
    val activityEvents: List<ActivityEventDto> = emptyList(),
    val hasProAccess: Boolean = false,
    val freeDeviceLimit: Int = FREE_DEVICE_LIMIT,
    val hiddenFreeDevices: Int = 0,
    val canPurchasePro: Boolean = false,
    val isPurchaseInProgress: Boolean = false,
    val isLoading: Boolean = false,
    val isActivityLoading: Boolean = false,
    val isActivityLoadingMore: Boolean = false,
    val activityHasMore: Boolean = false,
    val adminBackgroundAlertsEnabled: Boolean = true,
    val error: String? = null,
    val info: String? = null,
) {
    val isAuthenticated: Boolean
        get() = !token.isNullOrBlank()
    val isAdmin: Boolean
        get() = userRole == "admin"
    val hasInviteToken: Boolean
        get() = !inviteToken.isNullOrBlank()
}

class MainViewModel(application: Application) : AndroidViewModel(application), PurchasesUpdatedListener {
    private val prefs = SecurePrefs(application)
    private val api = ApiClient()
    private val appProof = AndroidAppProofCoordinator(
        apiClient = api,
        installationIdStore = InstallationIdStore { prefs.getInstallationId() },
        tokenProvider = buildIntegrityTokenProvider(application.applicationContext),
    )
    private val adminNotifications = AdminNotificationDispatcher(application.applicationContext)
    private val monetizationPrefs: SharedPreferences =
        application.getSharedPreferences(MONETIZATION_PREFS_NAME, Context.MODE_PRIVATE)
    private val billingClient = BillingClient
        .newBuilder(application)
        .setListener(this)
        .enablePendingPurchases()
        .build()

    private var proProductDetails: ProductDetails? = null
    private var allVisibleDevices: List<MyDeviceDto> = emptyList()
    private var activityFeedCursor: Int? = null
    private var activityPollingJob: Job? = null
    private var isActivityRefreshInFlight = false
    private var isActivityLoadMoreInFlight = false

    var state by mutableStateOf(
        AppUiState(
            backendUrl = prefs.getBackendUrl(),
            token = prefs.getToken(),
            userRole = extractRoleFromToken(prefs.getToken()),
            firstRunOnboardingAcknowledged = prefs.isFirstRunOnboardingAcknowledged(),
            themeMode = prefs.getThemeMode(),
            appLanguage = LanguagePrefs.get(application),
            adminBackgroundAlertsEnabled = prefs.isAdminBackgroundAlertsEnabled(),
            hasProAccess = isProUnlockedLocally(),
        ),
    )
        private set

    init {
        connectBilling()
        syncAdminBackgroundPolling()
        if (state.isAuthenticated) {
            refreshDevices()
            if (state.isAdmin) {
                refreshActivityEvents()
            }
        }
    }

    override fun onCleared() {
        stopAdminActivityPolling()
        billingClient.endConnection()
        super.onCleared()
    }

    private fun tr(@StringRes resId: Int, vararg args: Any): String = getApplication<Application>().getString(resId, *args)

    private fun installationId(): String = prefs.getInstallationId()

    private fun buildIntegrityTokenProvider(context: Context) =
        if (BuildConfig.PLAY_INTEGRITY_CLOUD_PROJECT_NUMBER.isBlank()) {
            com.wakefromfar.wolrelay.data.IntegrityTokenProvider { throw IllegalStateException("Play Integrity not configured") }
        } else {
            PlayIntegrityStandardTokenProvider(
                context = context,
                cloudProjectNumber = BuildConfig.PLAY_INTEGRITY_CLOUD_PROJECT_NUMBER.toLong(),
            )
        }

    private fun messageOr(@StringRes fallbackResId: Int, ex: Exception): String {
        if (ex is ApiException) {
            return tr(fallbackResId)
        }
        return ex.message ?: tr(fallbackResId)
    }

    private fun forbiddenMessageOr(
        ex: Exception,
        @StringRes forbiddenResId: Int,
        @StringRes fallbackResId: Int,
    ): String {
        return if (ex is ApiException && ex.statusCode == 403) {
            tr(forbiddenResId)
        } else {
            messageOr(fallbackResId, ex)
        }
    }

    private fun extractRoleFromToken(token: String?): String? {
        if (token.isNullOrBlank()) {
            return null
        }
        val parts = token.split(".")
        if (parts.size < 2) {
            return null
        }
        return try {
            val payloadBytes = Base64.decode(parts[1], Base64.URL_SAFE or Base64.NO_PADDING or Base64.NO_WRAP)
            val payload = JSONObject(String(payloadBytes, Charsets.UTF_8))
            payload.optString("role").trim().ifBlank { null }
        } catch (_: Exception) {
            null
        }
    }

    fun updateBackendUrl(value: String) {
        val previousUrl = state.backendUrl.trim().trimEnd('/')
        val nextUrl = value.trim().trimEnd('/')
        if (previousUrl != nextUrl) {
            prefs.setLastSeenAdminActivityEventId(0)
            prefs.setLastNotifiedShutdownEventId(0)
            resetActivityFeedPagination(clearEvents = true)
        }
        state = state.copy(backendUrl = value)
        syncAdminBackgroundPolling()
        if (allVisibleDevices.isNotEmpty()) {
            applyDeviceEntitlement()
        }
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

    fun updateAdminBackgroundAlertsEnabled(enabled: Boolean) {
        prefs.setAdminBackgroundAlertsEnabled(enabled)
        state = state.copy(adminBackgroundAlertsEnabled = enabled)
        syncAdminBackgroundPolling()
    }

    fun acknowledgeFirstRunOnboarding() {
        prefs.setFirstRunOnboardingAcknowledged(true)
        state = state.copy(firstRunOnboardingAcknowledged = true)
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
                val proof = appProof.prepareLoginProof(state.backendUrl, state.username.trim())
                val response = api.login(
                    baseUrl = state.backendUrl,
                    username = state.username,
                    password = state.password,
                    installationId = proof.installationId,
                    proofTicket = proof.proofTicket,
                )
                val role = extractRoleFromToken(response.token)
                prefs.setToken(response.token)
                prefs.setBackendUrl(state.backendUrl)
                state = state.copy(
                    token = response.token,
                    userRole = role,
                    password = "",
                    isLoading = false,
                    info = tr(R.string.info_login_success),
                )
                syncAdminBackgroundPolling()
                refreshDevices()
                if (role == "admin") {
                    refreshActivityEvents()
                } else {
                    stopAdminActivityPolling()
                }
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
        if (state.claimPassword.length < 6) {
            state = state.copy(error = tr(R.string.error_password_min_length, 6))
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
                val role = response.role.ifBlank { extractRoleFromToken(response.token) ?: "" }.ifBlank { null }
                prefs.setToken(response.token)
                prefs.setBackendUrl(state.backendUrl)
                state = state.copy(
                    token = response.token,
                    userRole = role,
                    username = response.username,
                    password = "",
                    claimPassword = "",
                    inviteToken = null,
                    isLoading = false,
                    info = tr(R.string.info_onboarding_success, response.username),
                )
                syncAdminBackgroundPolling()
                refreshDevices()
                if (role == "admin") {
                    refreshActivityEvents()
                } else {
                    stopAdminActivityPolling()
                }
            } catch (ex: Exception) {
                state = state.copy(isLoading = false, error = messageOr(R.string.error_onboarding_failed, ex))
            }
        }
    }

    fun logout() {
        stopAdminActivityPolling()
        resetActivityFeedPagination(clearEvents = true)
        prefs.clearSession()
        prefs.setLastNotifiedShutdownEventId(0)
        allVisibleDevices = emptyList()
        state = state.copy(
            token = null,
            userRole = null,
            devices = emptyList(),
            deviceSections = emptyList(),
            activityEvents = emptyList(),
            hiddenFreeDevices = 0,
            isActivityLoading = false,
            isActivityLoadingMore = false,
            activityHasMore = false,
            info = tr(R.string.info_logged_out),
        )
        syncAdminBackgroundPolling()
    }

    fun refreshDevices() {
        val token = state.token ?: return
        state = state.copy(isLoading = true, error = null)
        viewModelScope.launch {
            try {
                allVisibleDevices = sortDevicesForPresentation(
                    api.listMyDevices(
                        baseUrl = state.backendUrl,
                        token = token,
                        installationId = installationId(),
                    ),
                )
                applyDeviceEntitlement(isLoading = false)
            } catch (ex: Exception) {
                state = state.copy(isLoading = false, error = messageOr(R.string.error_devices_load_failed, ex))
            }
        }
    }

    fun refreshActivityEvents(showLoading: Boolean = true, silentErrors: Boolean = false) {
        val token = state.token ?: return
        if (!state.isAdmin) {
            return
        }
        if (isActivityRefreshInFlight) {
            return
        }
        isActivityRefreshInFlight = true
        if (showLoading) {
            state = state.copy(isActivityLoading = true, error = if (silentErrors) state.error else null)
        }
        viewModelScope.launch {
            try {
                val events = api.listAdminEvents(
                    baseUrl = state.backendUrl,
                    token = token,
                    limit = ACTIVITY_PAGE_SIZE,
                    typeFilter = "wake,poke",
                    installationId = installationId(),
                )
                if (state.token != token || !state.isAdmin) {
                    return@launch
                }
                activityFeedCursor = events.lastOrNull()?.id
                val latestEventId = events.maxOfOrNull { it.id }
                val previousEventId = prefs.getLastSeenAdminActivityEventId()
                val previousNotifiedEventId = prefs.getLastNotifiedShutdownEventId()
                val newEventsCount = if (previousEventId > 0) events.count { it.id > previousEventId } else 0
                val newShutdownRequests = if (previousNotifiedEventId > 0) {
                    events.filter { it.id > previousNotifiedEventId && it.event_type == SHUTDOWN_REQUEST_EVENT_TYPE }
                } else {
                    emptyList()
                }
                if (latestEventId != null && latestEventId > previousEventId) {
                    prefs.setLastSeenAdminActivityEventId(latestEventId)
                }
                adminNotifications.notifyShutdownRequests(newShutdownRequests)
                if (latestEventId != null && latestEventId > previousNotifiedEventId) {
                    prefs.setLastNotifiedShutdownEventId(latestEventId)
                }
                state = state.copy(
                    activityEvents = events,
                    isActivityLoading = false,
                    isActivityLoadingMore = false,
                    activityHasMore = events.size >= ACTIVITY_PAGE_SIZE,
                    info = if (newEventsCount > 0) tr(R.string.info_new_activity_events, newEventsCount) else state.info,
                )
            } catch (ex: Exception) {
                state = if (silentErrors) {
                    state.copy(isActivityLoading = false, isActivityLoadingMore = false)
                } else {
                    state.copy(
                        isActivityLoading = false,
                        isActivityLoadingMore = false,
                        error = messageOr(R.string.error_activity_load_failed, ex),
                    )
                }
            } finally {
                isActivityRefreshInFlight = false
            }
        }
    }

    fun loadMoreActivityEvents() {
        val token = state.token ?: return
        if (!state.isAdmin || !state.activityHasMore || isActivityLoadMoreInFlight) {
            return
        }
        val cursor = activityFeedCursor ?: return
        isActivityLoadMoreInFlight = true
        state = state.copy(isActivityLoadingMore = true, error = null)
        viewModelScope.launch {
            try {
                val page = api.listAdminEvents(
                    baseUrl = state.backendUrl,
                    token = token,
                    cursor = cursor,
                    limit = ACTIVITY_PAGE_SIZE,
                    typeFilter = "wake,poke",
                    installationId = installationId(),
                )
                if (state.token != token || !state.isAdmin) {
                    return@launch
                }
                val merged = (state.activityEvents + page)
                    .distinctBy { it.id }
                    .sortedByDescending { it.id }
                activityFeedCursor = merged.lastOrNull()?.id
                state = state.copy(
                    activityEvents = merged,
                    isActivityLoadingMore = false,
                    activityHasMore = page.size >= ACTIVITY_PAGE_SIZE,
                )
            } catch (ex: Exception) {
                state = state.copy(
                    isActivityLoadingMore = false,
                    error = messageOr(R.string.error_activity_load_failed, ex),
                )
            } finally {
                isActivityLoadMoreInFlight = false
            }
        }
    }

    fun startAdminActivityPolling() {
        if (!state.isAuthenticated || !state.isAdmin || state.backendUrl.isBlank()) {
            return
        }
        if (activityPollingJob?.isActive == true) {
            return
        }
        refreshActivityEvents(showLoading = state.activityEvents.isEmpty(), silentErrors = true)
        activityPollingJob = viewModelScope.launch {
            while (isActive) {
                delay(ACTIVITY_POLL_INTERVAL_MS)
                refreshActivityEvents(showLoading = false, silentErrors = true)
            }
        }
    }

    fun stopAdminActivityPolling() {
        activityPollingJob?.cancel()
        activityPollingJob = null
    }

    fun wakeDevice(device: MyDeviceDto) {
        val token = state.token ?: return
        if (!device.canWake) {
            state = state.copy(error = tr(R.string.error_wake_not_permitted), info = null)
            return
        }
        state = state.copy(isLoading = true, error = null)
        viewModelScope.launch {
            try {
                val res = api.wakeDevice(
                    baseUrl = state.backendUrl,
                    token = token,
                    hostId = device.id,
                    installationId = installationId(),
                )
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
                if (state.isAdmin) {
                    refreshActivityEvents()
                }
            } catch (ex: Exception) {
                state = state.copy(
                    isLoading = false,
                    error = forbiddenMessageOr(ex, R.string.error_wake_not_permitted, R.string.error_wake_failed),
                )
            }
        }
    }

    fun requestShutdownPoke(device: MyDeviceDto, message: String? = null) {
        val token = state.token ?: return
        if (!device.canRequestShutdown) {
            state = state.copy(error = tr(R.string.error_shutdown_not_permitted), info = null)
            return
        }
        state = state.copy(isLoading = true, error = null)
        viewModelScope.launch {
            try {
                api.requestShutdownPoke(
                    baseUrl = state.backendUrl,
                    token = token,
                    hostId = device.id,
                    message = message,
                    installationId = installationId(),
                )
                state = state.copy(isLoading = false, info = tr(R.string.info_shutdown_request_sent))
                if (state.isAdmin) {
                    refreshActivityEvents()
                }
            } catch (ex: Exception) {
                state = state.copy(
                    isLoading = false,
                    error = forbiddenMessageOr(
                        ex,
                        R.string.error_shutdown_not_permitted,
                        R.string.error_shutdown_request_failed,
                    ),
                )
            }
        }
    }

    fun toggleFavorite(device: MyDeviceDto) {
        val token = state.token ?: return
        state = state.copy(isLoading = true, error = null, info = null)
        viewModelScope.launch {
            try {
                val updatedDevice = api.updateMyDevicePreferences(
                    baseUrl = state.backendUrl,
                    token = token,
                    hostId = device.id,
                    isFavorite = !device.is_favorite,
                    installationId = installationId(),
                )
                allVisibleDevices = sortDevicesForPresentation(
                    allVisibleDevices.map { existing ->
                        if (existing.id == updatedDevice.id) updatedDevice else existing
                    },
                )
                applyDeviceEntitlement(isLoading = false)
            } catch (ex: Exception) {
                state = state.copy(
                    isLoading = false,
                    error = messageOr(R.string.error_device_preferences_update_failed, ex),
                )
            }
        }
    }

    fun markShutdownPokeSeen(pokeId: String) {
        val token = state.token ?: return
        if (!state.isAdmin) {
            return
        }
        state = state.copy(isActivityLoading = true, error = null)
        viewModelScope.launch {
            try {
                api.markShutdownPokeSeen(
                    baseUrl = state.backendUrl,
                    token = token,
                    pokeId = pokeId,
                    installationId = installationId(),
                )
                state = state.copy(info = tr(R.string.info_shutdown_request_seen))
                refreshActivityEvents()
            } catch (ex: Exception) {
                state = state.copy(isActivityLoading = false, error = messageOr(R.string.error_shutdown_request_update_failed, ex))
            }
        }
    }

    fun markShutdownPokeResolved(pokeId: String) {
        val token = state.token ?: return
        if (!state.isAdmin) {
            return
        }
        state = state.copy(isActivityLoading = true, error = null)
        viewModelScope.launch {
            try {
                api.markShutdownPokeResolved(
                    baseUrl = state.backendUrl,
                    token = token,
                    pokeId = pokeId,
                    installationId = installationId(),
                )
                state = state.copy(info = tr(R.string.info_shutdown_request_resolved))
                refreshActivityEvents()
            } catch (ex: Exception) {
                state = state.copy(isActivityLoading = false, error = messageOr(R.string.error_shutdown_request_update_failed, ex))
            }
        }
    }

    fun startProPurchase(activity: Activity) {
        if (state.hasProAccess) {
            state = state.copy(info = tr(R.string.info_pro_already_unlocked))
            return
        }
        val productDetails = proProductDetails
        if (productDetails == null || !state.canPurchasePro) {
            state = state.copy(error = tr(R.string.error_pro_purchase_not_ready))
            return
        }

        val productDetailsParams = BillingFlowParams.ProductDetailsParams.newBuilder()
            .setProductDetails(productDetails)
            .build()

        val flowParams = BillingFlowParams.newBuilder()
            .setProductDetailsParamsList(listOf(productDetailsParams))
            .build()

        state = state.copy(isPurchaseInProgress = true, error = null)
        val result = billingClient.launchBillingFlow(activity, flowParams)
        if (result.responseCode != BillingClient.BillingResponseCode.OK) {
            state = state.copy(
                isPurchaseInProgress = false,
                error = tr(
                    R.string.error_pro_purchase_start_failed,
                    result.debugMessage.ifBlank { result.responseCode.toString() },
                ),
            )
        }
    }

    fun restoreProPurchases() {
        queryExistingPurchases()
    }

    override fun onPurchasesUpdated(billingResult: BillingResult, purchases: MutableList<Purchase>?) {
        when (billingResult.responseCode) {
            BillingClient.BillingResponseCode.OK -> {
                val purchaseList = purchases.orEmpty()
                val unlocked = unlockProFromPurchases(purchaseList)
                state = if (unlocked) {
                    state.copy(
                        isPurchaseInProgress = false,
                        info = tr(R.string.info_pro_purchase_success),
                        error = null,
                    )
                } else {
                    state.copy(
                        isPurchaseInProgress = false,
                        error = tr(R.string.error_pro_purchase_not_found),
                    )
                }
            }

            BillingClient.BillingResponseCode.USER_CANCELED -> {
                state = state.copy(isPurchaseInProgress = false, info = tr(R.string.info_pro_purchase_canceled))
            }

            else -> {
                state = state.copy(
                    isPurchaseInProgress = false,
                    error = tr(
                        R.string.error_pro_purchase_failed,
                        billingResult.debugMessage.ifBlank { billingResult.responseCode.toString() },
                    ),
                )
            }
        }
    }

    private fun connectBilling() {
        billingClient.startConnection(
            object : BillingClientStateListener {
                override fun onBillingSetupFinished(result: BillingResult) {
                    if (result.responseCode != BillingClient.BillingResponseCode.OK) {
                        state = state.copy(canPurchasePro = false)
                        return
                    }
                    queryProductDetails()
                    queryExistingPurchases()
                }

                override fun onBillingServiceDisconnected() {
                    state = state.copy(canPurchasePro = false)
                }
            },
        )
    }

    private fun queryProductDetails() {
        val productQuery = QueryProductDetailsParams.Product.newBuilder()
            .setProductId(PRO_PRODUCT_ID)
            .setProductType(BillingClient.ProductType.INAPP)
            .build()

        val params = QueryProductDetailsParams.newBuilder()
            .setProductList(listOf(productQuery))
            .build()

        billingClient.queryProductDetailsAsync(params) { result, detailsList ->
            if (result.responseCode != BillingClient.BillingResponseCode.OK) {
                proProductDetails = null
                state = state.copy(canPurchasePro = false)
                return@queryProductDetailsAsync
            }

            proProductDetails = detailsList.firstOrNull { it.productId == PRO_PRODUCT_ID }
            state = state.copy(canPurchasePro = proProductDetails != null)
        }
    }

    private fun queryExistingPurchases() {
        val params = QueryPurchasesParams.newBuilder()
            .setProductType(BillingClient.ProductType.INAPP)
            .build()

        billingClient.queryPurchasesAsync(params) { result, purchases ->
            if (result.responseCode != BillingClient.BillingResponseCode.OK) {
                return@queryPurchasesAsync
            }

            unlockProFromPurchases(purchases)
        }
    }

    private fun unlockProFromPurchases(purchases: List<Purchase>): Boolean {
        val matchingPurchase = purchases.firstOrNull(::isPurchasedProProduct)
        val shouldUnlock = matchingPurchase != null || isProUnlockedLocally()
        if (!shouldUnlock) {
            return false
        }

        if (matchingPurchase != null && !matchingPurchase.isAcknowledged) {
            val acknowledgeParams = AcknowledgePurchaseParams.newBuilder()
                .setPurchaseToken(matchingPurchase.purchaseToken)
                .build()
            billingClient.acknowledgePurchase(acknowledgeParams) {}
        }

        setProUnlockedLocally(true)
        if (!state.hasProAccess) {
            state = state.copy(hasProAccess = true)
            applyDeviceEntitlement()
        }
        return true
    }

    private fun isPurchasedProProduct(purchase: Purchase): Boolean {
        return purchase.purchaseState == Purchase.PurchaseState.PURCHASED &&
            purchase.products.contains(PRO_PRODUCT_ID)
    }

    private fun applyDeviceEntitlement(isLoading: Boolean = state.isLoading) {
        val visibleDevices = if (state.hasProAccess) {
            allVisibleDevices
        } else {
            freeTierVisibleDevices(allVisibleDevices)
        }
        val hiddenCount = (allVisibleDevices.size - visibleDevices.size).coerceAtLeast(0)
        state = state.copy(
            devices = visibleDevices,
            deviceSections = buildDeviceSections(
                devices = visibleDevices,
                favoritesTitle = tr(R.string.section_favorites),
                fallbackGroupTitle = tr(R.string.section_other_devices),
            ),
            hiddenFreeDevices = hiddenCount,
            isLoading = isLoading,
        )
    }

    private fun freeTierVisibleDevices(devices: List<MyDeviceDto>): List<MyDeviceDto> {
        return devices.take(FREE_DEVICE_LIMIT)
    }

    private fun resetActivityFeedPagination(clearEvents: Boolean) {
        activityFeedCursor = null
        isActivityRefreshInFlight = false
        isActivityLoadMoreInFlight = false
        if (clearEvents) {
            state = state.copy(
                activityEvents = emptyList(),
                isActivityLoading = false,
                isActivityLoadingMore = false,
                activityHasMore = false,
            )
        }
    }

    private fun syncAdminBackgroundPolling() {
        val application = getApplication<Application>()
        if (
            state.isAuthenticated &&
            state.isAdmin &&
            state.backendUrl.isNotBlank() &&
            state.adminBackgroundAlertsEnabled
        ) {
            AdminAlertForegroundService.stop(application)
            AdminActivityBackgroundScheduler.ensureScheduled(application)
        } else {
            AdminActivityBackgroundScheduler.cancel(application)
            AdminAlertForegroundService.stop(application)
        }
    }

    private fun isProUnlockedLocally(): Boolean = monetizationPrefs.getBoolean(KEY_PRO_UNLOCKED, false)

    private fun setProUnlockedLocally(value: Boolean) {
        monetizationPrefs.edit().putBoolean(KEY_PRO_UNLOCKED, value).apply()
    }

    companion object {
        private const val SHUTDOWN_REQUEST_EVENT_TYPE = "shutdown_poke_requested"
        private const val PRO_PRODUCT_ID = "wakefromfar_pro_unlock"
        private const val MONETIZATION_PREFS_NAME = "wolrelay_monetization"
        private const val KEY_PRO_UNLOCKED = "pro_unlocked"
        private const val ACTIVITY_PAGE_SIZE = 30
        private const val ACTIVITY_POLL_INTERVAL_MS = 30_000L

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

private const val FREE_DEVICE_LIMIT = 3

internal fun sortDevicesForPresentation(devices: List<MyDeviceDto>): List<MyDeviceDto> {
    return devices.sortedWith(
        compareByDescending<MyDeviceDto> { it.is_favorite }
            .thenBy { if (it.is_favorite || !it.group_name.isNullOrBlank()) 0 else 1 }
            .thenBy { if (it.is_favorite || it.group_name.isNullOrBlank()) "" else it.group_name.trim() }
            .thenBy { it.sort_order }
            .thenBy(String.CASE_INSENSITIVE_ORDER) { it.displayTitle }
            .thenBy(String.CASE_INSENSITIVE_ORDER) { it.name }
            .thenBy { it.id },
    )
}

internal fun buildDeviceSections(
    devices: List<MyDeviceDto>,
    favoritesTitle: String,
    fallbackGroupTitle: String,
): List<DeviceSectionUiModel> {
    if (devices.isEmpty()) {
        return emptyList()
    }

    val sortedDevices = sortDevicesForPresentation(devices)
    val favorites = sortedDevices.filter { it.is_favorite }
    val groupedDevices = sortedDevices.filterNot { it.is_favorite }
    val sections = mutableListOf<DeviceSectionUiModel>()

    if (favorites.isNotEmpty()) {
        sections += DeviceSectionUiModel(
            key = "favorites",
            title = favoritesTitle,
            devices = favorites,
            isFavorites = true,
        )
    }

    groupedDevices
        .groupBy { device ->
            device.group_name?.trim()?.takeIf { it.isNotEmpty() } ?: fallbackGroupTitle
        }
        .forEach { (groupTitle, groupDevices) ->
            sections += DeviceSectionUiModel(
                key = "group:$groupTitle",
                title = groupTitle,
                devices = groupDevices,
            )
        }

    return sections
}
