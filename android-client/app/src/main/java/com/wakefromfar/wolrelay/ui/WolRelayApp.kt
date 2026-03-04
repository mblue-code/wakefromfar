package com.wakefromfar.wolrelay.ui

import android.app.Activity
import android.content.Context
import android.content.ContextWrapper
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.BoxWithConstraints
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ColumnScope
import androidx.compose.foundation.layout.ExperimentalLayoutApi
import androidx.compose.foundation.layout.FlowRow
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.layout.widthIn
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.LazyRow
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.automirrored.filled.Logout
import androidx.compose.material.icons.filled.Computer
import androidx.compose.material.icons.filled.Language
import androidx.compose.material.icons.filled.Lock
import androidx.compose.material.icons.filled.Person
import androidx.compose.material.icons.filled.PowerSettingsNew
import androidx.compose.material.icons.filled.Refresh
import androidx.compose.material.icons.filled.Settings
import androidx.compose.material.icons.filled.Visibility
import androidx.compose.material.icons.filled.VisibilityOff
import androidx.compose.material.icons.filled.Warning
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.DropdownMenu
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.ElevatedCard
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.FilterChip
import androidx.compose.material3.FilledTonalButton
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Button
import androidx.compose.material3.RadioButton
import androidx.compose.material3.Scaffold
import androidx.compose.material3.SnackbarHost
import androidx.compose.material3.SnackbarHostState
import androidx.compose.material3.Surface
import androidx.compose.material3.Tab
import androidx.compose.material3.TabRow
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.TopAppBarDefaults
import androidx.compose.material3.pulltorefresh.PullToRefreshBox
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.shadow
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.LocalLifecycleOwner
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.text.input.VisualTransformation
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.LifecycleEventObserver
import com.wakefromfar.wolrelay.AppLanguage
import com.wakefromfar.wolrelay.R
import com.wakefromfar.wolrelay.data.ActivityEventDto
import com.wakefromfar.wolrelay.data.MyDeviceDto
import com.wakefromfar.wolrelay.data.ThemeMode
import com.wakefromfar.wolrelay.ui.theme.MonoTextStyle

private enum class AdminHomeTab {
    DEVICES,
    ACTIVITY,
}

private enum class ActivityFilter {
    ALL,
    WAKE,
    POKE_OPEN,
    POKE_SEEN,
    POKE_RESOLVED,
    ERROR,
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun WolRelayApp(
    vm: MainViewModel,
) {
    val state = vm.state
    val snackbarHost = remember { SnackbarHostState() }
    var showLegalPrivacy by remember { mutableStateOf(false) }
    var adminHomeTab by remember(state.isAdmin) { mutableStateOf(AdminHomeTab.DEVICES) }
    val hostActivity = LocalContext.current.findActivity()
    val lifecycleOwner = LocalLifecycleOwner.current

    LaunchedEffect(state.error, state.info) {
        val msg = state.error ?: state.info
        if (!msg.isNullOrBlank()) {
            snackbarHost.showSnackbar(msg)
            vm.dismissMessages()
        }
    }

    DisposableEffect(lifecycleOwner, state.isAuthenticated, state.isAdmin, state.backendUrl) {
        val observer = LifecycleEventObserver { _, event ->
            if (!state.isAuthenticated || !state.isAdmin) {
                vm.stopAdminActivityPolling()
                return@LifecycleEventObserver
            }
            when (event) {
                Lifecycle.Event.ON_START -> vm.startAdminActivityPolling()
                Lifecycle.Event.ON_STOP -> vm.stopAdminActivityPolling()
                else -> Unit
            }
        }
        lifecycleOwner.lifecycle.addObserver(observer)
        if (state.isAuthenticated && state.isAdmin && lifecycleOwner.lifecycle.currentState.isAtLeast(Lifecycle.State.STARTED)) {
            vm.startAdminActivityPolling()
        } else {
            vm.stopAdminActivityPolling()
        }
        onDispose {
            lifecycleOwner.lifecycle.removeObserver(observer)
            vm.stopAdminActivityPolling()
        }
    }

    Scaffold(
        containerColor = MaterialTheme.colorScheme.background,
        topBar = {
            TopAppBar(
                colors = TopAppBarDefaults.topAppBarColors(
                    containerColor = MaterialTheme.colorScheme.surface,
                    titleContentColor = MaterialTheme.colorScheme.onSurface,
                ),
                navigationIcon = {
                    if (showLegalPrivacy) {
                        IconButton(onClick = { showLegalPrivacy = false }) {
                            Icon(
                                imageVector = Icons.AutoMirrored.Filled.ArrowBack,
                                contentDescription = stringResource(R.string.action_back),
                            )
                        }
                    }
                },
                title = {
                    Text(
                        text = when {
                            showLegalPrivacy -> stringResource(R.string.title_legal_privacy)
                            state.isAuthenticated -> stringResource(R.string.title_my_devices)
                            else -> stringResource(R.string.title_app)
                        },
                        style = MaterialTheme.typography.titleLarge.copy(fontWeight = FontWeight.SemiBold),
                    )
                },
                actions = {
                    if (!showLegalPrivacy) {
                        SettingsMenu(
                            currentThemeMode = state.themeMode,
                            currentLanguage = state.appLanguage,
                            onThemeModeSelected = vm::updateThemeMode,
                            onLanguageSelected = vm::updateAppLanguage,
                            onOpenLegalPrivacy = { showLegalPrivacy = true },
                        )
                        if (state.isAuthenticated) {
                            IconButton(
                                onClick = {
                                    if (state.isAdmin && adminHomeTab == AdminHomeTab.ACTIVITY) {
                                        vm.refreshActivityEvents()
                                    } else {
                                        vm.refreshDevices()
                                    }
                                },
                            ) {
                                Icon(
                                    imageVector = Icons.Default.Refresh,
                                    contentDescription = stringResource(R.string.action_refresh),
                                )
                            }
                            IconButton(onClick = vm::logout) {
                                Icon(
                                    imageVector = Icons.AutoMirrored.Filled.Logout,
                                    contentDescription = stringResource(R.string.action_logout),
                                )
                            }
                        }
                    }
                },
            )
        },
        snackbarHost = { SnackbarHost(hostState = snackbarHost) },
    ) { innerPadding ->
        val contentModifier = Modifier
            .fillMaxSize()
            .padding(innerPadding)

        when {
            showLegalPrivacy -> LegalPrivacyScreen(modifier = contentModifier)

            state.isAuthenticated && state.isAdmin -> AdminHomeScreen(
                selectedTab = adminHomeTab,
                onSelectedTabChange = { adminHomeTab = it },
                devices = state.devices,
                activityEvents = state.activityEvents,
                hasProAccess = state.hasProAccess,
                freeDeviceLimit = state.freeDeviceLimit,
                hiddenFreeDevices = state.hiddenFreeDevices,
                canPurchasePro = state.canPurchasePro,
                isPurchaseInProgress = state.isPurchaseInProgress,
                isLoadingDevices = state.isLoading,
                isLoadingActivity = state.isActivityLoading,
                isLoadingActivityMore = state.isActivityLoadingMore,
                canLoadMoreActivity = state.activityHasMore,
                onWake = vm::wakeDevice,
                onRequestShutdown = vm::requestShutdownPoke,
                onRefreshDevices = vm::refreshDevices,
                onRefreshActivity = { vm.refreshActivityEvents() },
                onLoadMoreActivity = vm::loadMoreActivityEvents,
                onMarkShutdownSeen = vm::markShutdownPokeSeen,
                onMarkShutdownResolved = vm::markShutdownPokeResolved,
                onUpgradeToPro = { hostActivity?.let(vm::startProPurchase) },
                onRestorePurchases = vm::restoreProPurchases,
                modifier = contentModifier,
            )

            state.isAuthenticated -> DeviceListScreen(
                devices = state.devices,
                hasProAccess = state.hasProAccess,
                freeDeviceLimit = state.freeDeviceLimit,
                hiddenFreeDevices = state.hiddenFreeDevices,
                canPurchasePro = state.canPurchasePro,
                isPurchaseInProgress = state.isPurchaseInProgress,
                isLoading = state.isLoading,
                onWake = vm::wakeDevice,
                onRequestShutdown = vm::requestShutdownPoke,
                onRefresh = vm::refreshDevices,
                onUpgradeToPro = { hostActivity?.let(vm::startProPurchase) },
                onRestorePurchases = vm::restoreProPurchases,
                modifier = contentModifier,
            )

            !state.firstRunOnboardingAcknowledged -> FirstRunOnboardingScreen(
                currentLanguage = state.appLanguage,
                onLanguageSelected = vm::updateAppLanguage,
                onContinue = vm::acknowledgeFirstRunOnboarding,
                modifier = contentModifier,
            )

            state.hasInviteToken -> InviteClaimScreen(
                state = state,
                currentLanguage = state.appLanguage,
                onLanguageSelected = vm::updateAppLanguage,
                onBackendUrlChange = vm::updateBackendUrl,
                onClaimPasswordChange = vm::updateClaimPassword,
                onClaim = vm::claimInvite,
                onUseLogin = vm::clearInviteToken,
                modifier = contentModifier,
            )

            else -> LoginScreen(
                state = state,
                onBackendUrlChange = vm::updateBackendUrl,
                onUsernameChange = vm::updateUsername,
                onPasswordChange = vm::updatePassword,
                currentLanguage = state.appLanguage,
                onLanguageSelected = vm::updateAppLanguage,
                onLogin = vm::login,
                modifier = contentModifier,
            )
        }
    }
}

@Composable
private fun SettingsMenu(
    currentThemeMode: ThemeMode,
    currentLanguage: AppLanguage,
    onThemeModeSelected: (ThemeMode) -> Unit,
    onLanguageSelected: (AppLanguage) -> Unit,
    onOpenLegalPrivacy: () -> Unit,
) {
    var expanded by remember { mutableStateOf(false) }

    Box {
        IconButton(onClick = { expanded = true }) {
            Icon(
                imageVector = Icons.Default.Settings,
                contentDescription = stringResource(R.string.action_settings),
            )
        }
        DropdownMenu(
            expanded = expanded,
            onDismissRequest = { expanded = false },
        ) {
            ThemeMode.values().forEach { mode ->
                DropdownMenuItem(
                    text = {
                        Text(
                            when (mode) {
                                ThemeMode.SYSTEM -> stringResource(R.string.theme_system)
                                ThemeMode.LIGHT -> stringResource(R.string.theme_light)
                                ThemeMode.DARK -> stringResource(R.string.theme_dark)
                            },
                        )
                    },
                    leadingIcon = {
                        RadioButton(
                            selected = mode == currentThemeMode,
                            onClick = null,
                        )
                    },
                    onClick = {
                        onThemeModeSelected(mode)
                        expanded = false
                    },
                )
            }
            HorizontalDivider()
            AppLanguage.entries.forEach { language ->
                val languageLabelRes = when (language) {
                    AppLanguage.ENGLISH -> R.string.language_english
                    AppLanguage.GERMAN -> R.string.language_german
                }
                DropdownMenuItem(
                    text = { Text(stringResource(languageLabelRes)) },
                    leadingIcon = {
                        RadioButton(
                            selected = language == currentLanguage,
                            onClick = null,
                        )
                    },
                    onClick = {
                        onLanguageSelected(language)
                        expanded = false
                    },
                )
            }
            HorizontalDivider()
            DropdownMenuItem(
                text = { Text(stringResource(R.string.action_legal_privacy)) },
                onClick = {
                    onOpenLegalPrivacy()
                    expanded = false
                },
            )
        }
    }
}

@Composable
private fun AuthCard(
    modifier: Modifier = Modifier,
    content: @Composable ColumnScope.() -> Unit,
) {
    ElevatedCard(
        modifier = modifier,
        colors = CardDefaults.elevatedCardColors(
            containerColor = MaterialTheme.colorScheme.surface,
        ),
    ) {
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .padding(20.dp),
            verticalArrangement = Arrangement.spacedBy(14.dp),
        ) {
            content()
        }
    }
}

@Composable
private fun FirstRunOnboardingScreen(
    currentLanguage: AppLanguage,
    onLanguageSelected: (AppLanguage) -> Unit,
    onContinue: () -> Unit,
    modifier: Modifier = Modifier,
) {
    LazyColumn(
        modifier = modifier.fillMaxSize(),
        contentPadding = PaddingValues(horizontal = 24.dp, vertical = 16.dp),
        verticalArrangement = Arrangement.spacedBy(14.dp),
        horizontalAlignment = Alignment.CenterHorizontally,
    ) {
        item {
            LanguageSelector(
                currentLanguage = currentLanguage,
                onLanguageSelected = onLanguageSelected,
                modifier = Modifier.fillMaxWidth(),
            )
        }
        item {
            Surface(
                shape = CircleShape,
                color = MaterialTheme.colorScheme.errorContainer,
                modifier = Modifier.size(80.dp),
            ) {
                Box(contentAlignment = Alignment.Center) {
                    Icon(
                        imageVector = Icons.Default.Warning,
                        contentDescription = null,
                        tint = MaterialTheme.colorScheme.error,
                        modifier = Modifier.size(40.dp),
                    )
                }
            }
        }
        item {
            Text(
                text = stringResource(R.string.first_run_onboarding_title),
                style = MaterialTheme.typography.headlineSmall,
                color = MaterialTheme.colorScheme.onBackground,
            )
        }
        item {
            Text(
                text = stringResource(R.string.first_run_onboarding_subtitle),
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
        item {
            AuthCard(modifier = Modifier.fillMaxWidth()) {
                OnboardingRule(text = stringResource(R.string.first_run_rule_admin_backend))
                OnboardingRule(text = stringResource(R.string.first_run_rule_admin_address))
                OnboardingRule(text = stringResource(R.string.first_run_rule_private_network))
                OnboardingRule(text = stringResource(R.string.first_run_rule_cloudflare_optional))
                OnboardingRule(text = stringResource(R.string.first_run_rule_insecure))
                OnboardingRule(text = stringResource(R.string.first_run_rule_admin_credentials))

                Button(
                    onClick = onContinue,
                    modifier = Modifier.fillMaxWidth(),
                ) {
                    Text(stringResource(R.string.button_first_run_continue))
                }
            }
        }
    }
}

@Composable
private fun OnboardingRule(text: String) {
    Row(
        modifier = Modifier.fillMaxWidth(),
        horizontalArrangement = Arrangement.spacedBy(8.dp),
        verticalAlignment = Alignment.Top,
    ) {
        Text(
            text = "\u2022",
            style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.primary,
            fontWeight = FontWeight.SemiBold,
        )
        Text(
            text = text,
            style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.onSurface,
            modifier = Modifier.weight(1f),
        )
    }
}

@Composable
private fun LegalPrivacyScreen(modifier: Modifier = Modifier) {
    val privacyBullets = listOf(
        stringResource(R.string.legal_privacy_bullet_no_dev_storage),
        stringResource(R.string.legal_privacy_bullet_admin_backend),
        stringResource(R.string.legal_privacy_bullet_local_storage),
        stringResource(R.string.legal_privacy_bullet_network_security),
        stringResource(R.string.legal_privacy_bullet_account_admin_only),
        stringResource(R.string.legal_privacy_bullet_no_sale),
    )
    val billingBullets = listOf(
        stringResource(R.string.legal_billing_bullet_use_google_play),
        stringResource(R.string.legal_billing_bullet_google_handles_payment),
        stringResource(R.string.legal_billing_bullet_receipt_ids),
        stringResource(R.string.legal_billing_bullet_release_note),
    )
    val openSourceBullets = listOf(
        stringResource(R.string.legal_oss_bullet_python_direct),
        stringResource(R.string.legal_oss_bullet_python_transitive),
        stringResource(R.string.legal_oss_bullet_android_direct),
        stringResource(R.string.legal_oss_bullet_google_fonts),
        stringResource(R.string.legal_oss_bullet_container_os),
        stringResource(R.string.legal_oss_bullet_play_billing_license),
        stringResource(R.string.legal_oss_bullet_review_date),
    )

    LazyColumn(
        modifier = modifier.fillMaxSize(),
        contentPadding = PaddingValues(horizontal = 16.dp, vertical = 12.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        item {
            Text(
                text = stringResource(R.string.legal_intro),
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
        item {
            LegalSectionCard(
                title = stringResource(R.string.legal_section_privacy_title),
                body = stringResource(R.string.legal_section_privacy_body),
                bullets = privacyBullets,
            )
        }
        item {
            LegalSectionCard(
                title = stringResource(R.string.legal_section_billing_title),
                body = stringResource(R.string.legal_section_billing_body),
                bullets = billingBullets,
            )
        }
        item {
            LegalSectionCard(
                title = stringResource(R.string.legal_section_oss_title),
                body = stringResource(R.string.legal_section_oss_body),
                bullets = openSourceBullets,
            )
        }
        item {
            Text(
                text = stringResource(R.string.legal_oss_disclaimer),
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                modifier = Modifier.padding(horizontal = 4.dp),
            )
        }
    }
}

@Composable
private fun LegalSectionCard(
    title: String,
    body: String,
    bullets: List<String>,
) {
    ElevatedCard(
        modifier = Modifier.fillMaxWidth(),
        colors = CardDefaults.elevatedCardColors(
            containerColor = MaterialTheme.colorScheme.surface,
        ),
    ) {
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(10.dp),
        ) {
            Text(
                text = title,
                style = MaterialTheme.typography.titleMedium,
                color = MaterialTheme.colorScheme.onSurface,
            )
            Text(
                text = body,
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            bullets.forEach { bullet ->
                LegalBullet(text = bullet)
            }
        }
    }
}

@Composable
private fun LegalBullet(text: String) {
    Row(
        modifier = Modifier.fillMaxWidth(),
        horizontalArrangement = Arrangement.spacedBy(8.dp),
        verticalAlignment = Alignment.Top,
    ) {
        Text(
            text = "\u2022",
            style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.primary,
            fontWeight = FontWeight.SemiBold,
        )
        Text(
            text = text,
            style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.onSurface,
            modifier = Modifier.weight(1f),
        )
    }
}

@Composable
private fun InviteClaimScreen(
    state: AppUiState,
    currentLanguage: AppLanguage,
    onLanguageSelected: (AppLanguage) -> Unit,
    onBackendUrlChange: (String) -> Unit,
    onClaimPasswordChange: (String) -> Unit,
    onClaim: () -> Unit,
    onUseLogin: () -> Unit,
    modifier: Modifier = Modifier,
) {
    val tokenPreview = state.inviteToken?.take(10) ?: "-"
    var passwordVisible by remember { mutableStateOf(false) }

    Box(modifier = modifier, contentAlignment = Alignment.Center) {
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .padding(horizontal = 24.dp),
            horizontalAlignment = Alignment.CenterHorizontally,
            verticalArrangement = Arrangement.spacedBy(16.dp),
        ) {
            Surface(
                shape = CircleShape,
                color = MaterialTheme.colorScheme.primaryContainer,
                modifier = Modifier.size(80.dp),
            ) {
                Box(contentAlignment = Alignment.Center) {
                    Icon(
                        imageVector = Icons.Default.PowerSettingsNew,
                        contentDescription = null,
                        tint = MaterialTheme.colorScheme.primary,
                        modifier = Modifier.size(40.dp),
                    )
                }
            }

            Spacer(modifier = Modifier.height(4.dp))

            Text(
                text = stringResource(R.string.invite_detected),
                style = MaterialTheme.typography.headlineMedium,
                color = MaterialTheme.colorScheme.onBackground,
            )

            Spacer(modifier = Modifier.height(4.dp))

            LanguageSelector(
                currentLanguage = currentLanguage,
                onLanguageSelected = onLanguageSelected,
                modifier = Modifier.fillMaxWidth(),
            )

            Spacer(modifier = Modifier.height(4.dp))

            AuthCard(modifier = Modifier.fillMaxWidth()) {
                Surface(
                    color = MaterialTheme.colorScheme.primaryContainer,
                    shape = MaterialTheme.shapes.small,
                    modifier = Modifier.fillMaxWidth(),
                ) {
                    Text(
                        text = stringResource(R.string.invite_token_preview, tokenPreview),
                        style = MonoTextStyle,
                        color = MaterialTheme.colorScheme.onPrimaryContainer,
                        modifier = Modifier.padding(horizontal = 12.dp, vertical = 8.dp),
                    )
                }

                OutlinedTextField(
                    value = state.backendUrl,
                    onValueChange = onBackendUrlChange,
                    label = { Text(stringResource(R.string.label_backend_url)) },
                    leadingIcon = { Icon(Icons.Default.Language, contentDescription = null) },
                    singleLine = true,
                    modifier = Modifier.fillMaxWidth(),
                )
                OutlinedTextField(
                    value = state.claimPassword,
                    onValueChange = onClaimPasswordChange,
                    label = { Text(stringResource(R.string.label_new_password)) },
                    leadingIcon = { Icon(Icons.Default.Lock, contentDescription = null) },
                    trailingIcon = {
                        IconButton(onClick = { passwordVisible = !passwordVisible }) {
                            Icon(
                                imageVector = if (passwordVisible) Icons.Default.VisibilityOff else Icons.Default.Visibility,
                                contentDescription = stringResource(
                                    if (passwordVisible) {
                                        R.string.action_hide_password
                                    } else {
                                        R.string.action_show_password
                                    },
                                ),
                            )
                        }
                    },
                    visualTransformation = if (passwordVisible) VisualTransformation.None else PasswordVisualTransformation(),
                    singleLine = true,
                    modifier = Modifier.fillMaxWidth(),
                )

                if (state.isLoading) {
                    Box(modifier = Modifier.fillMaxWidth(), contentAlignment = Alignment.Center) {
                        CircularProgressIndicator(modifier = Modifier.size(28.dp))
                    }
                } else {
                    Button(
                        onClick = onClaim,
                        enabled = !state.isLoading,
                        modifier = Modifier.fillMaxWidth(),
                    ) {
                        Text(stringResource(R.string.button_activate_account))
                    }
                }
            }

            TextButton(onClick = onUseLogin, enabled = !state.isLoading) {
                Text(stringResource(R.string.action_use_regular_login))
            }
        }
    }
}

@Composable
private fun LoginScreen(
    state: AppUiState,
    onBackendUrlChange: (String) -> Unit,
    onUsernameChange: (String) -> Unit,
    onPasswordChange: (String) -> Unit,
    currentLanguage: AppLanguage,
    onLanguageSelected: (AppLanguage) -> Unit,
    onLogin: () -> Unit,
    modifier: Modifier = Modifier,
) {
    var passwordVisible by remember { mutableStateOf(false) }

    Box(modifier = modifier, contentAlignment = Alignment.Center) {
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .padding(horizontal = 24.dp),
            horizontalAlignment = Alignment.CenterHorizontally,
            verticalArrangement = Arrangement.spacedBy(0.dp),
        ) {
            Surface(
                shape = CircleShape,
                color = MaterialTheme.colorScheme.primaryContainer,
                modifier = Modifier.size(80.dp),
            ) {
                Box(contentAlignment = Alignment.Center) {
                    Icon(
                        imageVector = Icons.Default.PowerSettingsNew,
                        contentDescription = null,
                        tint = MaterialTheme.colorScheme.primary,
                        modifier = Modifier.size(40.dp),
                    )
                }
            }

            Spacer(modifier = Modifier.height(12.dp))

            Text(
                text = stringResource(R.string.title_app),
                style = MaterialTheme.typography.headlineMedium,
                color = MaterialTheme.colorScheme.onBackground,
            )

            Spacer(modifier = Modifier.height(4.dp))

            Text(
                text = stringResource(R.string.login_subtitle),
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )

            Spacer(modifier = Modifier.height(14.dp))

            LanguageSelector(
                currentLanguage = currentLanguage,
                onLanguageSelected = onLanguageSelected,
                modifier = Modifier.fillMaxWidth(),
            )

            Spacer(modifier = Modifier.height(24.dp))

            AuthCard(modifier = Modifier.fillMaxWidth()) {
                OutlinedTextField(
                    value = state.backendUrl,
                    onValueChange = onBackendUrlChange,
                    label = { Text(stringResource(R.string.label_backend_url)) },
                    leadingIcon = { Icon(Icons.Default.Language, contentDescription = null) },
                    singleLine = true,
                    modifier = Modifier.fillMaxWidth(),
                )
                OutlinedTextField(
                    value = state.username,
                    onValueChange = onUsernameChange,
                    label = { Text(stringResource(R.string.label_username)) },
                    leadingIcon = { Icon(Icons.Default.Person, contentDescription = null) },
                    singleLine = true,
                    modifier = Modifier.fillMaxWidth(),
                )
                OutlinedTextField(
                    value = state.password,
                    onValueChange = onPasswordChange,
                    label = { Text(stringResource(R.string.label_password)) },
                    leadingIcon = { Icon(Icons.Default.Lock, contentDescription = null) },
                    trailingIcon = {
                        IconButton(onClick = { passwordVisible = !passwordVisible }) {
                            Icon(
                                imageVector = if (passwordVisible) Icons.Default.VisibilityOff else Icons.Default.Visibility,
                                contentDescription = stringResource(
                                    if (passwordVisible) {
                                        R.string.action_hide_password
                                    } else {
                                        R.string.action_show_password
                                    },
                                ),
                            )
                        }
                    },
                    visualTransformation = if (passwordVisible) VisualTransformation.None else PasswordVisualTransformation(),
                    singleLine = true,
                    modifier = Modifier.fillMaxWidth(),
                )

                if (state.isLoading) {
                    Box(modifier = Modifier.fillMaxWidth(), contentAlignment = Alignment.Center) {
                        CircularProgressIndicator(modifier = Modifier.size(28.dp))
                    }
                } else {
                    Button(
                        onClick = onLogin,
                        enabled = !state.isLoading,
                        modifier = Modifier.fillMaxWidth(),
                    ) {
                        Text(stringResource(R.string.button_login))
                    }
                }
            }
        }
    }
}

@Composable
private fun LanguageSelector(
    currentLanguage: AppLanguage,
    onLanguageSelected: (AppLanguage) -> Unit,
    modifier: Modifier = Modifier,
) {
    var expanded by remember { mutableStateOf(false) }
    val currentLanguageLabel = when (currentLanguage) {
        AppLanguage.ENGLISH -> stringResource(R.string.language_english)
        AppLanguage.GERMAN -> stringResource(R.string.language_german)
    }

    Row(
        modifier = modifier,
        horizontalArrangement = Arrangement.End,
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Text(
            text = stringResource(R.string.label_language),
            style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
        Spacer(modifier = Modifier.width(8.dp))
        Box {
            TextButton(onClick = { expanded = true }) {
                Text(currentLanguageLabel)
            }
            DropdownMenu(
                expanded = expanded,
                onDismissRequest = { expanded = false },
            ) {
                AppLanguage.entries.forEach { language ->
                    val languageLabelRes = when (language) {
                        AppLanguage.ENGLISH -> R.string.language_english
                        AppLanguage.GERMAN -> R.string.language_german
                    }
                    DropdownMenuItem(
                        text = { Text(stringResource(languageLabelRes)) },
                        leadingIcon = {
                            RadioButton(
                                selected = language == currentLanguage,
                                onClick = null,
                            )
                        },
                        onClick = {
                            onLanguageSelected(language)
                            expanded = false
                        },
                    )
                }
            }
        }
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun AdminHomeScreen(
    selectedTab: AdminHomeTab,
    onSelectedTabChange: (AdminHomeTab) -> Unit,
    devices: List<MyDeviceDto>,
    activityEvents: List<ActivityEventDto>,
    hasProAccess: Boolean,
    freeDeviceLimit: Int,
    hiddenFreeDevices: Int,
    canPurchasePro: Boolean,
    isPurchaseInProgress: Boolean,
    isLoadingDevices: Boolean,
    isLoadingActivity: Boolean,
    isLoadingActivityMore: Boolean,
    canLoadMoreActivity: Boolean,
    onWake: (String) -> Unit,
    onRequestShutdown: (String, String?) -> Unit,
    onRefreshDevices: () -> Unit,
    onRefreshActivity: () -> Unit,
    onLoadMoreActivity: () -> Unit,
    onMarkShutdownSeen: (String) -> Unit,
    onMarkShutdownResolved: (String) -> Unit,
    onUpgradeToPro: () -> Unit,
    onRestorePurchases: () -> Unit,
    modifier: Modifier = Modifier,
) {
    Column(modifier = modifier.fillMaxSize()) {
        TabRow(selectedTabIndex = if (selectedTab == AdminHomeTab.DEVICES) 0 else 1) {
            Tab(
                selected = selectedTab == AdminHomeTab.DEVICES,
                onClick = { onSelectedTabChange(AdminHomeTab.DEVICES) },
                text = { Text(stringResource(R.string.tab_devices)) },
            )
            Tab(
                selected = selectedTab == AdminHomeTab.ACTIVITY,
                onClick = { onSelectedTabChange(AdminHomeTab.ACTIVITY) },
                text = { Text(stringResource(R.string.tab_activity)) },
            )
        }

        when (selectedTab) {
            AdminHomeTab.DEVICES -> DeviceListScreen(
                devices = devices,
                hasProAccess = hasProAccess,
                freeDeviceLimit = freeDeviceLimit,
                hiddenFreeDevices = hiddenFreeDevices,
                canPurchasePro = canPurchasePro,
                isPurchaseInProgress = isPurchaseInProgress,
                isLoading = isLoadingDevices,
                onWake = onWake,
                onRequestShutdown = onRequestShutdown,
                onRefresh = onRefreshDevices,
                onUpgradeToPro = onUpgradeToPro,
                onRestorePurchases = onRestorePurchases,
                modifier = Modifier.fillMaxSize(),
            )

            AdminHomeTab.ACTIVITY -> ActivityFeedScreen(
                events = activityEvents,
                isLoading = isLoadingActivity,
                isLoadingMore = isLoadingActivityMore,
                canLoadMore = canLoadMoreActivity,
                onRefresh = onRefreshActivity,
                onLoadMore = onLoadMoreActivity,
                onMarkShutdownSeen = onMarkShutdownSeen,
                onMarkShutdownResolved = onMarkShutdownResolved,
                modifier = Modifier.fillMaxSize(),
            )
        }
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun ActivityFeedScreen(
    events: List<ActivityEventDto>,
    isLoading: Boolean,
    isLoadingMore: Boolean,
    canLoadMore: Boolean,
    onRefresh: () -> Unit,
    onLoadMore: () -> Unit,
    onMarkShutdownSeen: (String) -> Unit,
    onMarkShutdownResolved: (String) -> Unit,
    modifier: Modifier = Modifier,
) {
    var selectedFilter by remember { mutableStateOf(ActivityFilter.ALL) }
    val filteredEvents = remember(events, selectedFilter) {
        events.filter { event ->
            when (selectedFilter) {
                ActivityFilter.ALL -> true
                ActivityFilter.WAKE -> event.event_type in setOf("wake_sent", "wake_failed", "wake_already_on")
                ActivityFilter.POKE_OPEN -> event.event_type == "shutdown_poke_requested"
                ActivityFilter.POKE_SEEN -> event.event_type == "shutdown_poke_seen"
                ActivityFilter.POKE_RESOLVED -> event.event_type == "shutdown_poke_resolved"
                ActivityFilter.ERROR -> event.event_type == "wake_failed"
            }
        }
    }

    if (isLoading && events.isEmpty()) {
        Box(modifier = modifier, contentAlignment = Alignment.Center) {
            CircularProgressIndicator()
        }
        return
    }

    PullToRefreshBox(
        isRefreshing = isLoading,
        onRefresh = onRefresh,
        modifier = modifier,
    ) {
        if (events.isEmpty()) {
            Box(modifier = Modifier.fillMaxSize(), contentAlignment = Alignment.Center) {
                Column(
                    horizontalAlignment = Alignment.CenterHorizontally,
                    verticalArrangement = Arrangement.spacedBy(8.dp),
                ) {
                    Icon(
                        imageVector = Icons.Default.Computer,
                        contentDescription = null,
                        tint = MaterialTheme.colorScheme.onSurfaceVariant,
                        modifier = Modifier.size(56.dp),
                    )
                    Text(
                        text = stringResource(R.string.text_no_activity_events),
                        style = MaterialTheme.typography.bodyLarge,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                    Text(
                        text = stringResource(R.string.text_no_activity_hint),
                        style = MaterialTheme.typography.bodyMedium,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                }
            }
        } else {
            Column(modifier = Modifier.fillMaxSize()) {
                LazyRow(
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(horizontal = 12.dp, vertical = 10.dp),
                    horizontalArrangement = Arrangement.spacedBy(8.dp),
                ) {
                    item {
                        ActivityFilterChip(
                            text = stringResource(R.string.filter_activity_all),
                            selected = selectedFilter == ActivityFilter.ALL,
                            onClick = { selectedFilter = ActivityFilter.ALL },
                        )
                    }
                    item {
                        ActivityFilterChip(
                            text = stringResource(R.string.filter_activity_wake),
                            selected = selectedFilter == ActivityFilter.WAKE,
                            onClick = { selectedFilter = ActivityFilter.WAKE },
                        )
                    }
                    item {
                        ActivityFilterChip(
                            text = stringResource(R.string.filter_activity_poke_open),
                            selected = selectedFilter == ActivityFilter.POKE_OPEN,
                            onClick = { selectedFilter = ActivityFilter.POKE_OPEN },
                        )
                    }
                    item {
                        ActivityFilterChip(
                            text = stringResource(R.string.filter_activity_poke_seen),
                            selected = selectedFilter == ActivityFilter.POKE_SEEN,
                            onClick = { selectedFilter = ActivityFilter.POKE_SEEN },
                        )
                    }
                    item {
                        ActivityFilterChip(
                            text = stringResource(R.string.filter_activity_poke_resolved),
                            selected = selectedFilter == ActivityFilter.POKE_RESOLVED,
                            onClick = { selectedFilter = ActivityFilter.POKE_RESOLVED },
                        )
                    }
                    item {
                        ActivityFilterChip(
                            text = stringResource(R.string.filter_activity_error),
                            selected = selectedFilter == ActivityFilter.ERROR,
                            onClick = { selectedFilter = ActivityFilter.ERROR },
                        )
                    }
                }

                if (filteredEvents.isEmpty()) {
                    Box(modifier = Modifier.fillMaxSize(), contentAlignment = Alignment.Center) {
                        Column(
                            horizontalAlignment = Alignment.CenterHorizontally,
                            verticalArrangement = Arrangement.spacedBy(8.dp),
                        ) {
                            Text(
                                text = stringResource(R.string.text_no_activity_for_filter),
                                style = MaterialTheme.typography.bodyMedium,
                                color = MaterialTheme.colorScheme.onSurfaceVariant,
                            )
                            if (canLoadMore) {
                                TextButton(onClick = onLoadMore, enabled = !isLoadingMore) {
                                    if (isLoadingMore) {
                                        CircularProgressIndicator(modifier = Modifier.size(16.dp))
                                    } else {
                                        Text(stringResource(R.string.action_load_more_activity))
                                    }
                                }
                            }
                        }
                    }
                } else {
                    LazyColumn(
                        modifier = Modifier.fillMaxSize(),
                        contentPadding = PaddingValues(horizontal = 16.dp, vertical = 8.dp),
                        verticalArrangement = Arrangement.spacedBy(10.dp),
                    ) {
                        items(filteredEvents, key = { it.id }) { event ->
                            ActivityEventCard(
                                event = event,
                                onMarkShutdownSeen = onMarkShutdownSeen,
                                onMarkShutdownResolved = onMarkShutdownResolved,
                            )
                        }
                        if (canLoadMore) {
                            item {
                                Box(
                                    modifier = Modifier
                                        .fillMaxWidth()
                                        .padding(top = 6.dp, bottom = 4.dp),
                                    contentAlignment = Alignment.Center,
                                ) {
                                    TextButton(onClick = onLoadMore, enabled = !isLoadingMore) {
                                        if (isLoadingMore) {
                                            CircularProgressIndicator(modifier = Modifier.size(16.dp))
                                        } else {
                                            Text(stringResource(R.string.action_load_more_activity))
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}

@Composable
private fun ActivityFilterChip(
    text: String,
    selected: Boolean,
    onClick: () -> Unit,
) {
    FilterChip(
        selected = selected,
        onClick = onClick,
        label = { Text(text = text) },
    )
}

@Composable
private fun ActivityEventCard(
    event: ActivityEventDto,
    onMarkShutdownSeen: (String) -> Unit,
    onMarkShutdownResolved: (String) -> Unit,
) {
    val shutdownRequestId = event.target_id?.trim().orEmpty()
    val canActOnShutdownRequest = event.event_type == "shutdown_poke_requested" && shutdownRequestId.isNotBlank()
    ElevatedCard(
        modifier = Modifier.fillMaxWidth(),
        colors = CardDefaults.elevatedCardColors(
            containerColor = MaterialTheme.colorScheme.surface,
        ),
    ) {
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .padding(14.dp),
            verticalArrangement = Arrangement.spacedBy(6.dp),
        ) {
            Text(
                text = event.summary,
                style = MaterialTheme.typography.titleSmall,
                color = MaterialTheme.colorScheme.onSurface,
            )
            Text(
                text = event.created_at,
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            if (canActOnShutdownRequest) {
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.End,
                    verticalAlignment = Alignment.CenterVertically,
                ) {
                    TextButton(onClick = { onMarkShutdownSeen(shutdownRequestId) }) {
                        Text(stringResource(R.string.action_mark_seen))
                    }
                    TextButton(onClick = { onMarkShutdownResolved(shutdownRequestId) }) {
                        Text(stringResource(R.string.action_mark_resolved))
                    }
                }
            }
        }
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun DeviceListScreen(
    devices: List<MyDeviceDto>,
    hasProAccess: Boolean,
    freeDeviceLimit: Int,
    hiddenFreeDevices: Int,
    canPurchasePro: Boolean,
    isPurchaseInProgress: Boolean,
    isLoading: Boolean,
    onWake: (String) -> Unit,
    onRequestShutdown: (String, String?) -> Unit,
    onRefresh: () -> Unit,
    onUpgradeToPro: () -> Unit,
    onRestorePurchases: () -> Unit,
    modifier: Modifier = Modifier,
) {
    var showWakeDelayDialog by remember { mutableStateOf(false) }
    var shutdownRequestDeviceId by remember { mutableStateOf<String?>(null) }
    var shutdownRequestMessage by remember { mutableStateOf("") }

    if (showWakeDelayDialog) {
        AlertDialog(
            onDismissRequest = { showWakeDelayDialog = false },
            title = { Text(text = stringResource(R.string.wake_delay_dialog_title)) },
            text = { Text(text = stringResource(R.string.wake_delay_dialog_message)) },
            confirmButton = {
                TextButton(onClick = { showWakeDelayDialog = false }) {
                    Text(text = stringResource(R.string.action_ok))
                }
            },
        )
    }

    if (!shutdownRequestDeviceId.isNullOrBlank()) {
        AlertDialog(
            onDismissRequest = {
                shutdownRequestDeviceId = null
                shutdownRequestMessage = ""
            },
            title = { Text(text = stringResource(R.string.dialog_title_request_shutdown)) },
            text = {
                Column(verticalArrangement = Arrangement.spacedBy(10.dp)) {
                    Text(text = stringResource(R.string.dialog_message_request_shutdown))
                    OutlinedTextField(
                        value = shutdownRequestMessage,
                        onValueChange = { shutdownRequestMessage = it },
                        label = { Text(stringResource(R.string.label_shutdown_note)) },
                        singleLine = false,
                        maxLines = 3,
                        modifier = Modifier.fillMaxWidth(),
                    )
                }
            },
            confirmButton = {
                TextButton(
                    onClick = {
                        val target = shutdownRequestDeviceId
                        if (!target.isNullOrBlank()) {
                            onRequestShutdown(target, shutdownRequestMessage.trim().ifBlank { null })
                        }
                        shutdownRequestDeviceId = null
                        shutdownRequestMessage = ""
                    },
                ) {
                    Text(text = stringResource(R.string.button_notify_admin))
                }
            },
            dismissButton = {
                TextButton(
                    onClick = {
                        shutdownRequestDeviceId = null
                        shutdownRequestMessage = ""
                    },
                ) {
                    Text(text = stringResource(R.string.action_cancel))
                }
            },
        )
    }

    if (isLoading && devices.isEmpty()) {
        Box(modifier = modifier, contentAlignment = Alignment.Center) {
            CircularProgressIndicator()
        }
        return
    }

    PullToRefreshBox(
        isRefreshing = isLoading,
        onRefresh = onRefresh,
        modifier = modifier,
    ) {
        if (devices.isEmpty()) {
            Box(modifier = Modifier.fillMaxSize(), contentAlignment = Alignment.Center) {
                Column(
                    horizontalAlignment = Alignment.CenterHorizontally,
                    verticalArrangement = Arrangement.spacedBy(8.dp),
                ) {
                    Icon(
                        imageVector = Icons.Default.Computer,
                        contentDescription = null,
                        tint = MaterialTheme.colorScheme.onSurfaceVariant,
                        modifier = Modifier.size(64.dp),
                    )
                    Text(
                        text = stringResource(R.string.text_no_assigned_devices),
                        style = MaterialTheme.typography.bodyLarge,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                    Text(
                        text = stringResource(R.string.text_no_devices_hint),
                        style = MaterialTheme.typography.bodyMedium,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                }
            }
        } else {
            LazyColumn(
                modifier = Modifier.fillMaxSize(),
                contentPadding = PaddingValues(horizontal = 16.dp, vertical = 12.dp),
                verticalArrangement = Arrangement.spacedBy(10.dp),
            ) {
                if (!hasProAccess) {
                    item {
                        FreeTierCard(
                            freeDeviceLimit = freeDeviceLimit,
                            hiddenFreeDevices = hiddenFreeDevices,
                            canPurchasePro = canPurchasePro,
                            isPurchaseInProgress = isPurchaseInProgress,
                            onUpgradeToPro = onUpgradeToPro,
                            onRestorePurchases = onRestorePurchases,
                        )
                    }
                }
                items(devices, key = { it.id }) { device ->
                    DeviceCard(
                        device = device,
                        onWake = { deviceId ->
                            onWake(deviceId)
                            showWakeDelayDialog = true
                        },
                        onRequestShutdown = { deviceId ->
                            shutdownRequestDeviceId = deviceId
                            shutdownRequestMessage = ""
                        },
                    )
                }
            }
        }
    }
}

@Composable
private fun FreeTierCard(
    freeDeviceLimit: Int,
    hiddenFreeDevices: Int,
    canPurchasePro: Boolean,
    isPurchaseInProgress: Boolean,
    onUpgradeToPro: () -> Unit,
    onRestorePurchases: () -> Unit,
) {
    ElevatedCard(
        modifier = Modifier.fillMaxWidth(),
        colors = CardDefaults.elevatedCardColors(
            containerColor = MaterialTheme.colorScheme.surfaceVariant,
        ),
    ) {
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .padding(14.dp),
            verticalArrangement = Arrangement.spacedBy(8.dp),
        ) {
            Text(
                text = stringResource(R.string.label_free_tier_title),
                style = MaterialTheme.typography.titleMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            Text(
                text = stringResource(R.string.text_free_tier_limit_summary, freeDeviceLimit),
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            if (hiddenFreeDevices > 0) {
                Text(
                    text = stringResource(R.string.text_free_tier_hidden_devices, hiddenFreeDevices),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }

            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.End,
                verticalAlignment = Alignment.CenterVertically,
            ) {
                TextButton(
                    onClick = onRestorePurchases,
                    enabled = !isPurchaseInProgress,
                ) {
                    Text(stringResource(R.string.button_restore_purchases))
                }
                Button(
                    onClick = onUpgradeToPro,
                    enabled = canPurchasePro && !isPurchaseInProgress,
                ) {
                    if (isPurchaseInProgress) {
                        CircularProgressIndicator(modifier = Modifier.size(16.dp))
                    } else {
                        Text(stringResource(R.string.button_unlock_pro))
                    }
                }
            }
        }
    }
}

@Composable
private fun StatusBadge(stateKey: String) {
    val colorScheme = MaterialTheme.colorScheme
    val (dotColor, labelRes, labelColor) = when (stateKey) {
        "on" -> Triple(Color(0xFF22C55E), R.string.state_on, Color(0xFF22C55E))
        "off" -> Triple(colorScheme.error, R.string.state_off, colorScheme.error)
        else -> Triple(colorScheme.onSurfaceVariant, R.string.state_unknown, colorScheme.onSurfaceVariant)
    }

    Row(
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.spacedBy(4.dp),
    ) {
        Surface(
            shape = CircleShape,
            color = dotColor,
            modifier = Modifier.size(8.dp),
        ) {}
        Text(
            text = stringResource(labelRes),
            style = MaterialTheme.typography.labelMedium,
            color = labelColor,
        )
    }
}

@Composable
@OptIn(ExperimentalLayoutApi::class)
private fun DeviceCard(
    device: MyDeviceDto,
    onWake: (String) -> Unit,
    onRequestShutdown: (String) -> Unit,
) {
    val colorScheme = MaterialTheme.colorScheme
    val stateKey = device.last_power_state.lowercase()
    val isPoweredOn = stateKey == "on"
    val poweredOnColor = Color(0xFF22C55E)

    val (stateContainerColor, stateIconColor) = when (stateKey) {
        "on" -> poweredOnColor.copy(alpha = 0.14f) to poweredOnColor
        "off" -> colorScheme.errorContainer to colorScheme.error
        else -> colorScheme.surfaceVariant to colorScheme.onSurfaceVariant
    }

    val lastCheckedAt = device.last_power_checked_at ?: stringResource(R.string.last_checked_never)
    val staleSuffix = if (device.is_stale) stringResource(R.string.last_checked_stale_suffix) else ""

    ElevatedCard(
        modifier = Modifier.fillMaxWidth(),
        colors = CardDefaults.elevatedCardColors(
            containerColor = colorScheme.surface,
        ),
    ) {
        Row(
            modifier = Modifier.padding(14.dp),
            horizontalArrangement = Arrangement.spacedBy(12.dp),
        ) {
            Surface(
                shape = MaterialTheme.shapes.medium,
                color = stateContainerColor,
                modifier = Modifier
                    .size(48.dp)
                    .then(
                        if (isPoweredOn) {
                            Modifier
                                .shadow(
                                    elevation = 10.dp,
                                    shape = MaterialTheme.shapes.medium,
                                    ambientColor = poweredOnColor.copy(alpha = 0.45f),
                                    spotColor = poweredOnColor.copy(alpha = 0.55f),
                                )
                        } else {
                            Modifier
                        }
                    ),
            ) {
                Box(contentAlignment = Alignment.Center) {
                    Icon(
                        imageVector = Icons.Default.Computer,
                        contentDescription = null,
                        tint = stateIconColor,
                        modifier = Modifier.size(24.dp),
                    )
                }
            }

            Column(
                modifier = Modifier.fillMaxWidth(),
                verticalArrangement = Arrangement.spacedBy(4.dp),
            ) {
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    verticalAlignment = Alignment.CenterVertically,
                ) {
                    Text(
                        text = device.display_name ?: device.name,
                        style = MaterialTheme.typography.titleMedium,
                        modifier = Modifier.weight(1f),
                        maxLines = 1,
                        overflow = TextOverflow.Ellipsis,
                    )
                    Spacer(modifier = Modifier.width(8.dp))
                    StatusBadge(stateKey = stateKey)
                }

                device.group_name?.takeIf { it.isNotBlank() }?.let { groupName ->
                    Text(
                        text = groupName,
                        style = MaterialTheme.typography.bodySmall,
                        color = colorScheme.onSurfaceVariant,
                    )
                }

                Text(
                    text = device.mac,
                    style = MonoTextStyle,
                    color = colorScheme.onSurfaceVariant,
                )

                Row(
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.spacedBy(4.dp),
                ) {
                    Text(
                        text = stringResource(R.string.label_last_checked, lastCheckedAt, staleSuffix),
                        style = MaterialTheme.typography.bodySmall,
                        color = colorScheme.onSurfaceVariant,
                    )
                    if (device.is_stale) {
                        Icon(
                            imageVector = Icons.Default.Warning,
                            contentDescription = stringResource(R.string.content_desc_stale_status),
                            tint = colorScheme.tertiary,
                            modifier = Modifier.size(12.dp),
                        )
                    }
                }

                BoxWithConstraints(modifier = Modifier.fillMaxWidth()) {
                    val useStackedActions = maxWidth < 330.dp

                    FlowRow(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.spacedBy(8.dp),
                        verticalArrangement = Arrangement.spacedBy(6.dp),
                        maxItemsInEachRow = if (useStackedActions) 1 else 2,
                    ) {
                        TextButton(
                            onClick = { onRequestShutdown(device.id) },
                            modifier = if (useStackedActions) Modifier.fillMaxWidth() else Modifier,
                        ) {
                            Text(
                                text = stringResource(R.string.button_request_shutdown),
                                maxLines = if (useStackedActions) 1 else 2,
                                softWrap = true,
                                overflow = TextOverflow.Clip,
                            )
                        }
                        FilledTonalButton(
                            onClick = { onWake(device.id) },
                            modifier = if (useStackedActions) Modifier.fillMaxWidth() else Modifier.widthIn(min = 96.dp),
                            colors = ButtonDefaults.filledTonalButtonColors(
                                containerColor = colorScheme.tertiaryContainer,
                                contentColor = colorScheme.onTertiaryContainer,
                            ),
                        ) {
                            Icon(
                                imageVector = Icons.Default.PowerSettingsNew,
                                contentDescription = null,
                                modifier = Modifier.size(16.dp),
                            )
                            Spacer(modifier = Modifier.width(4.dp))
                            Text(text = stringResource(R.string.button_wake))
                        }
                    }
                }
            }
        }
    }
}

private tailrec fun Context.findActivity(): Activity? = when (this) {
    is Activity -> this
    is ContextWrapper -> baseContext.findActivity()
    else -> null
}
