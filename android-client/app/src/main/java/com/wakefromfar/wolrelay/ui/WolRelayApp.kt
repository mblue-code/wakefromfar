package com.wakefromfar.wolrelay.ui

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ColumnScope
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.material.icons.Icons
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
import androidx.compose.material3.ElevatedCard
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.FilledTonalButton
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
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.TopAppBarDefaults
import androidx.compose.material3.pulltorefresh.PullToRefreshBox
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.text.input.VisualTransformation
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.wakefromfar.wolrelay.R
import com.wakefromfar.wolrelay.data.MyDeviceDto
import com.wakefromfar.wolrelay.data.ThemeMode
import com.wakefromfar.wolrelay.ui.theme.MonoTextStyle

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun WolRelayApp(vm: MainViewModel) {
    val state = vm.state
    val snackbarHost = remember { SnackbarHostState() }

    LaunchedEffect(state.error, state.info) {
        val msg = state.error ?: state.info
        if (!msg.isNullOrBlank()) {
            snackbarHost.showSnackbar(msg)
            vm.dismissMessages()
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
                title = {
                    Text(
                        text = if (state.isAuthenticated) {
                            stringResource(R.string.title_my_devices)
                        } else {
                            stringResource(R.string.title_app)
                        },
                        style = MaterialTheme.typography.titleLarge.copy(fontWeight = FontWeight.SemiBold),
                    )
                },
                actions = {
                    SettingsMenu(
                        currentThemeMode = state.themeMode,
                        onThemeModeSelected = vm::updateThemeMode,
                    )
                    if (state.isAuthenticated) {
                        IconButton(onClick = vm::refreshDevices) {
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
                },
            )
        },
        snackbarHost = { SnackbarHost(hostState = snackbarHost) },
    ) { innerPadding ->
        val contentModifier = Modifier
            .fillMaxSize()
            .padding(innerPadding)

        when {
            state.isAuthenticated -> DeviceListScreen(
                devices = state.devices,
                isLoading = state.isLoading,
                onWake = vm::wakeDevice,
                onRefresh = vm::refreshDevices,
                modifier = contentModifier,
            )

            state.hasInviteToken -> InviteClaimScreen(
                state = state,
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
                onLogin = vm::login,
                modifier = contentModifier,
            )
        }
    }
}

@Composable
private fun SettingsMenu(
    currentThemeMode: ThemeMode,
    onThemeModeSelected: (ThemeMode) -> Unit,
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
private fun InviteClaimScreen(
    state: AppUiState,
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

@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun DeviceListScreen(
    devices: List<MyDeviceDto>,
    isLoading: Boolean,
    onWake: (String) -> Unit,
    onRefresh: () -> Unit,
    modifier: Modifier = Modifier,
) {
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
                items(devices, key = { it.id }) { device ->
                    DeviceCard(device = device, onWake = onWake)
                }
            }
        }
    }
}

@Composable
private fun StatusBadge(stateKey: String) {
    val colorScheme = MaterialTheme.colorScheme
    val (dotColor, labelRes) = when (stateKey) {
        "on" -> Color(0xFF22C55E) to R.string.state_on
        "off" -> colorScheme.error to R.string.state_off
        else -> colorScheme.onSurfaceVariant to R.string.state_unknown
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
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
    }
}

@Composable
private fun DeviceCard(device: MyDeviceDto, onWake: (String) -> Unit) {
    val colorScheme = MaterialTheme.colorScheme
    val stateKey = device.last_power_state.lowercase()

    val (stateContainerColor, stateIconColor) = when (stateKey) {
        "on" -> colorScheme.primaryContainer to colorScheme.primary
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
                modifier = Modifier.size(48.dp),
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
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically,
                ) {
                    Text(
                        text = device.display_name ?: device.name,
                        style = MaterialTheme.typography.titleMedium,
                    )
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

                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.End,
                ) {
                    FilledTonalButton(
                        onClick = { onWake(device.id) },
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
                        Text(stringResource(R.string.button_wake))
                    }
                }
            }
        }
    }
}
