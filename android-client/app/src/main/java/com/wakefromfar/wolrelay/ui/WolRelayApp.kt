package com.wakefromfar.wolrelay.ui

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ColumnScope
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material3.AssistChip
import androidx.compose.material3.AssistChipDefaults
import androidx.compose.material3.Button
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.DropdownMenu
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.ElevatedCard
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.RadioButton
import androidx.compose.material3.Scaffold
import androidx.compose.material3.SnackbarHost
import androidx.compose.material3.SnackbarHostState
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.TopAppBarDefaults
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.remember
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.unit.dp
import com.wakefromfar.wolrelay.R
import com.wakefromfar.wolrelay.data.MyDeviceDto
import com.wakefromfar.wolrelay.data.ThemeMode

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
                        TextButton(onClick = vm::refreshDevices) { Text(stringResource(R.string.action_refresh)) }
                        TextButton(onClick = vm::logout) { Text(stringResource(R.string.action_logout)) }
                    }
                },
            )
        },
        snackbarHost = { SnackbarHost(hostState = snackbarHost) },
    ) { innerPadding ->
        val contentModifier = Modifier
            .fillMaxSize()
            .padding(innerPadding)
            .padding(horizontal = 16.dp, vertical = 12.dp)

        when {
            state.isAuthenticated -> DeviceListScreen(
                devices = state.devices,
                isLoading = state.isLoading,
                onWake = vm::wakeDevice,
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
        TextButton(onClick = { expanded = true }) {
            Text(stringResource(R.string.action_settings))
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
    title: String,
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
            Text(
                text = title,
                style = MaterialTheme.typography.titleLarge,
            )
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

    Column(modifier = modifier, verticalArrangement = Arrangement.spacedBy(16.dp)) {
        AuthCard(
            title = stringResource(R.string.invite_detected),
            modifier = Modifier.fillMaxWidth(),
        ) {
            Text(
                text = stringResource(R.string.invite_token_preview, tokenPreview),
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            OutlinedTextField(
                value = state.backendUrl,
                onValueChange = onBackendUrlChange,
                label = { Text(stringResource(R.string.label_backend_url)) },
                singleLine = true,
                modifier = Modifier.fillMaxWidth(),
            )
            OutlinedTextField(
                value = state.claimPassword,
                onValueChange = onClaimPasswordChange,
                label = { Text(stringResource(R.string.label_new_password)) },
                visualTransformation = PasswordVisualTransformation(),
                singleLine = true,
                modifier = Modifier.fillMaxWidth(),
            )
            Button(
                onClick = onClaim,
                enabled = !state.isLoading,
                modifier = Modifier.fillMaxWidth(),
            ) {
                Text(stringResource(R.string.button_activate_account))
            }
            if (state.isLoading) {
                CircularProgressIndicator(modifier = Modifier.size(24.dp))
            }
        }

        TextButton(onClick = onUseLogin, enabled = !state.isLoading) {
            Text(stringResource(R.string.action_use_regular_login))
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
    Column(modifier = modifier, verticalArrangement = Arrangement.spacedBy(16.dp)) {
        AuthCard(
            title = stringResource(R.string.title_app),
            modifier = Modifier.fillMaxWidth(),
        ) {
            OutlinedTextField(
                value = state.backendUrl,
                onValueChange = onBackendUrlChange,
                label = { Text(stringResource(R.string.label_backend_url)) },
                singleLine = true,
                modifier = Modifier.fillMaxWidth(),
            )
            OutlinedTextField(
                value = state.username,
                onValueChange = onUsernameChange,
                label = { Text(stringResource(R.string.label_username)) },
                singleLine = true,
                modifier = Modifier.fillMaxWidth(),
            )
            OutlinedTextField(
                value = state.password,
                onValueChange = onPasswordChange,
                label = { Text(stringResource(R.string.label_password)) },
                visualTransformation = PasswordVisualTransformation(),
                singleLine = true,
                modifier = Modifier.fillMaxWidth(),
            )
            Button(
                onClick = onLogin,
                enabled = !state.isLoading,
                modifier = Modifier.fillMaxWidth(),
            ) {
                Text(stringResource(R.string.button_login))
            }
            if (state.isLoading) {
                CircularProgressIndicator(modifier = Modifier.size(24.dp))
            }
        }
    }
}

@Composable
private fun DeviceListScreen(
    devices: List<MyDeviceDto>,
    isLoading: Boolean,
    onWake: (String) -> Unit,
    modifier: Modifier = Modifier,
) {
    if (isLoading && devices.isEmpty()) {
        Box(modifier = modifier, contentAlignment = Alignment.Center) {
            CircularProgressIndicator()
        }
        return
    }

    Column(modifier = modifier, verticalArrangement = Arrangement.spacedBy(12.dp)) {
        if (isLoading) {
            LinearProgressIndicator(modifier = Modifier.fillMaxWidth())
        }

        if (devices.isEmpty()) {
            ElevatedCard(
                modifier = Modifier.fillMaxWidth(),
                colors = CardDefaults.elevatedCardColors(
                    containerColor = MaterialTheme.colorScheme.surface,
                ),
            ) {
                Text(
                    text = stringResource(R.string.text_no_assigned_devices),
                    style = MaterialTheme.typography.bodyLarge,
                    modifier = Modifier.padding(16.dp),
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
        }

        LazyColumn(
            modifier = Modifier.fillMaxSize(),
            contentPadding = PaddingValues(bottom = 20.dp),
            verticalArrangement = Arrangement.spacedBy(10.dp),
        ) {
            items(devices, key = { it.id }) { device ->
                DeviceCard(device = device, onWake = onWake)
            }
        }
    }
}

@Composable
private fun DeviceCard(device: MyDeviceDto, onWake: (String) -> Unit) {
    val colorScheme = MaterialTheme.colorScheme
    val stateKey = device.last_power_state.lowercase()
    val stateLabel = when (stateKey) {
        "on" -> stringResource(R.string.state_on)
        "off" -> stringResource(R.string.state_off)
        else -> stringResource(R.string.state_unknown)
    }
    val stateChipColors = when (stateKey) {
        "on" -> AssistChipDefaults.assistChipColors(
            containerColor = colorScheme.primaryContainer,
            labelColor = colorScheme.onPrimaryContainer,
        )

        "off" -> AssistChipDefaults.assistChipColors(
            containerColor = colorScheme.errorContainer,
            labelColor = colorScheme.onErrorContainer,
        )

        else -> AssistChipDefaults.assistChipColors(
            containerColor = colorScheme.surfaceVariant,
            labelColor = colorScheme.onSurfaceVariant,
        )
    }
    val lastCheckedAt = device.last_power_checked_at ?: stringResource(R.string.last_checked_never)
    val staleSuffix = if (device.is_stale) stringResource(R.string.last_checked_stale_suffix) else ""

    ElevatedCard(
        modifier = Modifier.fillMaxWidth(),
        colors = CardDefaults.elevatedCardColors(
            containerColor = MaterialTheme.colorScheme.surface,
        ),
    ) {
        Column(
            modifier = Modifier.padding(14.dp),
            verticalArrangement = Arrangement.spacedBy(10.dp),
        ) {
            Text(
                text = device.display_name ?: device.name,
                style = MaterialTheme.typography.titleMedium,
            )
            device.group_name?.takeIf { it.isNotBlank() }?.let { groupName ->
                Text(
                    text = groupName,
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
            Text(
                text = stringResource(R.string.label_mac, device.mac),
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            AssistChip(
                onClick = {},
                label = { Text(stringResource(R.string.label_state, stateLabel)) },
                colors = stateChipColors,
            )
            Text(
                text = stringResource(R.string.label_last_checked, lastCheckedAt, staleSuffix),
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            Row(
                horizontalArrangement = Arrangement.End,
                modifier = Modifier.fillMaxWidth(),
            ) {
                Button(onClick = { onWake(device.id) }) {
                    Text(stringResource(R.string.button_wake))
                }
            }
        }
    }
}
