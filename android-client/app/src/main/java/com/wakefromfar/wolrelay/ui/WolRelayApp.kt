package com.wakefromfar.wolrelay.ui

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material3.AssistChip
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.SnackbarHost
import androidx.compose.material3.SnackbarHostState
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.remember
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.unit.dp
import com.wakefromfar.wolrelay.R
import com.wakefromfar.wolrelay.data.MyDeviceDto

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

    MaterialTheme {
        Scaffold(
            topBar = {
                TopAppBar(
                    title = {
                        Text(
                            if (state.isAuthenticated) {
                                stringResource(R.string.title_my_devices)
                            } else {
                                stringResource(R.string.title_app)
                            },
                        )
                    },
                    actions = {
                        if (state.isAuthenticated) {
                            TextButton(onClick = vm::refreshDevices) { Text(stringResource(R.string.action_refresh)) }
                            TextButton(onClick = vm::logout) { Text(stringResource(R.string.action_logout)) }
                        }
                    },
                )
            },
            snackbarHost = { SnackbarHost(snackbarHost) },
        ) { innerPadding ->
            if (state.isAuthenticated) {
                DeviceListScreen(
                    devices = state.devices,
                    isLoading = state.isLoading,
                    onWake = vm::wakeDevice,
                    modifier = Modifier
                        .fillMaxSize()
                        .padding(innerPadding)
                        .padding(16.dp),
                )
            } else if (state.hasInviteToken) {
                InviteClaimScreen(
                    state = state,
                    onBackendUrlChange = vm::updateBackendUrl,
                    onClaimPasswordChange = vm::updateClaimPassword,
                    onClaim = vm::claimInvite,
                    onUseLogin = vm::clearInviteToken,
                    modifier = Modifier
                        .fillMaxSize()
                        .padding(innerPadding)
                        .padding(16.dp),
                )
            } else {
                LoginScreen(
                    state = state,
                    onBackendUrlChange = vm::updateBackendUrl,
                    onUsernameChange = vm::updateUsername,
                    onPasswordChange = vm::updatePassword,
                    onLogin = vm::login,
                    modifier = Modifier
                        .fillMaxSize()
                        .padding(innerPadding)
                        .padding(16.dp),
                )
            }
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
    Column(modifier = modifier, verticalArrangement = Arrangement.spacedBy(12.dp)) {
        Text(stringResource(R.string.invite_detected), style = MaterialTheme.typography.titleLarge)
        Text(stringResource(R.string.invite_token_preview, tokenPreview))
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
        Button(onClick = onClaim, enabled = !state.isLoading, modifier = Modifier.fillMaxWidth()) {
            Text(stringResource(R.string.button_activate_account))
        }
        TextButton(onClick = onUseLogin, enabled = !state.isLoading) {
            Text(stringResource(R.string.action_use_regular_login))
        }
        if (state.isLoading) {
            CircularProgressIndicator()
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
    Column(modifier = modifier, verticalArrangement = Arrangement.spacedBy(12.dp)) {
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
        Button(onClick = onLogin, enabled = !state.isLoading, modifier = Modifier.fillMaxWidth()) {
            Text(stringResource(R.string.button_login))
        }
        if (state.isLoading) {
            CircularProgressIndicator()
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
    Column(modifier = modifier, verticalArrangement = Arrangement.spacedBy(12.dp)) {
        if (isLoading) {
            CircularProgressIndicator()
        }
        if (devices.isEmpty() && !isLoading) {
            Text(stringResource(R.string.text_no_assigned_devices))
        }
        LazyColumn(verticalArrangement = Arrangement.spacedBy(8.dp)) {
            items(devices, key = { it.id }) { device ->
                DeviceCard(device = device, onWake = onWake)
            }
        }
    }
}

@Composable
private fun DeviceCard(device: MyDeviceDto, onWake: (String) -> Unit) {
    val stateColor = when (device.last_power_state) {
        "on" -> Color(0xFF2E7D32)
        "off" -> Color(0xFFC62828)
        else -> Color(0xFF6B7280)
    }
    val stateLabel = when (device.last_power_state.lowercase()) {
        "on" -> stringResource(R.string.state_on)
        "off" -> stringResource(R.string.state_off)
        else -> stringResource(R.string.state_unknown)
    }
    val lastCheckedAt = device.last_power_checked_at ?: stringResource(R.string.last_checked_never)
    val staleSuffix = if (device.is_stale) stringResource(R.string.last_checked_stale_suffix) else ""
    Card(modifier = Modifier.fillMaxWidth()) {
        Column(modifier = Modifier.padding(12.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
            Text(text = device.display_name ?: device.name, style = MaterialTheme.typography.titleMedium)
            Text(text = stringResource(R.string.label_mac, device.mac), style = MaterialTheme.typography.bodySmall)
            AssistChip(
                onClick = {},
                label = { Text(stringResource(R.string.label_state, stateLabel)) },
                colors = androidx.compose.material3.AssistChipDefaults.assistChipColors(
                    labelColor = stateColor,
                ),
            )
            Text(
                text = stringResource(R.string.label_last_checked, lastCheckedAt, staleSuffix),
                style = MaterialTheme.typography.bodySmall,
            )
            Row(horizontalArrangement = Arrangement.End, modifier = Modifier.fillMaxWidth()) {
                Button(onClick = { onWake(device.id) }) {
                    Text(stringResource(R.string.button_wake))
                }
            }
        }
    }
}
