package com.wakefromfar.wolrelay.ui

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
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
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.unit.dp
import com.wakefromfar.wolrelay.data.HostDto

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
                        Text(if (state.isAuthenticated) "WoL Hosts" else "WoL Relay Login")
                    },
                    actions = {
                        if (state.isAuthenticated) {
                            TextButton(onClick = vm::refreshHosts) { Text("Refresh") }
                            TextButton(onClick = vm::logout) { Text("Logout") }
                        }
                    },
                )
            },
            snackbarHost = { SnackbarHost(snackbarHost) },
        ) { innerPadding ->
            if (state.isAuthenticated) {
                HostListScreen(
                    hosts = state.hosts,
                    isLoading = state.isLoading,
                    onWake = vm::wakeHost,
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
            label = { Text("Backend URL") },
            singleLine = true,
            modifier = Modifier.fillMaxWidth(),
        )
        OutlinedTextField(
            value = state.username,
            onValueChange = onUsernameChange,
            label = { Text("Username") },
            singleLine = true,
            modifier = Modifier.fillMaxWidth(),
        )
        OutlinedTextField(
            value = state.password,
            onValueChange = onPasswordChange,
            label = { Text("Passwort") },
            visualTransformation = PasswordVisualTransformation(),
            singleLine = true,
            modifier = Modifier.fillMaxWidth(),
        )
        Button(onClick = onLogin, enabled = !state.isLoading, modifier = Modifier.fillMaxWidth()) {
            Text("Login")
        }
        if (state.isLoading) {
            CircularProgressIndicator()
        }
    }
}

@Composable
private fun HostListScreen(
    hosts: List<HostDto>,
    isLoading: Boolean,
    onWake: (String) -> Unit,
    modifier: Modifier = Modifier,
) {
    Column(modifier = modifier, verticalArrangement = Arrangement.spacedBy(12.dp)) {
        if (isLoading) {
            CircularProgressIndicator()
        }
        if (hosts.isEmpty() && !isLoading) {
            Text("Keine Hosts vorhanden. Bitte per Admin-API/CLI anlegen.")
        }
        LazyColumn(verticalArrangement = Arrangement.spacedBy(8.dp)) {
            items(hosts, key = { it.id }) { host ->
                HostCard(host = host, onWake = onWake)
            }
        }
    }
}

@Composable
private fun HostCard(host: HostDto, onWake: (String) -> Unit) {
    Card(modifier = Modifier.fillMaxWidth()) {
        Column(modifier = Modifier.padding(12.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
            Text(text = host.name, style = MaterialTheme.typography.titleMedium)
            Text(text = "MAC: ${host.mac}", style = MaterialTheme.typography.bodySmall)
            val route = host.broadcast ?: host.subnet_cidr ?: "255.255.255.255"
            Text(text = "Target: $route:${host.udp_port}", style = MaterialTheme.typography.bodySmall)
            Row(horizontalArrangement = Arrangement.End, modifier = Modifier.fillMaxWidth()) {
                Button(onClick = { onWake(host.id) }) {
                    Text("Wake")
                }
            }
        }
    }
}
