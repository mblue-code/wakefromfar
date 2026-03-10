package com.wakefromfar.wolrelay.data

import kotlinx.serialization.Serializable
import kotlinx.serialization.json.JsonObject

@Serializable
data class LoginRequest(
    val username: String,
    val password: String,
    val installation_id: String? = null,
    val proof_ticket: String? = null,
)

@Serializable
data class LoginResponse(
    val token: String,
    val expires_in: Int,
)

@Serializable
data class AppProofChallengeRequest(
    val platform: String,
    val purpose: String,
    val installation_id: String,
    val username: String? = null,
    val app_version: String? = null,
    val os_version: String? = null,
)

@Serializable
data class AppProofChallengeBinding(
    val canonical_fields: List<String>,
)

@Serializable
data class AppProofChallengeResponse(
    val challenge_id: String,
    val challenge: String,
    val purpose: String,
    val expires_in: Int,
    val binding: AppProofChallengeBinding,
)

@Serializable
data class AndroidAppProofVerifyRequest(
    val challenge_id: String,
    val installation_id: String,
    val request_hash: String,
    val integrity_token: String,
    val app_version: String? = null,
    val os_version: String? = null,
)

@Serializable
data class AppProofVerifyResponse(
    val proof_ticket: String,
    val proof_expires_in: Int,
    val installation_status: String,
)

@Serializable
data class DevicePermissionsDto(
    val can_view_status: Boolean = true,
    val can_wake: Boolean = true,
    val can_request_shutdown: Boolean = true,
    val can_manage_schedule: Boolean = false,
)

@Serializable
data class ScheduledWakeSummaryDto(
    val total_count: Int = 0,
    val enabled_count: Int = 0,
    val next_run_at: String? = null,
)

@Serializable
data class MyDeviceDto(
    val id: String,
    val name: String,
    val display_name: String? = null,
    val group_name: String? = null,
    val mac: String,
    val is_favorite: Boolean = false,
    val sort_order: Int = 0,
    val permissions: DevicePermissionsDto = DevicePermissionsDto(),
    val last_power_state: String = "unknown",
    val last_power_checked_at: String? = null,
    val is_stale: Boolean = true,
    val scheduled_wake_summary: ScheduledWakeSummaryDto? = null,
) {
    val displayTitle: String
        get() = display_name?.takeIf { it.isNotBlank() } ?: name

    val canViewStatus: Boolean
        get() = permissions.can_view_status

    val canWake: Boolean
        get() = permissions.can_wake

    val canRequestShutdown: Boolean
        get() = permissions.can_request_shutdown

    val canManageSchedule: Boolean
        get() = permissions.can_manage_schedule
}

@Serializable
data class MyDevicePreferencesUpdateRequest(
    val is_favorite: Boolean? = null,
    val sort_order: Int? = null,
)

@Serializable
data class ActivityEventDto(
    val id: Int,
    val event_type: String,
    val actor_username: String? = null,
    val target_type: String,
    val target_id: String? = null,
    val server_id: String? = null,
    val summary: String,
    val metadata: JsonObject? = null,
    val created_at: String,
)

@Serializable
data class ShutdownPokeCreateRequest(
    val message: String? = null,
)

@Serializable
data class ShutdownPokeDto(
    val id: String,
    val server_id: String,
    val device_name: String? = null,
    val device_display_name: String? = null,
    val requester_user_id: Int,
    val requester_username: String,
    val message: String? = null,
    val status: String,
    val created_at: String,
    val seen_at: String? = null,
    val resolved_at: String? = null,
    val resolved_by_user_id: Int? = null,
    val resolved_by_username: String? = null,
)

@Serializable
data class MeWakeResponse(
    val device_id: String,
    val result: String,
    val message: String,
    val precheck_state: String,
    val sent_to: String? = null,
    val timestamp: String,
    val error_detail: String? = null,
)

@Serializable
data class OnboardingClaimRequest(
    val token: String,
    val password: String,
)

@Serializable
data class OnboardingClaimResponse(
    val token: String,
    val expires_in: Int,
    val username: String,
    val role: String,
    val backend_url_hint: String? = null,
)
