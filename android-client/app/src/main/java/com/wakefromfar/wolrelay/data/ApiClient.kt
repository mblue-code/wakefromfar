package com.wakefromfar.wolrelay.data

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import okhttp3.HttpUrl.Companion.toHttpUrl
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody

class ApiClient(
    private val client: OkHttpClient = OkHttpClient.Builder().build(),
    private val json: Json = Json {
        ignoreUnknownKeys = true
        explicitNulls = false
    },
) {
    suspend fun login(
        baseUrl: String,
        username: String,
        password: String,
        installationId: String? = null,
        proofTicket: String? = null,
    ): LoginResponse = withContext(Dispatchers.IO) {
        val requestPayload = json.encodeToString(
            LoginRequest(
                username = username,
                password = password,
                installation_id = installationId,
                proof_ticket = proofTicket,
            ),
        )
        val request = Request.Builder()
            .url("${normalizeBaseUrl(baseUrl)}/auth/login")
            .post(requestPayload.toRequestBody(JSON_MEDIA_TYPE))
            .build()

        client.newCall(request).execute().use { response ->
            val responseBody = response.body?.string().orEmpty()
            if (!response.isSuccessful) {
                throw ApiException("Login failed (${response.code})", statusCode = response.code)
            }
            json.decodeFromString<LoginResponse>(responseBody)
        }
    }

    suspend fun requestAppProofChallenge(
        baseUrl: String,
        platform: String,
        purpose: String,
        installationId: String,
        username: String? = null,
        appVersion: String? = null,
        osVersion: String? = null,
    ): AppProofChallengeResponse = withContext(Dispatchers.IO) {
        val payload = json.encodeToString(
            AppProofChallengeRequest(
                platform = platform,
                purpose = purpose,
                installation_id = installationId,
                username = username,
                app_version = appVersion,
                os_version = osVersion,
            ),
        )
        val request = Request.Builder()
            .url("${normalizeBaseUrl(baseUrl)}/auth/app-proof/challenge")
            .post(payload.toRequestBody(JSON_MEDIA_TYPE))
            .build()

        client.newCall(request).execute().use { response ->
            val responseBody = response.body?.string().orEmpty()
            if (!response.isSuccessful) {
                throw ApiException(
                    errorFromResponse("App proof challenge failed", response.code, responseBody),
                    statusCode = response.code,
                )
            }
            json.decodeFromString<AppProofChallengeResponse>(responseBody)
        }
    }

    suspend fun verifyAndroidAppProof(
        baseUrl: String,
        challengeId: String,
        installationId: String,
        requestHash: String,
        integrityToken: String,
        appVersion: String? = null,
        osVersion: String? = null,
    ): AppProofVerifyResponse = withContext(Dispatchers.IO) {
        val payload = json.encodeToString(
            AndroidAppProofVerifyRequest(
                challenge_id = challengeId,
                installation_id = installationId,
                request_hash = requestHash,
                integrity_token = integrityToken,
                app_version = appVersion,
                os_version = osVersion,
            ),
        )
        val request = Request.Builder()
            .url("${normalizeBaseUrl(baseUrl)}/auth/app-proof/verify/android")
            .post(payload.toRequestBody(JSON_MEDIA_TYPE))
            .build()

        client.newCall(request).execute().use { response ->
            val responseBody = response.body?.string().orEmpty()
            if (!response.isSuccessful) {
                throw ApiException(
                    errorFromResponse("App proof verification failed", response.code, responseBody),
                    statusCode = response.code,
                )
            }
            json.decodeFromString<AppProofVerifyResponse>(responseBody)
        }
    }

    suspend fun claimOnboarding(baseUrl: String, token: String, password: String): OnboardingClaimResponse =
        withContext(Dispatchers.IO) {
            val payload = json.encodeToString(OnboardingClaimRequest(token = token, password = password))
            val request = Request.Builder()
                .url("${normalizeBaseUrl(baseUrl)}/onboarding/claim")
                .post(payload.toRequestBody(JSON_MEDIA_TYPE))
                .build()

            client.newCall(request).execute().use { response ->
                val responseBody = response.body?.string().orEmpty()
                if (!response.isSuccessful) {
                    throw ApiException(
                        errorFromResponse("Claim failed", response.code, responseBody),
                        statusCode = response.code,
                    )
                }
                json.decodeFromString<OnboardingClaimResponse>(responseBody)
            }
        }

    suspend fun listMyDevices(baseUrl: String, token: String, installationId: String? = null): List<MyDeviceDto> =
        withContext(Dispatchers.IO) {
        val request = authenticatedRequestBuilder(
            token = token,
            installationId = installationId,
        )
            .url("${normalizeBaseUrl(baseUrl)}/me/devices")
            .get()
            .build()

        client.newCall(request).execute().use { response ->
            val responseBody = response.body?.string().orEmpty()
            if (!response.isSuccessful) {
                throw ApiException(
                    errorFromResponse("Loading devices failed", response.code, responseBody),
                    statusCode = response.code,
                )
            }
            json.decodeFromString<List<MyDeviceDto>>(responseBody)
        }
    }

    suspend fun wakeDevice(
        baseUrl: String,
        token: String,
        hostId: String,
        installationId: String? = null,
    ): MeWakeResponse = withContext(Dispatchers.IO) {
        val request = authenticatedRequestBuilder(
            token = token,
            installationId = installationId,
        )
            .url("${normalizeBaseUrl(baseUrl)}/me/devices/$hostId/wake")
            .post("".toRequestBody(null))
            .build()

        client.newCall(request).execute().use { response ->
            val responseBody = response.body?.string().orEmpty()
            if (!response.isSuccessful) {
                throw ApiException(
                    errorFromResponse("Wake failed", response.code, responseBody),
                    statusCode = response.code,
                )
            }
            json.decodeFromString<MeWakeResponse>(responseBody)
        }
    }

    suspend fun updateMyDevicePreferences(
        baseUrl: String,
        token: String,
        hostId: String,
        isFavorite: Boolean? = null,
        sortOrder: Int? = null,
        installationId: String? = null,
    ): MyDeviceDto = withContext(Dispatchers.IO) {
        val payload = json.encodeToString(
            MyDevicePreferencesUpdateRequest(
                is_favorite = isFavorite,
                sort_order = sortOrder,
            ),
        )
        val request = authenticatedRequestBuilder(
            token = token,
            installationId = installationId,
        )
            .url("${normalizeBaseUrl(baseUrl)}/me/devices/$hostId/preferences")
            .patch(payload.toRequestBody(JSON_MEDIA_TYPE))
            .build()

        client.newCall(request).execute().use { response ->
            val responseBody = response.body?.string().orEmpty()
            if (!response.isSuccessful) {
                throw ApiException(
                    errorFromResponse("Updating device preferences failed", response.code, responseBody),
                    statusCode = response.code,
                )
            }
            json.decodeFromString<MyDeviceDto>(responseBody)
        }
    }

    suspend fun listAdminEvents(
        baseUrl: String,
        token: String,
        cursor: Int? = null,
        limit: Int = 50,
        typeFilter: String? = "wake,poke",
        installationId: String? = null,
    ): List<ActivityEventDto> = withContext(Dispatchers.IO) {
        val urlBuilder = "${normalizeBaseUrl(baseUrl)}/admin/mobile/events".toHttpUrl().newBuilder()
            .addQueryParameter("limit", limit.toString())
        if (cursor != null) {
            urlBuilder.addQueryParameter("cursor", cursor.toString())
        }
        if (!typeFilter.isNullOrBlank()) {
            urlBuilder.addQueryParameter("type", typeFilter)
        }
        val request = authenticatedRequestBuilder(
            token = token,
            installationId = installationId,
        )
            .url(urlBuilder.build())
            .get()
            .build()

        client.newCall(request).execute().use { response ->
            val responseBody = response.body?.string().orEmpty()
            if (!response.isSuccessful) {
                throw ApiException(
                    errorFromResponse("Loading admin events failed", response.code, responseBody),
                    statusCode = response.code,
                )
            }
            json.decodeFromString<List<ActivityEventDto>>(responseBody)
        }
    }

    suspend fun requestShutdownPoke(
        baseUrl: String,
        token: String,
        hostId: String,
        message: String? = null,
        installationId: String? = null,
    ): ShutdownPokeDto = withContext(Dispatchers.IO) {
        val payload = json.encodeToString(
            ShutdownPokeCreateRequest(
                message = message?.trim()?.ifBlank { null },
            ),
        )
        val request = authenticatedRequestBuilder(
            token = token,
            installationId = installationId,
        )
            .url("${normalizeBaseUrl(baseUrl)}/me/devices/$hostId/shutdown-poke")
            .post(payload.toRequestBody(JSON_MEDIA_TYPE))
            .build()

        client.newCall(request).execute().use { response ->
            val responseBody = response.body?.string().orEmpty()
            if (!response.isSuccessful) {
                throw ApiException(
                    errorFromResponse("Shutdown request failed", response.code, responseBody),
                    statusCode = response.code,
                )
            }
            json.decodeFromString<ShutdownPokeDto>(responseBody)
        }
    }

    suspend fun markShutdownPokeSeen(
        baseUrl: String,
        token: String,
        pokeId: String,
        installationId: String? = null,
    ): ShutdownPokeDto = withContext(Dispatchers.IO) {
        val request = authenticatedRequestBuilder(
            token = token,
            installationId = installationId,
        )
            .url("${normalizeBaseUrl(baseUrl)}/admin/shutdown-pokes/$pokeId/seen")
            .post("".toRequestBody(null))
            .build()

        client.newCall(request).execute().use { response ->
            val responseBody = response.body?.string().orEmpty()
            if (!response.isSuccessful) {
                throw ApiException(
                    errorFromResponse("Marking shutdown request seen failed", response.code, responseBody),
                    statusCode = response.code,
                )
            }
            json.decodeFromString<ShutdownPokeDto>(responseBody)
        }
    }

    suspend fun markShutdownPokeResolved(
        baseUrl: String,
        token: String,
        pokeId: String,
        installationId: String? = null,
    ): ShutdownPokeDto = withContext(Dispatchers.IO) {
        val request = authenticatedRequestBuilder(
            token = token,
            installationId = installationId,
        )
            .url("${normalizeBaseUrl(baseUrl)}/admin/shutdown-pokes/$pokeId/resolve")
            .post("".toRequestBody(null))
            .build()

        client.newCall(request).execute().use { response ->
            val responseBody = response.body?.string().orEmpty()
            if (!response.isSuccessful) {
                throw ApiException(
                    errorFromResponse("Resolving shutdown request failed", response.code, responseBody),
                    statusCode = response.code,
                )
            }
            json.decodeFromString<ShutdownPokeDto>(responseBody)
        }
    }

    private fun normalizeBaseUrl(baseUrl: String): String = baseUrl.trim().trimEnd('/')

    private fun authenticatedRequestBuilder(
        token: String,
        installationId: String? = null,
    ): Request.Builder {
        val builder = Request.Builder()
            .addHeader("Authorization", "Bearer $token")
        if (!installationId.isNullOrBlank()) {
            builder.addHeader("X-WFF-Installation-ID", installationId)
        }
        return builder
    }

    private fun errorFromResponse(prefix: String, code: Int, responseBody: String): String {
        val compact = responseBody.replace("\n", " ").trim().take(200)
        return if (compact.isBlank()) "$prefix ($code)" else "$prefix ($code): $compact"
    }

    private companion object {
        val JSON_MEDIA_TYPE = "application/json; charset=utf-8".toMediaType()
    }
}

class ApiException(
    message: String,
    val statusCode: Int? = null,
) : RuntimeException(message)
