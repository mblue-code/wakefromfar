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

class ApiClient {
    private val json = Json {
        ignoreUnknownKeys = true
        explicitNulls = false
    }

    private val client = OkHttpClient.Builder().build()

    suspend fun login(baseUrl: String, username: String, password: String): LoginResponse = withContext(Dispatchers.IO) {
        val payload = json.encodeToString(LoginRequest(username = username, password = password))
        val request = Request.Builder()
            .url("${normalizeBaseUrl(baseUrl)}/auth/login")
            .post(payload.toRequestBody(JSON_MEDIA_TYPE))
            .build()

        client.newCall(request).execute().use { response ->
            val responseBody = response.body?.string().orEmpty()
            if (!response.isSuccessful) {
                throw ApiException("Login failed (${response.code})", statusCode = response.code)
            }
            json.decodeFromString<LoginResponse>(responseBody)
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

    suspend fun listMyDevices(baseUrl: String, token: String): List<MyDeviceDto> = withContext(Dispatchers.IO) {
        val request = Request.Builder()
            .url("${normalizeBaseUrl(baseUrl)}/me/devices")
            .addHeader("Authorization", "Bearer $token")
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

    suspend fun wakeDevice(baseUrl: String, token: String, hostId: String): MeWakeResponse = withContext(Dispatchers.IO) {
        val request = Request.Builder()
            .url("${normalizeBaseUrl(baseUrl)}/me/devices/$hostId/wake")
            .addHeader("Authorization", "Bearer $token")
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
    ): MyDeviceDto = withContext(Dispatchers.IO) {
        val payload = json.encodeToString(
            MyDevicePreferencesUpdateRequest(
                is_favorite = isFavorite,
                sort_order = sortOrder,
            ),
        )
        val request = Request.Builder()
            .url("${normalizeBaseUrl(baseUrl)}/me/devices/$hostId/preferences")
            .addHeader("Authorization", "Bearer $token")
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
    ): List<ActivityEventDto> = withContext(Dispatchers.IO) {
        val urlBuilder = "${normalizeBaseUrl(baseUrl)}/admin/mobile/events".toHttpUrl().newBuilder()
            .addQueryParameter("limit", limit.toString())
        if (cursor != null) {
            urlBuilder.addQueryParameter("cursor", cursor.toString())
        }
        if (!typeFilter.isNullOrBlank()) {
            urlBuilder.addQueryParameter("type", typeFilter)
        }
        val request = Request.Builder()
            .url(urlBuilder.build())
            .addHeader("Authorization", "Bearer $token")
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
    ): ShutdownPokeDto = withContext(Dispatchers.IO) {
        val payload = json.encodeToString(
            ShutdownPokeCreateRequest(
                message = message?.trim()?.ifBlank { null },
            ),
        )
        val request = Request.Builder()
            .url("${normalizeBaseUrl(baseUrl)}/me/devices/$hostId/shutdown-poke")
            .addHeader("Authorization", "Bearer $token")
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
    ): ShutdownPokeDto = withContext(Dispatchers.IO) {
        val request = Request.Builder()
            .url("${normalizeBaseUrl(baseUrl)}/admin/shutdown-pokes/$pokeId/seen")
            .addHeader("Authorization", "Bearer $token")
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
    ): ShutdownPokeDto = withContext(Dispatchers.IO) {
        val request = Request.Builder()
            .url("${normalizeBaseUrl(baseUrl)}/admin/shutdown-pokes/$pokeId/resolve")
            .addHeader("Authorization", "Bearer $token")
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
