package com.wakefromfar.wolrelay.data

import android.content.Context
import android.os.Build
import android.util.Base64
import com.google.android.gms.tasks.Task
import com.google.android.play.core.integrity.IntegrityManagerFactory
import com.google.android.play.core.integrity.StandardIntegrityManager
import com.wakefromfar.wolrelay.BuildConfig
import java.security.MessageDigest
import kotlin.coroutines.resume
import kotlin.coroutines.resumeWithException
import kotlinx.coroutines.suspendCancellableCoroutine

data class PreparedLoginProof(
    val installationId: String,
    val proofTicket: String? = null,
)

fun interface InstallationIdStore {
    fun getOrCreateInstallationId(): String
}

fun interface IntegrityTokenProvider {
    suspend fun requestToken(requestHash: String): String
}

class AndroidAppProofCoordinator(
    private val apiClient: ApiClient,
    private val installationIdStore: InstallationIdStore,
    private val tokenProvider: IntegrityTokenProvider,
    private val appVersionProvider: () -> String = { BuildConfig.VERSION_NAME },
    private val osVersionProvider: () -> String = { "android-${Build.VERSION.RELEASE ?: "unknown"}" },
) {
    suspend fun prepareLoginProof(baseUrl: String, username: String): PreparedLoginProof {
        val installationId = installationIdStore.getOrCreateInstallationId()
        if (BuildConfig.PLAY_INTEGRITY_CLOUD_PROJECT_NUMBER.isBlank()) {
            return PreparedLoginProof(installationId = installationId)
        }
        return try {
            val challenge = apiClient.requestAppProofChallenge(
                baseUrl = baseUrl,
                platform = "android",
                purpose = "login",
                installationId = installationId,
                username = username,
                appVersion = appVersionProvider(),
                osVersion = osVersionProvider(),
            )
            val requestHash = androidRequestHash(
                purpose = challenge.purpose,
                challengeId = challenge.challenge_id,
                challenge = challenge.challenge,
                installationId = installationId,
                username = username,
            )
            val integrityToken = tokenProvider.requestToken(requestHash)
            val verifyResponse = apiClient.verifyAndroidAppProof(
                baseUrl = baseUrl,
                challengeId = challenge.challenge_id,
                installationId = installationId,
                requestHash = requestHash,
                integrityToken = integrityToken,
                appVersion = appVersionProvider(),
                osVersion = osVersionProvider(),
            )
            PreparedLoginProof(
                installationId = installationId,
                proofTicket = verifyResponse.proof_ticket,
            )
        } catch (_: Exception) {
            PreparedLoginProof(installationId = installationId)
        }
    }
}

class PlayIntegrityStandardTokenProvider(
    context: Context,
    private val cloudProjectNumber: Long,
) : IntegrityTokenProvider {
    private val integrityManager = IntegrityManagerFactory.createStandard(context.applicationContext)
    @Volatile
    private var tokenProvider: StandardIntegrityManager.StandardIntegrityTokenProvider? = null

    override suspend fun requestToken(requestHash: String): String {
        val preparedProvider = tokenProvider ?: prepareProvider().also { tokenProvider = it }
        val response = preparedProvider.request(
            StandardIntegrityManager.StandardIntegrityTokenRequest.builder()
                .setRequestHash(requestHash)
                .build(),
        ).await()
        return response.token()
    }

    private suspend fun prepareProvider(): StandardIntegrityManager.StandardIntegrityTokenProvider {
        return integrityManager.prepareIntegrityToken(
            StandardIntegrityManager.PrepareIntegrityTokenRequest.builder()
                .setCloudProjectNumber(cloudProjectNumber)
                .build(),
        ).await()
    }
}

fun androidRequestHash(
    purpose: String,
    challengeId: String,
    challenge: String,
    installationId: String,
    username: String?,
): String {
    val canonicalJson = buildString {
        append('{')
        append("\"purpose\":\"")
        append(jsonEscape(purpose))
        append("\",\"challenge_id\":\"")
        append(jsonEscape(challengeId))
        append("\",\"challenge\":\"")
        append(jsonEscape(challenge))
        append("\",\"installation_id\":\"")
        append(jsonEscape(installationId))
        if (!username.isNullOrBlank()) {
            append("\",\"username\":\"")
            append(jsonEscape(username))
        }
        append("\"}")
    }
    val digest = MessageDigest.getInstance("SHA-256").digest(canonicalJson.toByteArray(Charsets.UTF_8))
    return Base64.encodeToString(digest, Base64.URL_SAFE or Base64.NO_PADDING or Base64.NO_WRAP)
}

private fun jsonEscape(value: String): String {
    val out = StringBuilder(value.length + 8)
    value.forEach { ch ->
        when (ch) {
            '\\' -> out.append("\\\\")
            '"' -> out.append("\\\"")
            '\b' -> out.append("\\b")
            '\u000C' -> out.append("\\f")
            '\n' -> out.append("\\n")
            '\r' -> out.append("\\r")
            '\t' -> out.append("\\t")
            else -> {
                if (ch.code < 0x20) {
                    out.append("\\u")
                    out.append(ch.code.toString(16).padStart(4, '0'))
                } else {
                    out.append(ch)
                }
            }
        }
    }
    return out.toString()
}

private suspend fun <T> Task<T>.await(): T = suspendCancellableCoroutine { continuation ->
    addOnSuccessListener { continuation.resume(it) }
    addOnFailureListener { continuation.resumeWithException(it) }
    addOnCanceledListener { continuation.cancel() }
}
