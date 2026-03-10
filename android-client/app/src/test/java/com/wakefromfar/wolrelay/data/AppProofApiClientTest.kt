package com.wakefromfar.wolrelay.data

import java.util.concurrent.TimeUnit
import kotlinx.coroutines.runBlocking
import okhttp3.mockwebserver.MockResponse
import okhttp3.mockwebserver.MockWebServer
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test

class AppProofApiClientTest {
    private lateinit var server: MockWebServer
    private lateinit var apiClient: ApiClient

    @Before
    fun setUp() {
        server = MockWebServer()
        server.start()
        apiClient = ApiClient()
    }

    @After
    fun tearDown() {
        server.shutdown()
    }

    @Test
    fun requestChallengeAndVerifyFlowUsesExpectedEndpoints() = runBlocking {
        server.enqueue(
            MockResponse().setBody(
                """
                {
                  "challenge_id":"challenge-1",
                  "challenge":"nonce-1",
                  "purpose":"login",
                  "expires_in":300,
                  "binding":{"canonical_fields":["purpose","challenge_id","challenge","installation_id","username"]}
                }
                """.trimIndent(),
            ),
        )
        server.enqueue(
            MockResponse().setBody(
                """
                {
                  "proof_ticket":"ticket-1",
                  "proof_expires_in":300,
                  "installation_status":"trusted"
                }
                """.trimIndent(),
            ),
        )

        val baseUrl = server.url("/").toString()
        val challenge = apiClient.requestAppProofChallenge(
            baseUrl = baseUrl,
            platform = "android",
            purpose = "login",
            installationId = "install-1",
            username = "alice",
            appVersion = "1.0.0",
            osVersion = "android-15",
        )
        val verify = apiClient.verifyAndroidAppProof(
            baseUrl = baseUrl,
            challengeId = challenge.challenge_id,
            installationId = "install-1",
            requestHash = "request-hash",
            integrityToken = "integrity-token-12345",
        )

        assertEquals("ticket-1", verify.proof_ticket)

        val challengeRequest = server.takeRequest(1, TimeUnit.SECONDS)!!
        assertEquals("/auth/app-proof/challenge", challengeRequest.path)
        assertTrue(challengeRequest.body.readUtf8().contains("\"installation_id\":\"install-1\""))

        val verifyRequest = server.takeRequest(1, TimeUnit.SECONDS)!!
        assertEquals("/auth/app-proof/verify/android", verifyRequest.path)
        assertTrue(verifyRequest.body.readUtf8().contains("\"request_hash\":\"request-hash\""))
    }

    @Test
    fun loginIncludesInstallationBindingFieldsWhenProvided() = runBlocking {
        server.enqueue(MockResponse().setBody("""{"token":"jwt-token","expires_in":28800}"""))

        val response = apiClient.login(
            baseUrl = server.url("/").toString(),
            username = "alice",
            password = "secret",
            installationId = "install-2",
            proofTicket = "ticket-2",
        )

        assertEquals("jwt-token", response.token)
        val request = server.takeRequest(1, TimeUnit.SECONDS)!!
        assertEquals("/auth/login", request.path)
        val body = request.body.readUtf8()
        assertTrue(body.contains("\"installation_id\":\"install-2\""))
        assertTrue(body.contains("\"proof_ticket\":\"ticket-2\""))
    }

    @Test
    fun coordinatorFallsBackToPlainLoginWhenProofStepFails() = runBlocking {
        val coordinator = AndroidAppProofCoordinator(
            apiClient = apiClient,
            installationIdStore = InstallationIdStore { "install-3" },
            tokenProvider = IntegrityTokenProvider { throw IllegalStateException("no play services") },
            appVersionProvider = { "1.0.0" },
            osVersionProvider = { "android-15" },
        )

        val proof = coordinator.prepareLoginProof("https://example.test", "alice")

        assertEquals("install-3", proof.installationId)
        assertNull(proof.proofTicket)
    }
}
