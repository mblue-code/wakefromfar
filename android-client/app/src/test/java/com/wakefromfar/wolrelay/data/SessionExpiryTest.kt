package com.wakefromfar.wolrelay.data

import java.util.concurrent.TimeUnit
import kotlinx.coroutines.runBlocking
import okhttp3.mockwebserver.MockResponse
import okhttp3.mockwebserver.MockWebServer
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test

class SessionExpiryTest {
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
    fun treats401ApiFailuresAsExpiredSessions() = runBlocking {
        server.enqueue(MockResponse().setResponseCode(401).setBody("""{"detail":"Session expired"}"""))

        val failure = try {
            apiClient.listMyDevices(
                baseUrl = server.url("/").toString(),
                token = "expired-token",
                installationId = "install-1",
            )
            error("Expected ApiException")
        } catch (ex: ApiException) {
            ex
        }

        assertEquals(401, failure.statusCode)
        assertTrue(failure.isSessionInvalid())

        val request = server.takeRequest(1, TimeUnit.SECONDS)!!
        assertEquals("/me/devices", request.path)
    }

    @Test
    fun keeps403PermissionFailuresOutOfSessionExpiryPath() {
        val failure = ApiException("Forbidden", statusCode = 403)

        assertFalse(failure.isSessionInvalid())
    }
}
