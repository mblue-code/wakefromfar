package com.wakefromfar.wolrelay.data

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class ApiExceptionTest {
    @Test
    fun sessionInvalidMatchesUnauthorizedStatus() {
        assertTrue(ApiException("Unauthorized", statusCode = 401).isSessionInvalid())
    }

    @Test
    fun sessionInvalidIgnoresOtherFailures() {
        assertFalse(ApiException("Forbidden", statusCode = 403).isSessionInvalid())
        assertFalse(IllegalStateException("boom").isSessionInvalid())
    }
}
