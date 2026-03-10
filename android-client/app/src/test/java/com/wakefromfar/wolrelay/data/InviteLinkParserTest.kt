package com.wakefromfar.wolrelay.data

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

class InviteLinkParserTest {
    @Test
    fun parsesTokenAndBackendHint() {
        val parsed = InviteLinkParser.parse(
            "wakefromfar://claim?token=abc123&backend_url_hint=http%3A%2F%2Frelay.local%3A8080",
        )

        assertEquals("abc123", parsed?.token)
        assertEquals("http://relay.local:8080", parsed?.backendUrlHint)
    }

    @Test
    fun fallsBackToBackendUrlWhenHintIsMissing() {
        val parsed = InviteLinkParser.parse(
            "wakefromfar://claim?token=abc123&backend_url=http%3A%2F%2F100.64.0.5%3A8080",
        )

        assertEquals("abc123", parsed?.token)
        assertEquals("http://100.64.0.5:8080", parsed?.backendUrlHint)
    }

    @Test
    fun returnsNullWhenTokenMissing() {
        val parsed = InviteLinkParser.parse("wakefromfar://claim?backend_url_hint=http://relay.local")
        assertNull(parsed)
    }
}
