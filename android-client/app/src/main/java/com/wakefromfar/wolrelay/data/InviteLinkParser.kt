package com.wakefromfar.wolrelay.data

import java.net.URLDecoder
import java.nio.charset.StandardCharsets

data class ParsedInviteLink(
    val token: String,
    val backendUrlHint: String?,
)

object InviteLinkParser {
    fun parse(uriString: String?): ParsedInviteLink? {
        if (uriString.isNullOrBlank()) return null

        val queryStart = uriString.indexOf('?')
        if (queryStart < 0 || queryStart == uriString.length - 1) return null
        val query = uriString.substring(queryStart + 1)

        val params = mutableMapOf<String, String>()
        for (part in query.split('&')) {
            if (part.isBlank()) continue
            val idx = part.indexOf('=')
            val rawKey = if (idx >= 0) part.substring(0, idx) else part
            val rawValue = if (idx >= 0 && idx + 1 < part.length) part.substring(idx + 1) else ""
            val key = decode(rawKey).trim()
            if (key.isEmpty()) continue
            params[key] = decode(rawValue).trim()
        }

        val token = params["token"].orEmpty().trim()
        if (token.isEmpty()) return null

        val backend = params["backend_url_hint"].orEmpty().ifBlank {
            params["backend_url"].orEmpty()
        }.ifBlank {
            ""
        }

        return ParsedInviteLink(
            token = token,
            backendUrlHint = backend.ifBlank { null },
        )
    }

    private fun decode(value: String): String = URLDecoder.decode(value, StandardCharsets.UTF_8)
}
