package com.wakefromfar.wolrelay.data

import kotlinx.serialization.builtins.ListSerializer
import kotlinx.serialization.json.Json
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class MyDeviceDtoParsingTest {
    private val json = Json {
        ignoreUnknownKeys = true
        explicitNulls = false
    }

    @Test
    fun parsesMembershipAwareDevicePayload() {
        val payload = """
            [
              {
                "id": "media-pc",
                "name": "media-pc",
                "display_name": "Media PC",
                "group_name": "Home",
                "mac": "AA:BB:CC:DD:EE:03",
                "is_favorite": true,
                "sort_order": 7,
                "permissions": {
                  "can_view_status": false,
                  "can_wake": true,
                  "can_request_shutdown": false,
                  "can_manage_schedule": false
                },
                "last_power_state": "unknown",
                "last_power_checked_at": "2026-03-08T10:15:30Z",
                "is_stale": true,
                "scheduled_wake_summary": {
                  "total_count": 2,
                  "enabled_count": 1,
                  "next_run_at": "2026-03-10T07:30:00Z"
                }
              }
            ]
        """.trimIndent()

        val devices = json.decodeFromString(ListSerializer(MyDeviceDto.serializer()), payload)
        val device = devices.single()

        assertEquals("media-pc", device.id)
        assertEquals("Media PC", device.displayTitle)
        assertTrue(device.is_favorite)
        assertEquals(7, device.sort_order)
        assertFalse(device.canViewStatus)
        assertTrue(device.canWake)
        assertFalse(device.canRequestShutdown)
        assertFalse(device.canManageSchedule)
        assertEquals(2, device.scheduled_wake_summary?.total_count)
        assertEquals(1, device.scheduled_wake_summary?.enabled_count)
        assertEquals("2026-03-10T07:30:00Z", device.scheduled_wake_summary?.next_run_at)
    }

    @Test
    fun defaultsPermissionsSafelyWhenFieldsAreMissing() {
        val payload = """
            {
              "id": "nas",
              "name": "nas",
              "mac": "AA:BB:CC:DD:EE:01"
            }
        """.trimIndent()

        val device = json.decodeFromString(MyDeviceDto.serializer(), payload)

        assertFalse(device.is_favorite)
        assertEquals(0, device.sort_order)
        assertTrue(device.canViewStatus)
        assertTrue(device.canWake)
        assertTrue(device.canRequestShutdown)
        assertFalse(device.canManageSchedule)
    }

    @Test
    fun serializesPreferencePatchWithoutNullFields() {
        val payload = json.encodeToString(
            MyDevicePreferencesUpdateRequest.serializer(),
            MyDevicePreferencesUpdateRequest(is_favorite = true),
        )

        assertEquals("""{"is_favorite":true}""", payload)
    }
}
