package com.wakefromfar.wolrelay.ui

import com.wakefromfar.wolrelay.data.DevicePermissionsDto
import com.wakefromfar.wolrelay.data.MyDeviceDto
import org.junit.Assert.assertEquals
import org.junit.Test

class DevicePresentationTest {
    @Test
    fun buildsFavoritesAndGroupedSectionsInPresentationOrder() {
        val devices = listOf(
            device(id = "4", name = "media", displayName = "Media PC", groupName = "Home", isFavorite = true, sortOrder = 3),
            device(id = "3", name = "nas", displayName = "NAS", groupName = "Core", sortOrder = 2),
            device(id = "2", name = "laptop", displayName = "Laptop", groupName = "Work", sortOrder = 1),
            device(id = "1", name = "printer", displayName = "Printer", groupName = null, sortOrder = 0),
        )

        val sections = buildDeviceSections(
            devices = devices,
            favoritesTitle = "Favorites",
            fallbackGroupTitle = "Other",
        )

        assertEquals(listOf("Favorites", "Core", "Work", "Other"), sections.map { it.title })
        assertEquals(listOf("4"), sections[0].devices.map { it.id })
        assertEquals(listOf("3"), sections[1].devices.map { it.id })
        assertEquals(listOf("2"), sections[2].devices.map { it.id })
        assertEquals(listOf("1"), sections[3].devices.map { it.id })
    }

    private fun device(
        id: String,
        name: String,
        displayName: String,
        groupName: String?,
        isFavorite: Boolean = false,
        sortOrder: Int = 0,
    ): MyDeviceDto {
        return MyDeviceDto(
            id = id,
            name = name,
            display_name = displayName,
            group_name = groupName,
            mac = "AA:BB:CC:DD:EE:${id.padStart(2, '0')}",
            is_favorite = isFavorite,
            sort_order = sortOrder,
            permissions = DevicePermissionsDto(),
            last_power_state = "unknown",
            last_power_checked_at = null,
            is_stale = false,
        )
    }
}
