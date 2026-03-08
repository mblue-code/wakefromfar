import XCTest

final class DeviceContractTests: XCTestCase {
    private let decoder: JSONDecoder = {
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
        return decoder
    }()

    func testDecodesMembershipAwareDeviceFields() throws {
        let payload = """
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
        """.data(using: .utf8)!

        let device = try decoder.decode(MyDevice.self, from: payload)

        XCTAssertEqual(device.id, "media-pc")
        XCTAssertEqual(device.displayTitle, "Media PC")
        XCTAssertTrue(device.isFavorite)
        XCTAssertEqual(device.sortOrder, 7)
        XCTAssertFalse(device.canViewStatus)
        XCTAssertTrue(device.canWake)
        XCTAssertFalse(device.canRequestShutdown)
        XCTAssertFalse(device.canManageSchedule)
        XCTAssertTrue(device.isStale)
        XCTAssertEqual(device.scheduledWakeSummary?.totalCount, 2)
        XCTAssertEqual(device.scheduledWakeSummary?.enabledCount, 1)
        XCTAssertEqual(device.scheduledWakeSummary?.nextRunAt, ISO8601DateFormatter().date(from: "2026-03-10T07:30:00Z"))
    }

    func testDefaultsPermissionFieldsWhenOlderPayloadOmitsThem() throws {
        let payload = """
        {
          "id": "nas",
          "name": "nas",
          "mac": "AA:BB:CC:DD:EE:01"
        }
        """.data(using: .utf8)!

        let device = try decoder.decode(MyDevice.self, from: payload)

        XCTAssertFalse(device.isFavorite)
        XCTAssertEqual(device.sortOrder, 0)
        XCTAssertTrue(device.canViewStatus)
        XCTAssertTrue(device.canWake)
        XCTAssertTrue(device.canRequestShutdown)
        XCTAssertFalse(device.canManageSchedule)
        XCTAssertEqual(device.lastPowerState, .unknown)
        XCTAssertTrue(device.isStale)
    }

    func testEncodesPreferencePatchWithoutNullFields() throws {
        let encoder = JSONEncoder()
        let payload = try encoder.encode(
            DevicePreferencesUpdateRequest(
                isFavorite: true,
                sortOrder: nil
            )
        )

        XCTAssertEqual(String(decoding: payload, as: UTF8.self), #"{"is_favorite":true}"#)
    }

    func testBuildsFavoritesAndGroupedSectionsInPresentationOrder() throws {
        let payload = """
        [
          {
            "id": "4",
            "name": "media",
            "display_name": "Media PC",
            "group_name": "Home",
            "mac": "AA:BB:CC:DD:EE:04",
            "is_favorite": true,
            "sort_order": 3
          },
          {
            "id": "3",
            "name": "nas",
            "display_name": "NAS",
            "group_name": "Core",
            "mac": "AA:BB:CC:DD:EE:03",
            "sort_order": 2
          },
          {
            "id": "2",
            "name": "laptop",
            "display_name": "Laptop",
            "group_name": "Work",
            "mac": "AA:BB:CC:DD:EE:02",
            "sort_order": 1
          },
          {
            "id": "1",
            "name": "printer",
            "display_name": "Printer",
            "mac": "AA:BB:CC:DD:EE:01",
            "sort_order": 0
          }
        ]
        """.data(using: .utf8)!

        let devices = try decoder.decode([MyDevice].self, from: payload)
        let sections = buildDeviceSections(
            devices,
            favoritesTitle: "Favorites",
            fallbackGroupTitle: "Other"
        )

        XCTAssertEqual(sections.map(\.title), ["Favorites", "Core", "Work", "Other"])
        XCTAssertEqual(sections[0].devices.map(\.id), ["4"])
        XCTAssertEqual(sections[1].devices.map(\.id), ["3"])
        XCTAssertEqual(sections[2].devices.map(\.id), ["2"])
        XCTAssertEqual(sections[3].devices.map(\.id), ["1"])
    }
}
