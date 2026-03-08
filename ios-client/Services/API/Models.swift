import Foundation

struct LoginRequest: Encodable {
    let username: String
    let password: String
}

struct LoginResponse: Decodable {
    let token: String
    let expiresIn: Int

    enum CodingKeys: String, CodingKey {
        case token
        case expiresIn = "expires_in"
    }
}

enum PowerState: String, Codable {
    case on
    case off
    case unknown
}

struct DevicePermissions: Codable, Hashable {
    let canViewStatus: Bool
    let canWake: Bool
    let canRequestShutdown: Bool
    let canManageSchedule: Bool

    init(
        canViewStatus: Bool = true,
        canWake: Bool = true,
        canRequestShutdown: Bool = true,
        canManageSchedule: Bool = false
    ) {
        self.canViewStatus = canViewStatus
        self.canWake = canWake
        self.canRequestShutdown = canRequestShutdown
        self.canManageSchedule = canManageSchedule
    }

    enum CodingKeys: String, CodingKey {
        case canViewStatus = "can_view_status"
        case canWake = "can_wake"
        case canRequestShutdown = "can_request_shutdown"
        case canManageSchedule = "can_manage_schedule"
    }
}

struct ScheduledWakeSummary: Codable, Hashable {
    let totalCount: Int
    let enabledCount: Int
    let nextRunAt: Date?

    enum CodingKeys: String, CodingKey {
        case totalCount = "total_count"
        case enabledCount = "enabled_count"
        case nextRunAt = "next_run_at"
    }
}

struct MyDevice: Decodable, Identifiable {
    let id: String
    let name: String
    let displayName: String?
    let groupName: String?
    let mac: String
    let isFavorite: Bool
    let sortOrder: Int
    let permissions: DevicePermissions
    let lastPowerState: PowerState
    let lastPowerCheckedAt: Date?
    let isStale: Bool
    let scheduledWakeSummary: ScheduledWakeSummary?

    enum CodingKeys: String, CodingKey {
        case id
        case name
        case displayName = "display_name"
        case groupName = "group_name"
        case mac
        case isFavorite = "is_favorite"
        case sortOrder = "sort_order"
        case permissions
        case lastPowerState = "last_power_state"
        case lastPowerCheckedAt = "last_power_checked_at"
        case isStale = "is_stale"
        case scheduledWakeSummary = "scheduled_wake_summary"
    }

    init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        id = try container.decode(String.self, forKey: .id)
        name = try container.decode(String.self, forKey: .name)
        displayName = try container.decodeIfPresent(String.self, forKey: .displayName)
        groupName = try container.decodeIfPresent(String.self, forKey: .groupName)
        mac = try container.decode(String.self, forKey: .mac)
        isFavorite = try container.decodeIfPresent(Bool.self, forKey: .isFavorite) ?? false
        sortOrder = try container.decodeIfPresent(Int.self, forKey: .sortOrder) ?? 0
        permissions = try container.decodeIfPresent(DevicePermissions.self, forKey: .permissions) ?? DevicePermissions()
        lastPowerState = try container.decodeIfPresent(PowerState.self, forKey: .lastPowerState) ?? .unknown
        lastPowerCheckedAt = try container.decodeIfPresent(Date.self, forKey: .lastPowerCheckedAt)
        isStale = try container.decodeIfPresent(Bool.self, forKey: .isStale) ?? true
        scheduledWakeSummary = try container.decodeIfPresent(ScheduledWakeSummary.self, forKey: .scheduledWakeSummary)
    }

    var displayTitle: String {
        if let displayName, !displayName.isEmpty {
            return displayName
        }
        return name
    }

    var canViewStatus: Bool {
        permissions.canViewStatus
    }

    var canWake: Bool {
        permissions.canWake
    }

    var canRequestShutdown: Bool {
        permissions.canRequestShutdown
    }

    var canManageSchedule: Bool {
        permissions.canManageSchedule
    }

    var scheduledWakeHint: String? {
        guard let summary = scheduledWakeSummary else {
            return nil
        }
        if let nextRunAt = summary.nextRunAt, summary.enabledCount > 0 {
            let formatter = DateFormatter()
            formatter.locale = .current
            formatter.dateStyle = .short
            formatter.timeStyle = .short
            return String(
                format: NSLocalizedString("devices_schedule_next_format", comment: ""),
                formatter.string(from: nextRunAt)
            )
        }
        if summary.enabledCount > 0 {
            if summary.enabledCount == 1 {
                return NSLocalizedString("devices_schedule_active_one", comment: "")
            }
            return String(
                format: NSLocalizedString("devices_schedule_active_many_format", comment: ""),
                summary.enabledCount
            )
        }
        if summary.totalCount > 0 {
            if summary.totalCount == 1 {
                return NSLocalizedString("devices_schedule_disabled_one", comment: "")
            }
            return String(
                format: NSLocalizedString("devices_schedule_disabled_many_format", comment: ""),
                summary.totalCount
            )
        }
        return nil
    }
}

struct DevicePreferencesUpdateRequest: Encodable {
    let isFavorite: Bool?
    let sortOrder: Int?

    enum CodingKeys: String, CodingKey {
        case isFavorite = "is_favorite"
        case sortOrder = "sort_order"
    }
}

struct DeviceListSection: Identifiable {
    let id: String
    let title: String
    let devices: [MyDevice]
    let isFavorites: Bool
}

func sortDevicesForPresentation(_ devices: [MyDevice]) -> [MyDevice] {
    devices.sorted {
        let lhsFavorite = $0.isFavorite ? 0 : 1
        let rhsFavorite = $1.isFavorite ? 0 : 1
        if lhsFavorite != rhsFavorite { return lhsFavorite < rhsFavorite }

        let lhsUngrouped = !$0.isFavorite && isUngrouped($0.groupName)
        let rhsUngrouped = !$1.isFavorite && isUngrouped($1.groupName)
        if lhsUngrouped != rhsUngrouped { return rhsUngrouped }

        let lhsGroup = $0.isFavorite || lhsUngrouped ? "" : normalizedGroupName($0.groupName)
        let rhsGroup = $1.isFavorite || rhsUngrouped ? "" : normalizedGroupName($1.groupName)
        let groupComparison = lhsGroup.localizedCaseInsensitiveCompare(rhsGroup)
        if groupComparison != .orderedSame { return groupComparison == .orderedAscending }

        if $0.sortOrder != $1.sortOrder { return $0.sortOrder < $1.sortOrder }

        let titleComparison = $0.displayTitle.localizedCaseInsensitiveCompare($1.displayTitle)
        if titleComparison != .orderedSame { return titleComparison == .orderedAscending }

        let nameComparison = $0.name.localizedCaseInsensitiveCompare($1.name)
        if nameComparison != .orderedSame { return nameComparison == .orderedAscending }

        return $0.id < $1.id
    }
}

func buildDeviceSections(
    _ devices: [MyDevice],
    favoritesTitle: String,
    fallbackGroupTitle: String
) -> [DeviceListSection] {
    guard !devices.isEmpty else {
        return []
    }

    let sortedDevices = sortDevicesForPresentation(devices)
    let favorites = sortedDevices.filter(\.isFavorite)
    let groupedDevices = sortedDevices.filter { !$0.isFavorite }
    var sections: [DeviceListSection] = []

    if !favorites.isEmpty {
        sections.append(
            DeviceListSection(
                id: "favorites",
                title: favoritesTitle,
                devices: favorites,
                isFavorites: true
            )
        )
    }

    let grouped = Dictionary(grouping: groupedDevices) { device in
        let group = device.groupName?.trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
        return group.isEmpty ? fallbackGroupTitle : group
    }
    var seenTitles = Set<String>()
    let orderedTitles = groupedDevices.compactMap { device -> String? in
        let group = device.groupName?.trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
        let title = group.isEmpty ? fallbackGroupTitle : group
        guard seenTitles.insert(title).inserted else {
            return nil
        }
        return title
    }

    for title in orderedTitles {
        guard let groupDevices = grouped[title] else { continue }
        sections.append(
            DeviceListSection(
                id: "group:\(title)",
                title: title,
                devices: groupDevices,
                isFavorites: false
            )
        )
    }

    return sections
}

private func normalizedGroupName(_ value: String?) -> String {
    let trimmed = value?.trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
    return trimmed
}

private func isUngrouped(_ value: String?) -> Bool {
    normalizedGroupName(value).isEmpty
}

enum WakeResult: String, Codable {
    case alreadyOn = "already_on"
    case sent
    case failed
}

struct MeWakeResponse: Decodable {
    let deviceID: String
    let result: WakeResult
    let message: String
    let precheckState: PowerState
    let sentTo: String?
    let timestamp: Date
    let errorDetail: String?

    enum CodingKeys: String, CodingKey {
        case deviceID = "device_id"
        case result
        case message
        case precheckState = "precheck_state"
        case sentTo = "sent_to"
        case timestamp
        case errorDetail = "error_detail"
    }
}

struct ShutdownPokeCreateRequest: Encodable {
    let message: String?
}

enum APNSEnvironment: String, Codable {
    case development
    case production
}

struct APNSDeviceRegistrationRequest: Encodable {
    let installationID: String
    let token: String
    let appBundleID: String
    let environment: APNSEnvironment

    enum CodingKeys: String, CodingKey {
        case installationID = "installation_id"
        case token
        case appBundleID = "app_bundle_id"
        case environment
    }
}

struct NotificationDeviceRegistration: Decodable {
    let installationID: String
    let platform: String
    let provider: String
    let appBundleID: String
    let environment: APNSEnvironment
    let isActive: Bool
    let updatedAt: Date

    enum CodingKeys: String, CodingKey {
        case installationID = "installation_id"
        case platform
        case provider
        case appBundleID = "app_bundle_id"
        case environment
        case isActive = "is_active"
        case updatedAt = "updated_at"
    }
}

enum ShutdownPokeStatus: String, Codable {
    case open
    case seen
    case resolved
}

struct ShutdownPoke: Decodable, Identifiable {
    let id: String
    let serverID: String
    let deviceName: String?
    let deviceDisplayName: String?
    let requesterUserID: Int
    let requesterUsername: String
    let message: String?
    let status: ShutdownPokeStatus
    let createdAt: Date
    let seenAt: Date?
    let resolvedAt: Date?
    let resolvedByUserID: Int?
    let resolvedByUsername: String?

    enum CodingKeys: String, CodingKey {
        case id
        case serverID = "server_id"
        case deviceName = "device_name"
        case deviceDisplayName = "device_display_name"
        case requesterUserID = "requester_user_id"
        case requesterUsername = "requester_username"
        case message
        case status
        case createdAt = "created_at"
        case seenAt = "seen_at"
        case resolvedAt = "resolved_at"
        case resolvedByUserID = "resolved_by_user_id"
        case resolvedByUsername = "resolved_by_username"
    }
}

struct ActivityEvent: Decodable, Identifiable {
    let id: Int
    let eventType: String
    let actorUserID: Int?
    let actorUsername: String?
    let targetType: String
    let targetID: String?
    let serverID: String?
    let summary: String
    let metadata: [String: JSONValue]?
    let createdAt: Date

    enum CodingKeys: String, CodingKey {
        case id
        case eventType = "event_type"
        case actorUserID = "actor_user_id"
        case actorUsername = "actor_username"
        case targetType = "target_type"
        case targetID = "target_id"
        case serverID = "server_id"
        case summary
        case metadata
        case createdAt = "created_at"
    }
}

extension ActivityEvent {
    var isWakeEvent: Bool {
        eventType.hasPrefix("wake_")
    }

    var isErrorEvent: Bool {
        eventType == "wake_failed"
    }

    var isShutdownPokeEvent: Bool {
        eventType.hasPrefix("shutdown_poke_")
    }

    var pokeID: String? {
        if let metadataPokeID = metadata?["poke_id"]?.stringValue?.trimmedNonEmpty {
            return metadataPokeID
        }
        if targetType == "request" {
            return targetID?.trimmedNonEmpty
        }
        return nil
    }

    var shutdownStatus: ShutdownPokeStatus? {
        if let statusText = metadata?["status"]?.stringValue?.trimmedNonEmpty,
           let status = ShutdownPokeStatus(rawValue: statusText) {
            return status
        }

        switch eventType {
        case "shutdown_poke_requested":
            return .open
        case "shutdown_poke_seen":
            return .seen
        case "shutdown_poke_resolved":
            return .resolved
        default:
            return nil
        }
    }

    var shutdownNote: String? {
        metadata?["message"]?.stringValue?.trimmedNonEmpty
    }

    var sentTo: String? {
        metadata?["sent_to"]?.stringValue?.trimmedNonEmpty
    }

    var errorDetail: String? {
        metadata?["error_detail"]?.stringValue?.trimmedNonEmpty
    }

    var precheckState: PowerState? {
        guard let rawValue = metadata?["precheck_state"]?.stringValue?.trimmedNonEmpty else {
            return nil
        }
        return PowerState(rawValue: rawValue)
    }
}

enum JSONValue: Codable, Hashable {
    case string(String)
    case number(Double)
    case bool(Bool)
    case object([String: JSONValue])
    case array([JSONValue])
    case null

    init(from decoder: Decoder) throws {
        let container = try decoder.singleValueContainer()
        if container.decodeNil() {
            self = .null
        } else if let value = try? container.decode(Bool.self) {
            self = .bool(value)
        } else if let value = try? container.decode(Double.self) {
            self = .number(value)
        } else if let value = try? container.decode(String.self) {
            self = .string(value)
        } else if let value = try? container.decode([String: JSONValue].self) {
            self = .object(value)
        } else if let value = try? container.decode([JSONValue].self) {
            self = .array(value)
        } else {
            throw DecodingError.typeMismatch(
                JSONValue.self,
                DecodingError.Context(
                    codingPath: decoder.codingPath,
                    debugDescription: "Unsupported JSON value."
                )
            )
        }
    }

    func encode(to encoder: Encoder) throws {
        var container = encoder.singleValueContainer()
        switch self {
        case .string(let value):
            try container.encode(value)
        case .number(let value):
            try container.encode(value)
        case .bool(let value):
            try container.encode(value)
        case .object(let value):
            try container.encode(value)
        case .array(let value):
            try container.encode(value)
        case .null:
            try container.encodeNil()
        }
    }
}

extension JSONValue {
    var stringValue: String? {
        guard case .string(let value) = self else {
            return nil
        }
        return value
    }
}

private extension String {
    var trimmedNonEmpty: String? {
        let trimmed = trimmingCharacters(in: .whitespacesAndNewlines)
        return trimmed.isEmpty ? nil : trimmed
    }
}
