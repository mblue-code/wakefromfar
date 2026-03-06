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

struct MyDevice: Decodable, Identifiable {
    let id: String
    let name: String
    let displayName: String?
    let groupName: String?
    let mac: String
    let lastPowerState: PowerState
    let lastPowerCheckedAt: Date?
    let isStale: Bool

    enum CodingKeys: String, CodingKey {
        case id
        case name
        case displayName = "display_name"
        case groupName = "group_name"
        case mac
        case lastPowerState = "last_power_state"
        case lastPowerCheckedAt = "last_power_checked_at"
        case isStale = "is_stale"
    }

    var displayTitle: String {
        if let displayName, !displayName.isEmpty {
            return displayName
        }
        return name
    }
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
