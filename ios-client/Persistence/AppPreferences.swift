import SwiftUI
import Foundation

enum AppAppearance: String, CaseIterable, Identifiable {
    case system
    case light
    case dark

    var id: String { rawValue }

    var titleKey: LocalizedStringKey {
        switch self {
        case .system:
            return "settings_appearance_system"
        case .light:
            return "settings_appearance_light"
        case .dark:
            return "settings_appearance_dark"
        }
    }

    var colorScheme: ColorScheme? {
        switch self {
        case .system:
            return nil
        case .light:
            return .light
        case .dark:
            return .dark
        }
    }
}

enum AppLanguage: String, CaseIterable, Identifiable {
    case system
    case english = "en"
    case german = "de"

    var id: String { rawValue }

    var titleKey: LocalizedStringKey {
        switch self {
        case .system:
            return "settings_language_system"
        case .english:
            return "settings_language_english"
        case .german:
            return "settings_language_german"
        }
    }

    var locale: Locale {
        switch self {
        case .system:
            return .autoupdatingCurrent
        case .english:
            return Locale(identifier: "en")
        case .german:
            return Locale(identifier: "de")
        }
    }
}

final class AppPreferences {
    static let defaultBackendURL = "http://100.100.100.100:8080"

    private enum Keys {
        static let backendURL = "backend_url"
        static let lastUsername = "last_username"
        static let appearance = "appearance"
        static let language = "language"
        static let firstRunGuidanceAcknowledged = "first_run_guidance_acknowledged"
        static let notificationInstallationID = "notification_installation_id"
        static let notificationDeviceToken = "notification_device_token"
    }

    private let userDefaults: UserDefaults

    init(userDefaults: UserDefaults) {
        self.userDefaults = userDefaults
    }

    var backendURL: String {
        get {
            userDefaults.string(forKey: Keys.backendURL) ?? Self.defaultBackendURL
        }
        set {
            userDefaults.set(
                newValue.trimmingCharacters(in: .whitespacesAndNewlines),
                forKey: Keys.backendURL
            )
        }
    }

    var lastUsername: String {
        get {
            userDefaults.string(forKey: Keys.lastUsername) ?? ""
        }
        set {
            userDefaults.set(
                newValue.trimmingCharacters(in: .whitespacesAndNewlines),
                forKey: Keys.lastUsername
            )
        }
    }

    var appearance: AppAppearance {
        get {
            AppAppearance(rawValue: userDefaults.string(forKey: Keys.appearance) ?? "") ?? .system
        }
        set {
            userDefaults.set(newValue.rawValue, forKey: Keys.appearance)
        }
    }

    var language: AppLanguage {
        get {
            AppLanguage(rawValue: userDefaults.string(forKey: Keys.language) ?? "") ?? .system
        }
        set {
            userDefaults.set(newValue.rawValue, forKey: Keys.language)
        }
    }

    var hasAcknowledgedFirstRunGuidance: Bool {
        get {
            userDefaults.bool(forKey: Keys.firstRunGuidanceAcknowledged)
        }
        set {
            userDefaults.set(newValue, forKey: Keys.firstRunGuidanceAcknowledged)
        }
    }

    var notificationInstallationID: String {
        get {
            if let existing = userDefaults.string(forKey: Keys.notificationInstallationID),
               !existing.isEmpty {
                return existing
            }
            let generated = UUID().uuidString.lowercased()
            userDefaults.set(generated, forKey: Keys.notificationInstallationID)
            return generated
        }
        set {
            userDefaults.set(newValue.trimmingCharacters(in: .whitespacesAndNewlines), forKey: Keys.notificationInstallationID)
        }
    }

    var notificationDeviceToken: String {
        get {
            userDefaults.string(forKey: Keys.notificationDeviceToken) ?? ""
        }
        set {
            userDefaults.set(newValue.trimmingCharacters(in: .whitespacesAndNewlines), forKey: Keys.notificationDeviceToken)
        }
    }

}

@MainActor
final class SettingsStore: ObservableObject {
    @Published private(set) var appearance: AppAppearance
    @Published private(set) var language: AppLanguage
    @Published private(set) var hasAcknowledgedFirstRunGuidance: Bool

    private let preferences: AppPreferences

    init(preferences: AppPreferences) {
        self.preferences = preferences
        appearance = preferences.appearance
        language = preferences.language
        hasAcknowledgedFirstRunGuidance = preferences.hasAcknowledgedFirstRunGuidance
    }

    var colorScheme: ColorScheme? {
        appearance.colorScheme
    }

    var locale: Locale {
        language.locale
    }

    func updateAppearance(_ value: AppAppearance) {
        appearance = value
        preferences.appearance = value
    }

    func updateLanguage(_ value: AppLanguage) {
        language = value
        preferences.language = value
    }

    func acknowledgeFirstRunGuidance() {
        hasAcknowledgedFirstRunGuidance = true
        preferences.hasAcknowledgedFirstRunGuidance = true
    }
}
