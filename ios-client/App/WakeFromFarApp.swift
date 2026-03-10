import SwiftUI

@main
struct WakeFromFarApp: App {
    @UIApplicationDelegateAdaptor(WakeFromFarAppDelegate.self) private var appDelegate

    private let services: AppServices

    @StateObject private var settingsStore: SettingsStore
    @StateObject private var sessionStore: SessionStore

    init() {
        let preferences = AppPreferences(userDefaults: .standard)
        let apiClient = APIClient()
        let tokenStore = KeychainStore(service: "com.wakefromfar.iosclient")
        let settingsStore = SettingsStore(preferences: preferences)
        let sessionStore = SessionStore(
            apiClient: apiClient,
            tokenStore: tokenStore,
            preferences: preferences
        )
        let notificationCoordinator = APNSNotificationCoordinator(
            apiClient: apiClient,
            preferences: preferences
        )
        let services = AppServices(
            apiClient: apiClient,
            preferences: preferences,
            notificationCoordinator: notificationCoordinator
        )

        WakeFromFarAppDelegate.notificationCoordinator = notificationCoordinator
        self.services = services
        _settingsStore = StateObject(wrappedValue: settingsStore)
        _sessionStore = StateObject(wrappedValue: sessionStore)
    }

    var body: some Scene {
        WindowGroup {
            RootView(
                sessionStore: sessionStore,
                settingsStore: settingsStore,
                services: services
            )
            .environment(\.locale, settingsStore.locale)
            .preferredColorScheme(settingsStore.colorScheme)
        }
    }
}
