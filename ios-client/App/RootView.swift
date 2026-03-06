import SwiftUI

struct RootView: View {
    @ObservedObject var sessionStore: SessionStore
    @ObservedObject var settingsStore: SettingsStore

    let services: AppServices

    var body: some View {
        Group {
            if sessionStore.isAuthenticated {
                MainTabView(
                    sessionStore: sessionStore,
                    settingsStore: settingsStore,
                    services: services
                )
            } else if !settingsStore.hasAcknowledgedFirstRunGuidance {
                FirstRunGuidanceView(settingsStore: settingsStore)
            } else {
                LoginView(
                    viewModel: LoginViewModel(
                        sessionStore: sessionStore,
                        preferences: services.preferences
                    )
                )
            }
        }
        .task(id: sessionStore.currentSession) {
            await services.notificationCoordinator.bootstrap(session: sessionStore.currentSession)
        }
    }
}
