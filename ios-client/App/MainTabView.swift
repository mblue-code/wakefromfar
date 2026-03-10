import SwiftUI

enum MainTab: Hashable {
    case devices
    case activity
    case settings
}

struct MainTabView: View {
    let sessionStore: SessionStore
    let settingsStore: SettingsStore
    let services: AppServices

    @State private var selectedTab: MainTab = .devices

    var body: some View {
        TabView(selection: $selectedTab) {
            DevicesView(
                viewModel: DevicesViewModel(
                    sessionStore: sessionStore,
                    apiClient: services.apiClient
                )
            )
            .tag(MainTab.devices)
            .tabItem {
                Label("tab_devices", systemImage: "desktopcomputer")
            }

            if sessionStore.currentSession?.role == .admin {
                AdminActivityView(
                    viewModel: AdminActivityViewModel(
                        sessionStore: sessionStore,
                        apiClient: services.apiClient
                    ),
                    notificationCoordinator: services.notificationCoordinator
                )
                .tag(MainTab.activity)
                .tabItem {
                    Label("tab_activity", systemImage: "clock.arrow.circlepath")
                }
            }

            SettingsView(
                sessionStore: sessionStore,
                settingsStore: settingsStore,
                services: services,
                notificationCoordinator: services.notificationCoordinator
            )
            .tag(MainTab.settings)
            .tabItem {
                Label("tab_settings", systemImage: "gearshape")
            }
        }
        .onReceive(services.notificationCoordinator.$pendingTabSelection) { pendingTab in
            guard let pendingTab else { return }
            if pendingTab == .activity, sessionStore.currentSession?.role != .admin {
                selectedTab = .devices
            } else {
                selectedTab = pendingTab
            }
            services.notificationCoordinator.consumePendingTabSelection()
        }
    }
}
