import SwiftUI

struct SettingsView: View {
    let sessionStore: SessionStore
    @ObservedObject var settingsStore: SettingsStore
    let services: AppServices
    @ObservedObject var notificationCoordinator: APNSNotificationCoordinator

    var body: some View {
        NavigationStack {
            Form {
                Section {
                    Picker("settings_appearance_title", selection: appearanceBinding) {
                        ForEach(AppAppearance.allCases) { appearance in
                            Text(appearance.titleKey).tag(appearance)
                        }
                    }
                } header: {
                    Text("settings_appearance_section")
                }

                Section {
                    Picker("settings_language_title", selection: languageBinding) {
                        ForEach(AppLanguage.allCases) { language in
                            Text(language.titleKey).tag(language)
                        }
                    }
                } header: {
                    Text("settings_language_section")
                }

                Section {
                    LabeledContent("settings_backend_url_label") {
                        Text(verbatim: sessionStore.currentSession?.backendURL.absoluteString ?? services.preferences.backendURL)
                            .multilineTextAlignment(.trailing)
                            .fixedSize(horizontal: false, vertical: true)
                    }

                    LabeledContent("settings_username_label") {
                        Text(verbatim: sessionStore.currentSession?.username ?? services.preferences.lastUsername)
                            .fixedSize(horizontal: false, vertical: true)
                    }
                } header: {
                    Text("settings_connection_section")
                }

                Section {
                    Text("settings_billing_summary")
                        .fixedSize(horizontal: false, vertical: true)
                    Text("settings_billing_source_builds")
                        .font(.footnote)
                        .foregroundStyle(.secondary)
                        .fixedSize(horizontal: false, vertical: true)
                } header: {
                    Text("settings_billing_section")
                } footer: {
                    Text("settings_billing_footer")
                }

                Section {
                    NavigationLink("settings_legal_entry") {
                        LegalPrivacyView()
                    }
                    .accessibilityHint(Text("settings_legal_entry_hint"))
                } header: {
                    Text("settings_legal_section")
                }

                if sessionStore.currentSession?.role == .admin {
                    Section {
                        Text(LocalizedStringKey(notificationCoordinator.adminAlertStrategySummaryKey))
                            .fixedSize(horizontal: false, vertical: true)
                        LabeledContent("settings_notifications_status_label") {
                            Text(LocalizedStringKey(notificationCoordinator.notificationStatusKey))
                                .multilineTextAlignment(.trailing)
                                .fixedSize(horizontal: false, vertical: true)
                        }

                        if let actionTitleKey = notificationCoordinator.settingsActionTitleKey {
                            Button(actionTitleKey) {
                                Task {
                                    await notificationCoordinator.handleSettingsAction()
                                }
                            }
                            .accessibilityHint(Text("settings_notifications_action_hint"))
                        }
                    } header: {
                        Text("settings_notifications_section")
                    }
                }

                Section {
                    Button("settings_logout_button", role: .destructive) {
                        sessionStore.logout()
                    }
                    .accessibilityHint(Text("settings_logout_hint"))
                }
            }
            .navigationTitle("settings_title")
            .task {
                await notificationCoordinator.refreshStatus()
            }
        }
    }

    private var appearanceBinding: Binding<AppAppearance> {
        Binding(
            get: { settingsStore.appearance },
            set: { settingsStore.updateAppearance($0) }
        )
    }

    private var languageBinding: Binding<AppLanguage> {
        Binding(
            get: { settingsStore.language },
            set: { settingsStore.updateLanguage($0) }
        )
    }
}
