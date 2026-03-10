import SwiftUI

struct LegalPrivacyView: View {
    var body: some View {
        List {
            Section {
                Text("legal_intro")
                    .fixedSize(horizontal: false, vertical: true)
            } header: {
                Text("legal_overview_title")
            }

            Section {
                Text("legal_privacy_item_backend")
                    .fixedSize(horizontal: false, vertical: true)
                Text("legal_privacy_item_keychain")
                    .fixedSize(horizontal: false, vertical: true)
                Text("legal_privacy_item_defaults")
                    .fixedSize(horizontal: false, vertical: true)
                Text("legal_privacy_item_notifications")
                    .fixedSize(horizontal: false, vertical: true)
                Text("legal_privacy_item_billing")
                    .fixedSize(horizontal: false, vertical: true)
                Text("legal_privacy_item_network")
                    .fixedSize(horizontal: false, vertical: true)
            } header: {
                Text("legal_privacy_title")
            }

            Section {
                Text("legal_compliance_item_no_invites")
                    .fixedSize(horizontal: false, vertical: true)
                Text("legal_compliance_item_apns")
                    .fixedSize(horizontal: false, vertical: true)
                Text("legal_compliance_item_permissions")
                    .fixedSize(horizontal: false, vertical: true)
                Text("legal_compliance_item_background")
                    .fixedSize(horizontal: false, vertical: true)
                Text("legal_compliance_item_app_store_distribution")
                    .fixedSize(horizontal: false, vertical: true)
            } header: {
                Text("legal_compliance_title")
            }

            Section {
                Text("legal_open_source_item_repo")
                    .fixedSize(horizontal: false, vertical: true)
                Text("legal_open_source_item_notices")
                    .fixedSize(horizontal: false, vertical: true)
                Text("legal_open_source_item_ios_foundation")
                    .fixedSize(horizontal: false, vertical: true)
                Text("legal_open_source_item_distribution")
                    .fixedSize(horizontal: false, vertical: true)
            } header: {
                Text("legal_open_source_title")
            }
        }
        .navigationTitle("legal_title")
        .appInlineNavigationBarTitle()
    }
}
