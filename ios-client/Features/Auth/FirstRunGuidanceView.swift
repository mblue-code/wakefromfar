import SwiftUI

struct FirstRunGuidanceView: View {
    @ObservedObject var settingsStore: SettingsStore

    var body: some View {
        NavigationStack {
            ScrollView {
                VStack(alignment: .leading, spacing: 24) {
                    AuthBrandHeaderView(subtitleKey: "first_run_body")

                    VStack(alignment: .leading, spacing: 10) {
                        Text("first_run_title")
                            .font(.title2.weight(.semibold))
                            .accessibilityAddTraits(.isHeader)
                    }

                    VStack(alignment: .leading, spacing: 14) {
                        GuidanceRow(systemImage: "server.rack", textKey: "first_run_rule_admin_setup")
                        GuidanceRow(systemImage: "person.crop.rectangle", textKey: "first_run_rule_credentials")
                        GuidanceRow(systemImage: "lock.shield", textKey: "first_run_rule_private_network")
                    }
                    .padding(18)
                    .background(.thinMaterial, in: RoundedRectangle(cornerRadius: 20, style: .continuous))

                    Button {
                        settingsStore.acknowledgeFirstRunGuidance()
                    } label: {
                        HStack {
                            Spacer()
                            Text("first_run_continue")
                                .fontWeight(.semibold)
                            Spacer()
                        }
                        .padding(.vertical, 14)
                    }
                    .buttonStyle(.borderedProminent)
                    .accessibilityHint(Text("first_run_continue_hint"))
                }
                .padding(24)
            }
            .appInlineNavigationBarTitle()
        }
    }
}

private struct GuidanceRow: View {
    let systemImage: String
    let textKey: LocalizedStringKey

    var body: some View {
        HStack(alignment: .top, spacing: 12) {
            Image(systemName: systemImage)
                .foregroundStyle(.tint)
                .padding(.top, 2)
                .accessibilityHidden(true)

            Text(textKey)
                .font(.body)
                .fixedSize(horizontal: false, vertical: true)
        }
        .accessibilityElement(children: .combine)
    }
}
