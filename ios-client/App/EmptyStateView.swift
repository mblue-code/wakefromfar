import SwiftUI

struct EmptyStateView: View {
    let systemImage: String
    let title: AppMessage
    let message: AppMessage
    var actionTitleKey: LocalizedStringKey?
    var action: (() -> Void)?

    var body: some View {
        VStack(spacing: 12) {
            Image(systemName: systemImage)
                .font(.system(size: 36, weight: .semibold))
                .foregroundStyle(.secondary)
                .accessibilityHidden(true)

            messageText(title)
                .font(.headline)
                .accessibilityAddTraits(.isHeader)

            messageText(message)
                .font(.subheadline)
                .foregroundStyle(.secondary)
                .multilineTextAlignment(.center)

            if let actionTitleKey, let action {
                Button(action: action) {
                    Text(actionTitleKey)
                }
                .buttonStyle(.borderedProminent)
                .padding(.top, 4)
            }
        }
        .frame(maxWidth: .infinity)
        .padding(.vertical, 40)
        .padding(.horizontal, 24)
        .accessibilityElement(children: .contain)
    }

    @ViewBuilder
    private func messageText(_ message: AppMessage) -> some View {
        switch message {
        case .localized(let key):
            Text(LocalizedStringKey(key))
        case .verbatim(let text):
            Text(verbatim: text)
        }
    }
}
