import SwiftUI

struct MessageBanner: View {
    let message: AppMessage
    let tint: Color

    var body: some View {
        HStack(alignment: .top, spacing: 12) {
            Image(systemName: "info.circle.fill")
                .foregroundStyle(tint)
                .accessibilityHidden(true)

            Group {
                switch message {
                case .localized(let key):
                    Text(LocalizedStringKey(key))
                case .verbatim(let text):
                    Text(verbatim: text)
                }
            }
            .font(.subheadline)
            .foregroundStyle(.primary)

            Spacer(minLength: 0)
        }
        .padding(12)
        .background(tint.opacity(0.12), in: RoundedRectangle(cornerRadius: 14, style: .continuous))
        .accessibilityElement(children: .combine)
    }
}
