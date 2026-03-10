import SwiftUI

extension View {
    @ViewBuilder
    func appTextFieldChrome() -> some View {
        #if os(iOS)
        self
            .padding(14)
            .background(
                Color(uiColor: .secondarySystemBackground),
                in: RoundedRectangle(cornerRadius: 14, style: .continuous)
            )
        #else
        self
            .padding(14)
            .background(
                Color.secondary.opacity(0.12),
                in: RoundedRectangle(cornerRadius: 14, style: .continuous)
            )
        #endif
    }

    @ViewBuilder
    func appURLInputTraits() -> some View {
        #if os(iOS)
        self
            .textInputAutocapitalization(.never)
            .keyboardType(.URL)
            .autocorrectionDisabled()
            .textContentType(.URL)
        #else
        self
        #endif
    }

    @ViewBuilder
    func appUsernameInputTraits() -> some View {
        #if os(iOS)
        self
            .textInputAutocapitalization(.never)
            .autocorrectionDisabled()
            .textContentType(.username)
        #else
        self
        #endif
    }

    @ViewBuilder
    func appPasswordInputTraits() -> some View {
        #if os(iOS)
        self.textContentType(.password)
        #else
        self
        #endif
    }

    @ViewBuilder
    func appInlineNavigationBarTitle() -> some View {
        #if os(iOS)
        self.navigationBarTitleDisplayMode(.inline)
        #else
        self
        #endif
    }
}

struct AuthBrandHeaderView: View {
    let subtitleKey: LocalizedStringKey

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            Image("BrandMark")
                .resizable()
                .interpolation(.high)
                .frame(width: 68, height: 68)
                .clipShape(RoundedRectangle(cornerRadius: 18, style: .continuous))
                .shadow(color: .black.opacity(0.12), radius: 12, y: 6)
                .accessibilityHidden(true)

            Text("app_title")
                .font(.system(size: 38, weight: .bold, design: .rounded))
                .lineLimit(1)
                .minimumScaleFactor(0.8)
                .accessibilityAddTraits(.isHeader)

            Text(subtitleKey)
                .font(.title3)
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
        }
        .padding(.top, 16)
    }
}
