import SwiftUI

struct LoginView: View {
    @StateObject private var viewModel: LoginViewModel
    @FocusState private var focusedField: Field?

    private enum Field {
        case backendURL
        case username
        case password
    }

    init(viewModel: LoginViewModel) {
        _viewModel = StateObject(wrappedValue: viewModel)
    }

    var body: some View {
        NavigationStack {
            ScrollView {
                VStack(alignment: .leading, spacing: 24) {
                    AuthBrandHeaderView(subtitleKey: "login_subtitle")

                    VStack(alignment: .leading, spacing: 12) {
                        Text("login_policy_title")
                            .font(.headline)

                        Text("login_policy_message")
                            .font(.subheadline)
                            .foregroundStyle(.secondary)

                        Text("login_network_message")
                            .font(.footnote)
                            .foregroundStyle(.secondary)
                    }
                    .padding(16)
                    .background(.thinMaterial, in: RoundedRectangle(cornerRadius: 18, style: .continuous))

                    if let errorMessage = viewModel.errorMessage {
                        MessageBanner(message: errorMessage, tint: .red)
                    }

                    VStack(alignment: .leading, spacing: 16) {
                        VStack(alignment: .leading, spacing: 8) {
                            Text("login_backend_url_label")
                                .font(.headline)

                            TextField("", text: $viewModel.backendURL, prompt: Text("login_backend_url_placeholder"))
                                .appURLInputTraits()
                                .appTextFieldChrome()
                                .focused($focusedField, equals: .backendURL)
                                .submitLabel(.next)
                                .accessibilityLabel(Text("login_backend_url_label"))
                                .accessibilityHint(Text("login_backend_url_hint"))
                                .onSubmit {
                                    focusedField = .username
                                }
                        }

                        VStack(alignment: .leading, spacing: 8) {
                            Text("login_username_label")
                                .font(.headline)

                            TextField("", text: $viewModel.username, prompt: Text("login_username_placeholder"))
                                .appUsernameInputTraits()
                                .appTextFieldChrome()
                                .focused($focusedField, equals: .username)
                                .submitLabel(.next)
                                .accessibilityLabel(Text("login_username_label"))
                                .onSubmit {
                                    focusedField = .password
                                }
                        }

                        VStack(alignment: .leading, spacing: 8) {
                            Text("login_password_label")
                                .font(.headline)

                            SecureField("", text: $viewModel.password, prompt: Text("login_password_placeholder"))
                                .appPasswordInputTraits()
                                .appTextFieldChrome()
                                .focused($focusedField, equals: .password)
                                .submitLabel(.go)
                                .accessibilityLabel(Text("login_password_label"))
                                .accessibilityHint(Text("login_password_hint"))
                                .onSubmit {
                                    Task {
                                        await viewModel.login()
                                    }
                                }
                        }
                    }

                    Button {
                        Task {
                            await viewModel.login()
                        }
                    } label: {
                        HStack {
                            Spacer()

                            if viewModel.isLoading {
                                ProgressView()
                                    .tint(.white)
                            } else {
                                Text("login_button")
                                    .fontWeight(.semibold)
                            }

                            Spacer()
                        }
                        .padding(.vertical, 14)
                    }
                    .buttonStyle(.borderedProminent)
                    .disabled(viewModel.isLoginDisabled)
                    .accessibilityHint(Text("login_button_hint"))

                    Text("login_footer_note")
                        .font(.footnote)
                        .foregroundStyle(.secondary)
                }
                .padding(24)
            }
            .appInlineNavigationBarTitle()
            .task {
                viewModel.consumeAuthMessageIfNeeded()
            }
        }
    }
}
