import Foundation

@MainActor
final class LoginViewModel: ObservableObject {
    @Published var backendURL: String {
        didSet {
            preferences.backendURL = backendURL
            errorMessage = nil
        }
    }

    @Published var username: String {
        didSet {
            preferences.lastUsername = username
            errorMessage = nil
        }
    }

    @Published var password: String = "" {
        didSet {
            errorMessage = nil
        }
    }

    @Published private(set) var isLoading = false
    @Published private(set) var errorMessage: AppMessage?

    private let sessionStore: SessionStore
    private let preferences: AppPreferences

    init(sessionStore: SessionStore, preferences: AppPreferences) {
        self.sessionStore = sessionStore
        self.preferences = preferences
        backendURL = preferences.backendURL.isEmpty ? AppPreferences.defaultBackendURL : preferences.backendURL
        username = preferences.lastUsername
        errorMessage = sessionStore.authMessageSnapshot()
    }

    var isLoginDisabled: Bool {
        isLoading ||
        backendURL.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty ||
        username.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty ||
        password.isEmpty
    }

    func login() async {
        guard !backendURL.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty,
              !username.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty,
              !password.isEmpty else {
            errorMessage = .localized("login_error_required_fields")
            return
        }

        isLoading = true
        defer { isLoading = false }

        do {
            try await sessionStore.login(
                backendURLString: backendURL,
                username: username,
                password: password
            )
            password = ""
        } catch let error as APIClientError {
            if case .invalidBaseURL = error {
                errorMessage = .localized("login_error_invalid_url")
            } else {
                errorMessage = .verbatim(error.localizedDescription)
            }
        } catch {
            errorMessage = .verbatim(error.localizedDescription)
        }
    }

    func consumeAuthMessageIfNeeded() {
        guard errorMessage == sessionStore.authMessageSnapshot() else {
            return
        }
        errorMessage = sessionStore.consumeAuthMessage()
    }
}
