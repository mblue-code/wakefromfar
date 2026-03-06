import Foundation

struct UserSession: Equatable {
    let token: String
    let backendURL: URL
    let username: String
    let role: UserRole?
}

@MainActor
final class SessionStore: ObservableObject {
    @Published private(set) var currentSession: UserSession?
    @Published private(set) var authMessage: AppMessage?

    private let apiClient: APIClient
    private let tokenStore: KeychainStore
    private let preferences: AppPreferences
    private let claimsDecoder = JWTClaimsDecoder()
    private let tokenAccount = "auth_token"

    init(apiClient: APIClient, tokenStore: KeychainStore, preferences: AppPreferences) {
        self.apiClient = apiClient
        self.tokenStore = tokenStore
        self.preferences = preferences
        restore()
    }

    var isAuthenticated: Bool {
        currentSession != nil
    }

    func login(backendURLString: String, username: String, password: String) async throws {
        let baseURL = try apiClient.normalizedBaseURL(from: backendURLString)
        let response = try await apiClient.login(
            baseURL: baseURL,
            username: username.trimmingCharacters(in: .whitespacesAndNewlines),
            password: password
        )

        try tokenStore.writeString(response.token, account: tokenAccount)
        preferences.backendURL = baseURL.absoluteString
        preferences.lastUsername = username.trimmingCharacters(in: .whitespacesAndNewlines)

        currentSession = UserSession(
            token: response.token,
            backendURL: baseURL,
            username: preferences.lastUsername,
            role: claimsDecoder.role(from: response.token)
        )
        authMessage = nil
    }

    func logout(message: AppMessage? = nil) {
        do {
            try tokenStore.deleteValue(account: tokenAccount)
        } catch {
            assertionFailure("Failed to clear auth token: \(error)")
        }
        currentSession = nil
        authMessage = message
    }

    func authMessageSnapshot() -> AppMessage? {
        authMessage
    }

    func consumeAuthMessage() -> AppMessage? {
        let message = authMessage
        authMessage = nil
        return message
    }

    private func restore() {
        guard !preferences.backendURL.isEmpty,
              let baseURL = try? apiClient.normalizedBaseURL(from: preferences.backendURL) else {
            currentSession = nil
            return
        }

        let storedToken = try? tokenStore.readString(account: tokenAccount)
        guard let token = storedToken ?? nil,
              !token.isEmpty else {
            currentSession = nil
            return
        }

        currentSession = UserSession(
            token: token,
            backendURL: baseURL,
            username: preferences.lastUsername,
            role: claimsDecoder.role(from: token)
        )
    }
}
