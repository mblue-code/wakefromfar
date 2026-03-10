import CryptoKit
import DeviceCheck
import Foundation
import UIKit

struct UserSession: Equatable {
    let token: String
    let backendURL: URL
    let username: String
    let role: UserRole?
    let installationID: String
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
    private let appAttestCoordinator: AppAttestCoordinator

    init(apiClient: APIClient, tokenStore: KeychainStore, preferences: AppPreferences) {
        self.apiClient = apiClient
        self.tokenStore = tokenStore
        self.preferences = preferences
        self.appAttestCoordinator = AppAttestCoordinator(apiClient: apiClient, tokenStore: tokenStore)
        restore()
    }

    var isAuthenticated: Bool {
        currentSession != nil
    }

    func login(backendURLString: String, username: String, password: String) async throws {
        let baseURL = try apiClient.normalizedBaseURL(from: backendURLString)
        let normalizedUsername = username.trimmingCharacters(in: .whitespacesAndNewlines)
        let proof = await appAttestCoordinator.prepareLoginProof(baseURL: baseURL, username: normalizedUsername)
        let response = try await apiClient.login(
            baseURL: baseURL,
            username: normalizedUsername,
            password: password,
            installationID: proof.installationID,
            proofTicket: proof.proofTicket
        )

        try tokenStore.writeString(response.token, account: tokenAccount)
        preferences.backendURL = baseURL.absoluteString
        preferences.lastUsername = normalizedUsername

        currentSession = UserSession(
            token: response.token,
            backendURL: baseURL,
            username: preferences.lastUsername,
            role: claimsDecoder.role(from: response.token),
            installationID: proof.installationID
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
            role: claimsDecoder.role(from: token),
            installationID: (try? appAttestCoordinator.installationID()) ?? ""
        )
    }
}

private struct PreparedLoginProof {
    let installationID: String
    let proofTicket: String?
}

private final class AppAttestCoordinator {
    private let apiClient: APIClient
    private let tokenStore: KeychainStore
    private let service = DCAppAttestService.shared
    private let installationIDAccount = "app_installation_id"
    private let keyIDAccount = "app_attest_key_id"
    private let enrolledAccount = "app_attest_enrolled"

    init(apiClient: APIClient, tokenStore: KeychainStore) {
        self.apiClient = apiClient
        self.tokenStore = tokenStore
    }

    func installationID() throws -> String {
        if let existing = try tokenStore.readString(account: installationIDAccount),
           !existing.isEmpty {
            return existing
        }
        let generated = UUID().uuidString.lowercased()
        try tokenStore.writeString(generated, account: installationIDAccount)
        return generated
    }

    func prepareLoginProof(baseURL: URL, username: String) async -> PreparedLoginProof {
        let installationID = (try? installationID()) ?? UUID().uuidString.lowercased()
        guard service.isSupported else {
            return PreparedLoginProof(installationID: installationID, proofTicket: nil)
        }
        do {
            let keyID = try await ensureAttestedKey(baseURL: baseURL, installationID: installationID)
            let challenge = try await apiClient.requestAppProofChallenge(
                baseURL: baseURL,
                platform: "ios",
                purpose: "login",
                installationID: installationID,
                username: username,
                appVersion: appVersion(),
                osVersion: osVersion()
            )
            let clientDataHash = appProofClientDataHash(
                purpose: challenge.purpose,
                challengeID: challenge.challengeID,
                challenge: challenge.challenge,
                installationID: installationID,
                username: username
            )
            let assertion = try await generateAssertion(keyID: keyID, clientDataHash: clientDataHash)
            let verify = try await apiClient.verifyIOSAppProof(
                baseURL: baseURL,
                mode: "assert",
                challengeID: challenge.challengeID,
                installationID: installationID,
                keyID: keyID,
                assertionObject: assertion.base64EncodedString(),
                appVersion: appVersion(),
                osVersion: osVersion()
            )
            return PreparedLoginProof(installationID: installationID, proofTicket: verify.proofTicket)
        } catch {
            return PreparedLoginProof(installationID: installationID, proofTicket: nil)
        }
    }

    private func ensureAttestedKey(baseURL: URL, installationID: String) async throws -> String {
        if let existing = try tokenStore.readString(account: keyIDAccount),
           !existing.isEmpty,
           isEnrolled() {
            return existing
        }

        let keyID = try await generateKeyID()
        let challenge = try await apiClient.requestAppProofChallenge(
            baseURL: baseURL,
            platform: "ios",
            purpose: "enroll",
            installationID: installationID,
            appVersion: appVersion(),
            osVersion: osVersion()
        )
        let clientDataHash = appProofClientDataHash(
            purpose: challenge.purpose,
            challengeID: challenge.challengeID,
            challenge: challenge.challenge,
            installationID: installationID,
            username: nil
        )
        let attestationObject = try await attestKey(keyID: keyID, clientDataHash: clientDataHash)
        _ = try await apiClient.verifyIOSAppProof(
            baseURL: baseURL,
            mode: "attest",
            challengeID: challenge.challengeID,
            installationID: installationID,
            keyID: keyID,
            attestationObject: attestationObject.base64EncodedString(),
            appVersion: appVersion(),
            osVersion: osVersion()
        )
        try tokenStore.writeString(keyID, account: keyIDAccount)
        try tokenStore.writeString("1", account: enrolledAccount)
        return keyID
    }

    private func isEnrolled() -> Bool {
        (try? tokenStore.readString(account: enrolledAccount)) == "1"
    }

    private func appVersion() -> String {
        Bundle.main.infoDictionary?["CFBundleShortVersionString"] as? String ?? "unknown"
    }

    private func osVersion() -> String {
        "ios-\(UIDevice.current.systemVersion)"
    }

    private func generateKeyID() async throws -> String {
        let keyID: String = try await withCheckedThrowingContinuation { continuation in
            service.generateKey { keyID, error in
                if let error {
                    continuation.resume(throwing: error)
                    return
                }
                guard let keyID else {
                    continuation.resume(throwing: APIClientError.invalidResponse)
                    return
                }
                continuation.resume(returning: keyID)
            }
        }
        try tokenStore.writeString(keyID, account: keyIDAccount)
        return keyID
    }

    private func attestKey(keyID: String, clientDataHash: Data) async throws -> Data {
        try await withCheckedThrowingContinuation { continuation in
            service.attestKey(keyID, clientDataHash: clientDataHash) { attestationObject, error in
                if let error {
                    continuation.resume(throwing: error)
                    return
                }
                guard let attestationObject else {
                    continuation.resume(throwing: APIClientError.invalidResponse)
                    return
                }
                continuation.resume(returning: attestationObject)
            }
        }
    }

    private func generateAssertion(keyID: String, clientDataHash: Data) async throws -> Data {
        try await withCheckedThrowingContinuation { continuation in
            service.generateAssertion(keyID, clientDataHash: clientDataHash) { assertion, error in
                if let error {
                    continuation.resume(throwing: error)
                    return
                }
                guard let assertion else {
                    continuation.resume(throwing: APIClientError.invalidResponse)
                    return
                }
                continuation.resume(returning: assertion)
            }
        }
    }
}

private func appProofClientDataHash(
    purpose: String,
    challengeID: String,
    challenge: String,
    installationID: String,
    username: String?
) -> Data {
    let canonicalJSON = appProofCanonicalJSON(
        purpose: purpose,
        challengeID: challengeID,
        challenge: challenge,
        installationID: installationID,
        username: username
    )
    return Data(SHA256.hash(data: Data(canonicalJSON.utf8)))
}

private func appProofCanonicalJSON(
    purpose: String,
    challengeID: String,
    challenge: String,
    installationID: String,
    username: String?
) -> String {
    var pieces = [
        "\"purpose\":\"\(jsonEscaped(purpose))\"",
        "\"challenge_id\":\"\(jsonEscaped(challengeID))\"",
        "\"challenge\":\"\(jsonEscaped(challenge))\"",
        "\"installation_id\":\"\(jsonEscaped(installationID))\""
    ]
    if let username, !username.isEmpty {
        pieces.append("\"username\":\"\(jsonEscaped(username))\"")
    }
    return "{\(pieces.joined(separator: ","))}"
}

private func jsonEscaped(_ value: String) -> String {
    var result = ""
    result.reserveCapacity(value.count + 8)
    for scalar in value.unicodeScalars {
        switch scalar {
        case "\"":
            result += "\\\""
        case "\\":
            result += "\\\\"
        case "\u{08}":
            result += "\\b"
        case "\u{0C}":
            result += "\\f"
        case "\n":
            result += "\\n"
        case "\r":
            result += "\\r"
        case "\t":
            result += "\\t"
        default:
            if scalar.value < 0x20 {
                result += String(format: "\\u%04x", scalar.value)
            } else {
                result.unicodeScalars.append(scalar)
            }
        }
    }
    return result
}
