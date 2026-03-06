import Foundation

enum APIClientError: LocalizedError {
    case invalidBaseURL
    case invalidResponse
    case server(statusCode: Int, message: String)
    case decoding(underlying: Error)

    var errorDescription: String? {
        switch self {
        case .invalidBaseURL:
            return "Invalid backend URL."
        case .invalidResponse:
            return "Unexpected server response."
        case .server(_, let message):
            return message
        case .decoding:
            return "The server response could not be decoded."
        }
    }

    var statusCode: Int? {
        guard case .server(let statusCode, _) = self else {
            return nil
        }
        return statusCode
    }
}

final class APIClient {
    private let session: URLSession
    private let decoder: JSONDecoder
    private let encoder: JSONEncoder

    init(session: URLSession = .shared) {
        self.session = session

        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
        self.decoder = decoder

        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .iso8601
        self.encoder = encoder
    }

    func login(baseURL: URL, username: String, password: String) async throws -> LoginResponse {
        try await send(
            endpoint: .init(
                path: "/auth/login",
                method: "POST",
                body: try encoder.encode(LoginRequest(username: username, password: password))
            ),
            baseURL: baseURL,
            token: nil
        )
    }

    func fetchMyDevices(baseURL: URL, token: String) async throws -> [MyDevice] {
        try await send(
            endpoint: .init(path: "/me/devices", method: "GET"),
            baseURL: baseURL,
            token: token
        )
    }

    func wakeDevice(hostID: String, baseURL: URL, token: String) async throws -> MeWakeResponse {
        try await send(
            endpoint: .init(path: "/me/devices/\(hostID)/wake", method: "POST"),
            baseURL: baseURL,
            token: token
        )
    }

    func requestShutdownPoke(
        hostID: String,
        message: String?,
        baseURL: URL,
        token: String
    ) async throws -> ShutdownPoke {
        try await send(
            endpoint: .init(
                path: "/me/devices/\(hostID)/shutdown-poke",
                method: "POST",
                body: try encoder.encode(ShutdownPokeCreateRequest(message: message?.isEmpty == true ? nil : message))
            ),
            baseURL: baseURL,
            token: token
        )
    }

    func registerAPNSDevice(
        installationID: String,
        token deviceToken: String,
        appBundleID: String,
        environment: APNSEnvironment,
        baseURL: URL,
        authToken: String
    ) async throws -> NotificationDeviceRegistration {
        try await send(
            endpoint: .init(
                path: "/me/notification-devices/apns",
                method: "POST",
                body: try encoder.encode(
                    APNSDeviceRegistrationRequest(
                        installationID: installationID,
                        token: deviceToken,
                        appBundleID: appBundleID,
                        environment: environment
                    )
                )
            ),
            baseURL: baseURL,
            token: authToken
        )
    }

    func deleteAPNSDevice(
        installationID: String,
        baseURL: URL,
        authToken: String
    ) async throws {
        try await sendWithoutResponse(
            endpoint: .init(
                path: "/me/notification-devices/apns/\(installationID)",
                method: "DELETE"
            ),
            baseURL: baseURL,
            token: authToken
        )
    }

    func fetchAdminActivityEvents(
        baseURL: URL,
        token: String,
        cursor: Int?,
        limit: Int,
        typeFilter: String?
    ) async throws -> [ActivityEvent] {
        var queryItems = [URLQueryItem(name: "limit", value: String(limit))]
        if let cursor {
            queryItems.append(URLQueryItem(name: "cursor", value: String(cursor)))
        }
        if let typeFilter, !typeFilter.isEmpty {
            queryItems.append(URLQueryItem(name: "type", value: typeFilter))
        }

        return try await send(
            endpoint: .init(
                path: "/admin/mobile/events",
                method: "GET",
                queryItems: queryItems
            ),
            baseURL: baseURL,
            token: token
        )
    }

    func markShutdownPokeSeen(
        pokeID: String,
        baseURL: URL,
        token: String
    ) async throws -> ShutdownPoke {
        try await send(
            endpoint: .init(
                path: "/admin/shutdown-pokes/\(pokeID)/seen",
                method: "POST"
            ),
            baseURL: baseURL,
            token: token
        )
    }

    func markShutdownPokeResolved(
        pokeID: String,
        baseURL: URL,
        token: String
    ) async throws -> ShutdownPoke {
        try await send(
            endpoint: .init(
                path: "/admin/shutdown-pokes/\(pokeID)/resolve",
                method: "POST"
            ),
            baseURL: baseURL,
            token: token
        )
    }

    func normalizedBaseURL(from rawValue: String) throws -> URL {
        let trimmed = rawValue.trimmingCharacters(in: .whitespacesAndNewlines)
        guard var components = URLComponents(string: trimmed),
              let scheme = components.scheme?.lowercased(),
              ["http", "https"].contains(scheme),
              components.host != nil else {
            throw APIClientError.invalidBaseURL
        }
        if components.path.hasSuffix("/") {
            components.path.removeLast()
        }
        guard let url = components.url else {
            throw APIClientError.invalidBaseURL
        }
        return url
    }

    private func send<Response: Decodable>(
        endpoint: Endpoint,
        baseURL: URL,
        token: String?
    ) async throws -> Response {
        let request = try buildRequest(endpoint: endpoint, baseURL: baseURL, token: token)
        let (data, response) = try await session.data(for: request)

        guard let httpResponse = response as? HTTPURLResponse else {
            throw APIClientError.invalidResponse
        }

        guard (200..<300).contains(httpResponse.statusCode) else {
            throw APIClientError.server(
                statusCode: httpResponse.statusCode,
                message: decodeErrorMessage(from: data, statusCode: httpResponse.statusCode)
            )
        }

        do {
            return try decoder.decode(Response.self, from: data)
        } catch {
            throw APIClientError.decoding(underlying: error)
        }
    }

    private func sendWithoutResponse(
        endpoint: Endpoint,
        baseURL: URL,
        token: String?
    ) async throws {
        let request = try buildRequest(endpoint: endpoint, baseURL: baseURL, token: token)
        let (_, response) = try await session.data(for: request)

        guard let httpResponse = response as? HTTPURLResponse else {
            throw APIClientError.invalidResponse
        }

        guard (200..<300).contains(httpResponse.statusCode) else {
            throw APIClientError.server(
                statusCode: httpResponse.statusCode,
                message: HTTPURLResponse.localizedString(forStatusCode: httpResponse.statusCode)
            )
        }
    }

    private func buildRequest(endpoint: Endpoint, baseURL: URL, token: String?) throws -> URLRequest {
        guard var components = URLComponents(url: baseURL, resolvingAgainstBaseURL: false) else {
            throw APIClientError.invalidBaseURL
        }

        let basePath = components.path.hasSuffix("/") ? String(components.path.dropLast()) : components.path
        components.path = basePath + endpoint.path
        if !endpoint.queryItems.isEmpty {
            components.queryItems = endpoint.queryItems
        }

        guard let url = components.url else {
            throw APIClientError.invalidBaseURL
        }

        var request = URLRequest(url: url)
        request.httpMethod = endpoint.method
        request.httpBody = endpoint.body

        if endpoint.body != nil {
            request.setValue("application/json; charset=utf-8", forHTTPHeaderField: "Content-Type")
        }
        if let token {
            request.setValue("Bearer \(token)", forHTTPHeaderField: "Authorization")
        }

        return request
    }

    private func decodeErrorMessage(from data: Data, statusCode: Int) -> String {
        if let payload = try? decoder.decode(APIErrorEnvelope.self, from: data),
           let detail = payload.detail,
           !detail.isEmpty {
            return detail
        }
        if let raw = String(data: data, encoding: .utf8)?
            .trimmingCharacters(in: .whitespacesAndNewlines),
           !raw.isEmpty {
            return raw
        }
        return HTTPURLResponse.localizedString(forStatusCode: statusCode)
    }
}

private struct Endpoint {
    let path: String
    let method: String
    var queryItems: [URLQueryItem] = []
    var body: Data? = nil
}

private struct APIErrorEnvelope: Decodable {
    let detail: String?
}
