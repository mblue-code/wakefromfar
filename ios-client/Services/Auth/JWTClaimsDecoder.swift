import Foundation

enum UserRole: String {
    case admin
    case user
}

struct JWTClaimsDecoder {
    // JWT claims are read for local UX only. Backend authorization remains authoritative.
    func role(from token: String) -> UserRole? {
        let parts = token.split(separator: ".")
        guard parts.count > 1 else { return nil }
        let payloadSegment = String(parts[1])
        guard let data = decodeBase64URL(payloadSegment),
              let object = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
              let roleText = object["role"] as? String else {
            return nil
        }
        return UserRole(rawValue: roleText)
    }

    private func decodeBase64URL(_ value: String) -> Data? {
        var base64 = value
            .replacingOccurrences(of: "-", with: "+")
            .replacingOccurrences(of: "_", with: "/")
        let padding = 4 - (base64.count % 4)
        if padding < 4 {
            base64 += String(repeating: "=", count: padding)
        }
        return Data(base64Encoded: base64)
    }
}
