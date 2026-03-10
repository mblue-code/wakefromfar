import Foundation
import Security

enum KeychainStoreError: LocalizedError {
    case unexpectedStatus(OSStatus)
    case invalidData

    var errorDescription: String? {
        switch self {
        case .unexpectedStatus(let status):
            return SecCopyErrorMessageString(status, nil) as String? ?? "Keychain error \(status)"
        case .invalidData:
            return "Keychain returned unreadable data."
        }
    }
}

final class KeychainStore {
    private let service: String
    #if targetEnvironment(simulator)
    private let simulatorFallbackDefaults = UserDefaults.standard
    #endif

    init(service: String) {
        self.service = service
    }

    func readString(account: String) throws -> String? {
        var query = baseQuery(account: account)
        query[kSecReturnData as String] = true
        query[kSecMatchLimit as String] = kSecMatchLimitOne

        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)
        switch status {
        case errSecSuccess:
            guard let data = item as? Data,
                  let string = String(data: data, encoding: .utf8) else {
                throw KeychainStoreError.invalidData
            }
            return string
        case errSecItemNotFound:
            return nil
        #if targetEnvironment(simulator)
        case errSecMissingEntitlement:
            return simulatorFallbackDefaults.string(forKey: simulatorFallbackKey(account: account))
        #endif
        default:
            throw KeychainStoreError.unexpectedStatus(status)
        }
    }

    func writeString(_ value: String, account: String) throws {
        let data = Data(value.utf8)
        let query = baseQuery(account: account)

        let attributesToUpdate: [String: Any] = [
            kSecValueData as String: data,
        ]
        let updateStatus = SecItemUpdate(query as CFDictionary, attributesToUpdate as CFDictionary)
        switch updateStatus {
        case errSecSuccess:
            return
        case errSecItemNotFound:
            var addQuery = query
            addQuery[kSecValueData as String] = data
            let addStatus = SecItemAdd(addQuery as CFDictionary, nil)
            guard addStatus == errSecSuccess else {
                throw KeychainStoreError.unexpectedStatus(addStatus)
            }
        #if targetEnvironment(simulator)
        case errSecMissingEntitlement:
            simulatorFallbackDefaults.set(value, forKey: simulatorFallbackKey(account: account))
        default:
            throw KeychainStoreError.unexpectedStatus(updateStatus)
        #else
        default:
            throw KeychainStoreError.unexpectedStatus(updateStatus)
        #endif
        }
    }

    func deleteValue(account: String) throws {
        let status = SecItemDelete(baseQuery(account: account) as CFDictionary)
        #if targetEnvironment(simulator)
        if status == errSecMissingEntitlement {
            simulatorFallbackDefaults.removeObject(forKey: simulatorFallbackKey(account: account))
            return
        }
        #endif
        guard status == errSecSuccess || status == errSecItemNotFound else {
            throw KeychainStoreError.unexpectedStatus(status)
        }
    }

    private func baseQuery(account: String) -> [String: Any] {
        [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
            kSecAttrAccessible as String: kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
        ]
    }

    #if targetEnvironment(simulator)
    private func simulatorFallbackKey(account: String) -> String {
        "simulator_keychain_fallback_\(service)_\(account)"
    }
    #endif
}
