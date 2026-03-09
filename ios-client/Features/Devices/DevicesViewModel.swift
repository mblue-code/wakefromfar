import Foundation
import SwiftUI

@MainActor
final class DevicesViewModel: ObservableObject {
    @Published private(set) var devices: [MyDevice] = []
    @Published private(set) var deviceSections: [DeviceListSection] = []
    @Published private(set) var isLoading = false
    @Published private(set) var activeDeviceID: String?
    @Published private(set) var feedbackMessage: AppMessage?
    @Published private(set) var feedbackTint: Color = .blue
    @Published private(set) var loadErrorMessage: AppMessage?

    private let sessionStore: SessionStore
    private let apiClient: APIClient
    private var allVisibleDevices: [MyDevice] = []
    private var hasLoaded = false
    private var followUpRefreshTask: Task<Void, Never>?

    var hasLoadedOnce: Bool {
        hasLoaded
    }

    init(
        sessionStore: SessionStore,
        apiClient: APIClient
    ) {
        self.sessionStore = sessionStore
        self.apiClient = apiClient
    }

    func refresh(force: Bool) async {
        guard force || !hasLoaded else { return }
        guard let session = sessionStore.currentSession else {
            devices = []
            allVisibleDevices = []
            deviceSections = []
            return
        }

        isLoading = true
        loadErrorMessage = nil
        defer {
            isLoading = false
            hasLoaded = true
        }

        do {
            allVisibleDevices = sortDevicesForPresentation(try await apiClient.fetchMyDevices(
                baseURL: session.backendURL,
                token: session.token,
                installationID: session.installationID
            ))
            guard isCurrentSession(session) else { return }
            applyDevicePresentation(allVisibleDevices)
            loadErrorMessage = nil
        } catch {
            guard isCurrentSession(session) else { return }
            if handleAuthenticationError(session: session, error: error) {
                return
            }
            let renderedError = render(error: error, fallbackKey: "devices_error_generic")
            if devices.isEmpty {
                loadErrorMessage = renderedError
            } else {
                feedbackMessage = renderedError
                feedbackTint = .red
            }
        }
    }

    func toggleFavorite(device: MyDevice) async {
        guard let session = sessionStore.currentSession else { return }

        activeDeviceID = device.id
        defer { activeDeviceID = nil }

        do {
            let updatedDevice = try await apiClient.updateDevicePreferences(
                hostID: device.id,
                isFavorite: !device.isFavorite,
                baseURL: session.backendURL,
                token: session.token,
                installationID: session.installationID
            )
            guard isCurrentSession(session) else { return }
            allVisibleDevices = sortDevicesForPresentation(
                allVisibleDevices.map { existing in
                    existing.id == updatedDevice.id ? updatedDevice : existing
                }
            )
            applyDevicePresentation(allVisibleDevices)
        } catch {
            guard isCurrentSession(session) else { return }
            if handleAuthenticationError(session: session, error: error) {
                return
            }
            feedbackMessage = render(error: error, fallbackKey: "devices_preferences_error_generic")
            feedbackTint = .red
        }
    }

    func wake(device: MyDevice) async {
        guard let session = sessionStore.currentSession else { return }
        guard device.canWake else {
            feedbackMessage = .localized("devices_wake_not_permitted")
            feedbackTint = .orange
            return
        }

        activeDeviceID = device.id
        defer { activeDeviceID = nil }

        do {
            let response = try await apiClient.wakeDevice(
                hostID: device.id,
                baseURL: session.backendURL,
                token: session.token,
                installationID: session.installationID
            )
            guard isCurrentSession(session) else { return }
            switch response.result {
            case .alreadyOn:
                feedbackMessage = .localized("devices_wake_result_already_on")
                feedbackTint = .orange
            case .sent:
                if let sentTo = response.sentTo, !sentTo.isEmpty {
                    feedbackMessage = .verbatim(
                        String(
                            format: NSLocalizedString("devices_wake_result_sent_target_format", comment: ""),
                            sentTo
                        )
                    )
                } else {
                    feedbackMessage = .localized("devices_wake_result_sent")
                }
                feedbackTint = .green
                scheduleFollowUpRefresh()
            case .failed:
                let detail = (response.errorDetail ?? response.message).trimmingCharacters(in: .whitespacesAndNewlines)
                if detail.isEmpty {
                    feedbackMessage = .localized("devices_wake_result_failed")
                } else {
                    feedbackMessage = .verbatim(
                        String(
                            format: NSLocalizedString("devices_wake_result_failed_detail_format", comment: ""),
                            detail
                        )
                    )
                }
                feedbackTint = .red
            }
            await refresh(force: true)
        } catch {
            guard isCurrentSession(session) else { return }
            if handleAuthenticationError(session: session, error: error) {
                return
            }
            if isForbidden(error) {
                feedbackMessage = .localized("devices_wake_not_permitted")
                feedbackTint = .orange
            } else {
                feedbackMessage = render(error: error, fallbackKey: "devices_wake_error_generic")
                feedbackTint = .red
            }
        }
    }

    func requestShutdown(device: MyDevice, note: String) async {
        guard let session = sessionStore.currentSession else { return }
        guard device.canRequestShutdown else {
            feedbackMessage = .localized("devices_shutdown_not_permitted")
            feedbackTint = .orange
            return
        }
        let trimmedNote = note.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !isShutdownNoteTooLong(trimmedNote) else {
            feedbackMessage = .localized("devices_shutdown_note_limit")
            feedbackTint = .red
            return
        }

        activeDeviceID = device.id
        defer { activeDeviceID = nil }

        do {
            _ = try await apiClient.requestShutdownPoke(
                hostID: device.id,
                message: trimmedNote,
                baseURL: session.backendURL,
                token: session.token,
                installationID: session.installationID
            )
            guard isCurrentSession(session) else { return }
            feedbackMessage = .localized("devices_shutdown_result_success")
            feedbackTint = .green
        } catch {
            guard isCurrentSession(session) else { return }
            if handleAuthenticationError(session: session, error: error) {
                return
            }
            if isForbidden(error) {
                feedbackMessage = .localized("devices_shutdown_not_permitted")
                feedbackTint = .orange
            } else {
                feedbackMessage = render(error: error, fallbackKey: "devices_shutdown_error_generic")
                feedbackTint = .red
            }
        }
    }

    func isShutdownNoteTooLong(_ value: String) -> Bool {
        value.count > 280
    }

    private func scheduleFollowUpRefresh() {
        followUpRefreshTask?.cancel()
        followUpRefreshTask = Task { [weak self] in
            try? await Task.sleep(nanoseconds: 8_000_000_000)
            guard !Task.isCancelled else { return }
            await self?.refresh(force: true)
        }
    }

    private func applyDevicePresentation(_ devices: [MyDevice]) {
        self.devices = devices
        deviceSections = buildDeviceSections(
            devices,
            favoritesTitle: NSLocalizedString("devices_favorites_section", comment: ""),
            fallbackGroupTitle: NSLocalizedString("devices_other_section", comment: "")
        )
    }

    private func render(error: Error, fallbackKey: String) -> AppMessage {
        if let apiError = error as? APIClientError {
            switch apiError {
            case .server(_, let message):
                return .verbatim(message)
            default:
                return .localized(fallbackKey)
            }
        }
        return .localized(fallbackKey)
    }

    private func handleAuthenticationError(session: UserSession, error: Error) -> Bool {
        guard isCurrentSession(session) else {
            return true
        }
        guard let apiError = error as? APIClientError,
              apiError.statusCode == 401 else {
            return false
        }
        sessionStore.logout(message: .localized("session_expired_message"))
        return true
    }

    private func isForbidden(_ error: Error) -> Bool {
        guard let apiError = error as? APIClientError,
              apiError.statusCode == 403 else {
            return false
        }
        return true
    }

    private func isCurrentSession(_ session: UserSession) -> Bool {
        sessionStore.currentSession == session
    }
}
