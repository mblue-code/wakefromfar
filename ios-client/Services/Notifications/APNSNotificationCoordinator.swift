import Foundation
import UserNotifications
import UIKit

@MainActor
final class APNSNotificationCoordinator: NSObject, ObservableObject {
    let adminAlertStrategySummaryKey = "settings_notifications_summary"

    @Published private(set) var authorizationStatus: UNAuthorizationStatus = .notDetermined
    @Published private(set) var pendingTabSelection: MainTab?
    @Published private(set) var activityRefreshToken: Int = 0

    private let apiClient: APIClient
    private let preferences: AppPreferences

    private var observedSession: UserSession?
    private var lastSyncedContext: RegistrationContext?

    init(apiClient: APIClient, preferences: AppPreferences) {
        self.apiClient = apiClient
        self.preferences = preferences
        super.init()
    }

    var notificationStatusKey: String {
        switch authorizationStatus {
        case .notDetermined:
            return "settings_notifications_status_not_determined"
        case .denied:
            return "settings_notifications_status_denied"
        case .authorized, .provisional, .ephemeral:
            return preferences.notificationDeviceToken.isEmpty
                ? "settings_notifications_status_authorized_pending"
                : "settings_notifications_status_authorized"
        @unknown default:
            return "settings_notifications_status_unknown"
        }
    }

    var settingsActionTitleKey: String? {
        switch authorizationStatus {
        case .notDetermined:
            return "settings_notifications_enable_button"
        case .denied:
            return "settings_notifications_open_settings_button"
        case .authorized, .provisional, .ephemeral:
            return preferences.notificationDeviceToken.isEmpty
                ? "settings_notifications_register_button"
                : "settings_notifications_reregister_button"
        @unknown default:
            return nil
        }
    }

    func bootstrap(session: UserSession?) async {
        UNUserNotificationCenter.current().delegate = self
        await handleSessionState(session)
    }

    func refreshStatus() async {
        await refreshAuthorizationStatus()
    }

    func handleSessionState(_ session: UserSession?) async {
        let previousSession = observedSession
        observedSession = session
        await refreshAuthorizationStatus()

        if let previousSession, previousSession != session, previousSession.role == .admin {
            await deregisterDevice(using: previousSession)
            if observedSession == session {
                lastSyncedContext = nil
            }
        }

        guard let session, session.role == .admin else {
            lastSyncedContext = nil
            return
        }

        guard isAuthorizedForAlerts else {
            if authorizationStatus == .denied {
                await deregisterDevice(using: session)
            }
            return
        }

        await registerForRemoteNotifications()
        await syncCurrentRegistrationIfNeeded(force: previousSession != session)
    }

    func prepareForAdminActivity() async {
        guard observedSession?.role == .admin else { return }
        await refreshAuthorizationStatus()

        if authorizationStatus == .notDetermined {
            _ = await requestAuthorization()
            await refreshAuthorizationStatus()
        }

        guard isAuthorizedForAlerts else {
            if let session = observedSession, authorizationStatus == .denied {
                await deregisterDevice(using: session)
            }
            return
        }

        await registerForRemoteNotifications()
        await syncCurrentRegistrationIfNeeded(force: false)
    }

    func handleSettingsAction() async {
        await refreshAuthorizationStatus()
        switch authorizationStatus {
        case .notDetermined:
            _ = await requestAuthorization()
            await refreshAuthorizationStatus()
            if isAuthorizedForAlerts {
                await registerForRemoteNotifications()
                await syncCurrentRegistrationIfNeeded(force: true)
            }
        case .denied:
            openSystemNotificationSettings()
        case .authorized, .provisional, .ephemeral:
            await registerForRemoteNotifications()
            await syncCurrentRegistrationIfNeeded(force: true)
        @unknown default:
            break
        }
    }

    func consumePendingTabSelection() {
        pendingTabSelection = nil
    }

    func didRegisterForRemoteNotifications(deviceToken: Data) async {
        let token = deviceToken.map { String(format: "%02x", $0) }.joined()
        preferences.notificationDeviceToken = token
        await syncCurrentRegistrationIfNeeded(force: true)
    }

    func didFailToRegisterForRemoteNotifications(error: Error) {
        assertionFailure("APNs registration failed: \(error.localizedDescription)")
    }

    func handleLaunchNotificationPayload(_ userInfo: [AnyHashable: Any]) {
        handleNotification(userInfo: userInfo, activateRoute: true)
    }

    private var isAuthorizedForAlerts: Bool {
        switch authorizationStatus {
        case .authorized, .provisional, .ephemeral:
            return true
        default:
            return false
        }
    }

    private func refreshAuthorizationStatus() async {
        let settings = await UNUserNotificationCenter.current().notificationSettings()
        authorizationStatus = settings.authorizationStatus
    }

    private func requestAuthorization() async -> Bool {
        do {
            return try await UNUserNotificationCenter.current().requestAuthorization(options: [.alert, .badge, .sound])
        } catch {
            return false
        }
    }

    private func registerForRemoteNotifications() async {
        UIApplication.shared.registerForRemoteNotifications()
    }

    private func syncCurrentRegistrationIfNeeded(force: Bool) async {
        guard let session = observedSession,
              let context = registrationContext(for: session) else {
            return
        }
        guard force || context != lastSyncedContext else {
            return
        }

        do {
            _ = try await apiClient.registerAPNSDevice(
                installationID: context.installationID,
                token: context.deviceToken,
                appBundleID: context.bundleID,
                environment: context.environment,
                baseURL: session.backendURL,
                authToken: session.token
            )
            guard isObservedSession(session) else { return }
            lastSyncedContext = context
        } catch {
            guard isObservedSession(session) else { return }
            if shouldClearRegistration(for: error) {
                lastSyncedContext = nil
            }
        }
    }

    private func deregisterDevice(using session: UserSession) async {
        guard session.role == .admin else { return }
        let installationID = preferences.notificationInstallationID
        guard !installationID.isEmpty else { return }

        do {
            try await apiClient.deleteAPNSDevice(
                installationID: installationID,
                baseURL: session.backendURL,
                authToken: session.token
            )
        } catch {
            guard isObservedSession(session) else { return }
            if shouldClearRegistration(for: error) {
                lastSyncedContext = nil
            }
            return
        }
        guard isObservedSession(session) else { return }
        lastSyncedContext = nil
    }

    private func registrationContext(for session: UserSession) -> RegistrationContext? {
        guard session.role == .admin else { return nil }
        guard isAuthorizedForAlerts else { return nil }
        let deviceToken = preferences.notificationDeviceToken.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !deviceToken.isEmpty else { return nil }
        let bundleID = Bundle.main.bundleIdentifier ?? "com.wakefromfar.iosclient"
        return RegistrationContext(
            backendURL: session.backendURL.absoluteString,
            username: session.username,
            installationID: preferences.notificationInstallationID,
            deviceToken: deviceToken,
            bundleID: bundleID,
            environment: currentEnvironment
        )
    }

    private var currentEnvironment: APNSEnvironment {
        #if DEBUG
        .development
        #else
        .production
        #endif
    }

    private func openSystemNotificationSettings() {
        guard let url = URL(string: UIApplication.openSettingsURLString) else { return }
        UIApplication.shared.open(url)
    }

    private func shouldClearRegistration(for error: Error) -> Bool {
        guard let apiError = error as? APIClientError,
              let statusCode = apiError.statusCode else {
            return false
        }
        return statusCode == 401 || statusCode == 403
    }

    private func isObservedSession(_ session: UserSession) -> Bool {
        observedSession == session
    }

    private func handleNotification(userInfo: [AnyHashable: Any], activateRoute: Bool) {
        guard notificationRoute(from: userInfo) == "admin_activity" else { return }
        activityRefreshToken &+= 1
        if activateRoute {
            pendingTabSelection = .activity
        }
    }

    private func notificationRoute(from userInfo: [AnyHashable: Any]) -> String? {
        if let route = userInfo["wf_route"] as? String, !route.isEmpty {
            return route
        }
        if let wf = userInfo["wf"] as? [String: Any],
           let route = wf["route"] as? String,
           !route.isEmpty {
            return route
        }
        return nil
    }
}

extension APNSNotificationCoordinator: UNUserNotificationCenterDelegate {
    nonisolated func userNotificationCenter(
        _ center: UNUserNotificationCenter,
        willPresent notification: UNNotification
    ) async -> UNNotificationPresentationOptions {
        await MainActor.run {
            handleNotification(userInfo: notification.request.content.userInfo, activateRoute: false)
        }
        return [.banner, .list, .sound]
    }

    nonisolated func userNotificationCenter(
        _ center: UNUserNotificationCenter,
        didReceive response: UNNotificationResponse
    ) async {
        await MainActor.run {
            handleNotification(userInfo: response.notification.request.content.userInfo, activateRoute: true)
        }
    }
}

private struct RegistrationContext: Equatable {
    let backendURL: String
    let username: String
    let installationID: String
    let deviceToken: String
    let bundleID: String
    let environment: APNSEnvironment
}
