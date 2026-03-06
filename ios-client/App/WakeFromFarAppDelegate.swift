import UIKit
import UserNotifications

final class WakeFromFarAppDelegate: NSObject, UIApplicationDelegate {
    static weak var notificationCoordinator: APNSNotificationCoordinator?

    func application(
        _ application: UIApplication,
        didFinishLaunchingWithOptions launchOptions: [UIApplication.LaunchOptionsKey: Any]? = nil
    ) -> Bool {
        UNUserNotificationCenter.current().delegate = Self.notificationCoordinator
        if let payload = launchOptions?[.remoteNotification] as? [AnyHashable: Any] {
            Task { @MainActor in
                Self.notificationCoordinator?.handleLaunchNotificationPayload(payload)
            }
        }
        return true
    }

    func application(_ application: UIApplication, didRegisterForRemoteNotificationsWithDeviceToken deviceToken: Data) {
        Task { @MainActor in
            await Self.notificationCoordinator?.didRegisterForRemoteNotifications(deviceToken: deviceToken)
        }
    }

    func application(_ application: UIApplication, didFailToRegisterForRemoteNotificationsWithError error: Error) {
        Task { @MainActor in
            Self.notificationCoordinator?.didFailToRegisterForRemoteNotifications(error: error)
        }
    }
}
