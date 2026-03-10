import Foundation

final class AppServices {
    let apiClient: APIClient
    let preferences: AppPreferences
    let notificationCoordinator: APNSNotificationCoordinator

    init(
        apiClient: APIClient,
        preferences: AppPreferences,
        notificationCoordinator: APNSNotificationCoordinator
    ) {
        self.apiClient = apiClient
        self.preferences = preferences
        self.notificationCoordinator = notificationCoordinator
    }
}
