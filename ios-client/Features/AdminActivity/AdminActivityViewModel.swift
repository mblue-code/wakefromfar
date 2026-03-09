import Foundation
import SwiftUI

enum ActivityFilter: String, CaseIterable, Identifiable {
    case all
    case wake
    case pokeOpen
    case pokeSeen
    case pokeResolved
    case error

    var id: String { rawValue }

    var backendTypeFilter: String? {
        switch self {
        case .all:
            return nil
        case .wake:
            return "wake"
        case .pokeOpen, .pokeSeen, .pokeResolved:
            return "poke"
        case .error:
            return "error"
        }
    }

    var titleKey: LocalizedStringKey {
        switch self {
        case .all:
            return "activity_filter_all"
        case .wake:
            return "activity_filter_wake"
        case .pokeOpen:
            return "activity_filter_poke_open"
        case .pokeSeen:
            return "activity_filter_poke_seen"
        case .pokeResolved:
            return "activity_filter_poke_resolved"
        case .error:
            return "activity_filter_error"
        }
    }

    func includes(
        _ event: ActivityEvent,
        latestPokeEventIDs: [String: Int],
        pokeStatuses: [String: ShutdownPokeStatus]
    ) -> Bool {
        switch self {
        case .all:
            return true
        case .wake:
            return event.isWakeEvent
        case .error:
            return event.isErrorEvent
        case .pokeOpen, .pokeSeen, .pokeResolved:
            guard let pokeID = event.pokeID,
                  latestPokeEventIDs[pokeID] == event.id,
                  let status = pokeStatuses[pokeID] else {
                return false
            }

            switch self {
            case .pokeOpen:
                return status == .open
            case .pokeSeen:
                return status == .seen
            case .pokeResolved:
                return status == .resolved
            case .all, .wake, .error:
                return false
            }
        }
    }
}

enum ShutdownRequestAction: Hashable {
    case markSeen
    case markResolved

    var titleKey: LocalizedStringKey {
        switch self {
        case .markSeen:
            return "activity_action_mark_seen"
        case .markResolved:
            return "activity_action_mark_resolved"
        }
    }

    var successMessageKey: String {
        switch self {
        case .markSeen:
            return "activity_action_seen_success"
        case .markResolved:
            return "activity_action_resolved_success"
        }
    }
}

@MainActor
final class AdminActivityViewModel: ObservableObject {
    @Published private(set) var events: [ActivityEvent] = []
    @Published private(set) var isLoading = false
    @Published private(set) var isLoadingMore = false
    @Published private(set) var feedbackMessage: AppMessage?
    @Published private(set) var feedbackTint: Color = .blue
    @Published private(set) var loadErrorMessage: AppMessage?
    @Published var selectedFilter: ActivityFilter = .all {
        didSet {
            updateDisplayedEvents()
        }
    }

    private let sessionStore: SessionStore
    private let apiClient: APIClient
    private let pageSize = 20

    private var allEvents: [ActivityEvent] = []
    private var activeShutdownRequestIDs = Set<String>()
    private var latestPokeEventIDByPokeID: [String: Int] = [:]
    private var pokeStatusByPokeID: [String: ShutdownPokeStatus] = [:]
    private var nextCursor: Int?
    private var hasMorePages = false
    private var lastRefreshSucceeded = false
    private(set) var hasLoaded = false

    var canLoadMore: Bool {
        hasMorePages && nextCursor != nil && !isLoadingMore
    }

    init(sessionStore: SessionStore, apiClient: APIClient) {
        self.sessionStore = sessionStore
        self.apiClient = apiClient
    }

    func refresh(force: Bool) async {
        guard force || !hasLoaded else { return }
        guard let session = sessionStore.currentSession, session.role == .admin else {
            resetState()
            return
        }

        isLoading = true
        loadErrorMessage = nil
        feedbackMessage = nil
        lastRefreshSucceeded = false
        defer {
            isLoading = false
            hasLoaded = true
        }

        do {
            let page = try await apiClient.fetchAdminActivityEvents(
                baseURL: session.backendURL,
                token: session.token,
                cursor: nil,
                limit: pageSize,
                typeFilter: selectedFilter.backendTypeFilter,
                installationID: session.installationID
            )
            guard isCurrentSession(session) else { return }
            guard !Task.isCancelled else { return }
            replaceEvents(with: page)
            lastRefreshSucceeded = true
        } catch {
            guard isCurrentSession(session) else { return }
            guard !handleAuthorizationError(session: session, error: error) else { return }
            let renderedError = render(error: error, fallbackKey: "activity_error_generic")
            if allEvents.isEmpty {
                loadErrorMessage = renderedError
            } else {
                feedbackMessage = renderedError
                feedbackTint = .red
            }
        }
    }

    func loadMore() async {
        guard let session = sessionStore.currentSession, session.role == .admin else { return }
        guard let cursor = nextCursor, hasMorePages, !isLoadingMore else { return }

        isLoadingMore = true
        defer { isLoadingMore = false }

        do {
            let page = try await apiClient.fetchAdminActivityEvents(
                baseURL: session.backendURL,
                token: session.token,
                cursor: cursor,
                limit: pageSize,
                typeFilter: selectedFilter.backendTypeFilter,
                installationID: session.installationID
            )
            guard isCurrentSession(session) else { return }
            guard !Task.isCancelled else { return }
            appendEvents(page)
        } catch {
            guard isCurrentSession(session) else { return }
            guard !handleAuthorizationError(session: session, error: error) else { return }
            feedbackMessage = render(error: error, fallbackKey: "activity_error_generic")
            feedbackTint = .red
        }
    }

    func actions(for event: ActivityEvent) -> [ShutdownRequestAction] {
        guard let pokeID = event.pokeID,
              latestPokeEventIDByPokeID[pokeID] == event.id,
              !isActionInFlight(for: pokeID),
              let status = pokeStatusByPokeID[pokeID] else {
            return []
        }

        switch status {
        case .open:
            return [.markSeen, .markResolved]
        case .seen:
            return [.markResolved]
        case .resolved:
            return []
        }
    }

    func isActionInFlight(for pokeID: String?) -> Bool {
        guard let pokeID else {
            return false
        }
        return activeShutdownRequestIDs.contains(pokeID)
    }

    func currentShutdownStatus(for event: ActivityEvent) -> ShutdownPokeStatus? {
        guard let pokeID = event.pokeID else {
            return nil
        }
        return pokeStatusByPokeID[pokeID] ?? event.shutdownStatus
    }

    func perform(_ action: ShutdownRequestAction, for event: ActivityEvent) async {
        guard let session = sessionStore.currentSession, session.role == .admin else { return }
        guard let pokeID = event.pokeID, !activeShutdownRequestIDs.contains(pokeID) else { return }

        activeShutdownRequestIDs.insert(pokeID)
        defer { activeShutdownRequestIDs.remove(pokeID) }

        do {
            let updatedPoke: ShutdownPoke
            switch action {
            case .markSeen:
                updatedPoke = try await apiClient.markShutdownPokeSeen(
                    pokeID: pokeID,
                    baseURL: session.backendURL,
                    token: session.token,
                    installationID: session.installationID
                )
            case .markResolved:
                updatedPoke = try await apiClient.markShutdownPokeResolved(
                    pokeID: pokeID,
                    baseURL: session.backendURL,
                    token: session.token,
                    installationID: session.installationID
                )
            }
            guard isCurrentSession(session) else { return }
            guard !Task.isCancelled else { return }

            applyLocalStatusUpdate(pokeID: pokeID, status: updatedPoke.status)
            await refresh(force: true)
            if lastRefreshSucceeded {
                feedbackMessage = .localized(action.successMessageKey)
                feedbackTint = .green
            }
        } catch {
            guard isCurrentSession(session) else { return }
            guard !handleAuthorizationError(session: session, error: error) else { return }
            feedbackMessage = render(error: error, fallbackKey: "activity_action_error_generic")
            feedbackTint = .red
        }
    }

    private func replaceEvents(with page: [ActivityEvent]) {
        allEvents = deduplicatedSorted(page)
        nextCursor = allEvents.last?.id
        hasMorePages = page.count == pageSize
        updateDerivedState()
        loadErrorMessage = nil
    }

    private func appendEvents(_ page: [ActivityEvent]) {
        allEvents = deduplicatedSorted(allEvents + page)
        nextCursor = allEvents.last?.id
        hasMorePages = page.count == pageSize
        updateDerivedState()
    }

    private func deduplicatedSorted(_ input: [ActivityEvent]) -> [ActivityEvent] {
        var seenIDs = Set<Int>()
        return input
            .sorted { $0.id > $1.id }
            .filter { event in
                seenIDs.insert(event.id).inserted
            }
    }

    private func updateDerivedState() {
        latestPokeEventIDByPokeID = [:]
        pokeStatusByPokeID = [:]

        for event in allEvents {
            guard let pokeID = event.pokeID else { continue }
            latestPokeEventIDByPokeID[pokeID] = max(latestPokeEventIDByPokeID[pokeID] ?? 0, event.id)
            if let status = event.shutdownStatus {
                let currentRank = pokeStatusByPokeID[pokeID].map(statusRank) ?? -1
                let nextRank = statusRank(status)
                if nextRank >= currentRank {
                    pokeStatusByPokeID[pokeID] = status
                }
            }
        }

        updateDisplayedEvents()
    }

    private func updateDisplayedEvents() {
        events = allEvents.filter {
            selectedFilter.includes(
                $0,
                latestPokeEventIDs: latestPokeEventIDByPokeID,
                pokeStatuses: pokeStatusByPokeID
            )
        }
    }

    private func applyLocalStatusUpdate(pokeID: String, status: ShutdownPokeStatus) {
        pokeStatusByPokeID[pokeID] = status
        updateDisplayedEvents()
    }

    private func statusRank(_ status: ShutdownPokeStatus) -> Int {
        switch status {
        case .open:
            return 0
        case .seen:
            return 1
        case .resolved:
            return 2
        }
    }

    private func resetState() {
        allEvents = []
        events = []
        nextCursor = nil
        hasMorePages = false
        hasLoaded = false
        lastRefreshSucceeded = false
        latestPokeEventIDByPokeID = [:]
        pokeStatusByPokeID = [:]
        activeShutdownRequestIDs = []
        loadErrorMessage = nil
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

    private func handleAuthorizationError(session: UserSession, error: Error) -> Bool {
        guard isCurrentSession(session) else {
            return true
        }
        guard let apiError = error as? APIClientError,
              let statusCode = apiError.statusCode else {
            return false
        }

        if statusCode == 401 {
            sessionStore.logout(message: .localized("session_expired_message"))
            return true
        }

        if statusCode == 403 {
            sessionStore.logout(message: .localized("activity_admin_access_changed_message"))
            return true
        }

        return false
    }

    private func isCurrentSession(_ session: UserSession) -> Bool {
        sessionStore.currentSession == session
    }
}
