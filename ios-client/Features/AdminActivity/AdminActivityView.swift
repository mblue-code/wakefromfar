import SwiftUI

struct AdminActivityView: View {
    @StateObject private var viewModel: AdminActivityViewModel
    @ObservedObject private var notificationCoordinator: APNSNotificationCoordinator

    init(viewModel: AdminActivityViewModel, notificationCoordinator: APNSNotificationCoordinator) {
        _viewModel = StateObject(wrappedValue: viewModel)
        _notificationCoordinator = ObservedObject(wrappedValue: notificationCoordinator)
    }

    var body: some View {
        NavigationStack {
            List {
                if let message = viewModel.feedbackMessage {
                    MessageBanner(message: message, tint: viewModel.feedbackTint)
                        .listRowInsets(EdgeInsets(top: 8, leading: 16, bottom: 8, trailing: 16))
                        .listRowBackground(Color.clear)
                }

                Section {
                    Menu {
                        Picker("activity_filter_label", selection: $viewModel.selectedFilter) {
                            ForEach(ActivityFilter.allCases) { filter in
                                Text(filter.titleKey).tag(filter)
                            }
                        }
                    } label: {
                        HStack(spacing: 12) {
                            Text("activity_filter_label")

                            Spacer()

                            Text(viewModel.selectedFilter.titleKey)
                                .foregroundStyle(.secondary)

                            Image(systemName: "line.3.horizontal.decrease.circle")
                                .foregroundStyle(.secondary)
                        }
                    }
                    .accessibilityLabel(Text("activity_filter_label"))
                    .accessibilityValue(Text(viewModel.selectedFilter.titleKey))
                }

                if let loadError = viewModel.loadErrorMessage, viewModel.events.isEmpty && !viewModel.isLoading {
                    EmptyStateView(
                        systemImage: "exclamationmark.arrow.trianglehead.clockwise",
                        title: .localized("activity_error_title"),
                        message: loadError,
                        actionTitleKey: "activity_retry"
                    ) {
                        Task {
                            await viewModel.refresh(force: true)
                        }
                    }
                    .listRowBackground(Color.clear)
                } else if viewModel.events.isEmpty && !viewModel.isLoading && viewModel.hasLoaded {
                    EmptyStateView(
                        systemImage: "clock.badge.questionmark",
                        title: .localized(emptyStateTitleKey),
                        message: .localized(emptyStateMessageKey),
                        actionTitleKey: "activity_refresh"
                    ) {
                        Task {
                            await viewModel.refresh(force: true)
                        }
                    }
                    .listRowBackground(Color.clear)
                } else {
                    ForEach(viewModel.events) { event in
                        AdminActivityRow(
                            event: event,
                            currentStatus: viewModel.currentShutdownStatus(for: event),
                            actions: viewModel.actions(for: event),
                            isActionInFlight: viewModel.isActionInFlight(for: event.pokeID)
                        ) { action in
                            Task {
                                await viewModel.perform(action, for: event)
                            }
                        }
                    }

                    if viewModel.canLoadMore {
                        Button {
                            Task {
                                await viewModel.loadMore()
                            }
                        } label: {
                            HStack {
                                Spacer()

                                if viewModel.isLoadingMore {
                                    ProgressView()
                                } else {
                                    Text("activity_load_more")
                                }

                                Spacer()
                            }
                        }
                        .disabled(viewModel.isLoadingMore)
                    }
                }
            }
            .listStyle(.automatic)
            .overlay {
                if viewModel.isLoading && viewModel.events.isEmpty {
                    ProgressView("activity_loading")
                        .accessibilityElement(children: .combine)
                }
            }
            .navigationTitle("activity_title")
            .toolbar {
                ToolbarItem(placement: .primaryAction) {
                    Button("activity_refresh") {
                        Task {
                            await viewModel.refresh(force: true)
                        }
                    }
                }
            }
            .task {
                await notificationCoordinator.prepareForAdminActivity()
                await viewModel.refresh(force: false)
            }
            .task(id: notificationCoordinator.activityRefreshToken) {
                guard notificationCoordinator.activityRefreshToken > 0 else { return }
                await viewModel.refresh(force: true)
            }
            .onChange(of: viewModel.selectedFilter) { _ in
                Task {
                    await viewModel.refresh(force: true)
                }
            }
            .refreshable {
                await viewModel.refresh(force: true)
            }
        }
    }

    private var emptyStateTitleKey: String {
        viewModel.selectedFilter == .all ? "activity_empty_title" : "activity_empty_filtered_title"
    }

    private var emptyStateMessageKey: String {
        viewModel.selectedFilter == .all ? "activity_empty_message" : "activity_empty_filtered_message"
    }
}

private struct AdminActivityRow: View {
    let event: ActivityEvent
    let currentStatus: ShutdownPokeStatus?
    let actions: [ShutdownRequestAction]
    let isActionInFlight: Bool
    let onAction: (ShutdownRequestAction) -> Void

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            HStack(alignment: .top, spacing: 12) {
                Image(systemName: eventSymbol)
                    .font(.title3.weight(.semibold))
                    .foregroundStyle(eventTint)
                    .frame(width: 24)
                    .accessibilityHidden(true)

                VStack(alignment: .leading, spacing: 10) {
                    ViewThatFits(in: .horizontal) {
                        HStack(alignment: .top, spacing: 12) {
                            Text(event.summary)
                                .font(.body.weight(.semibold))
                                .multilineTextAlignment(.leading)
                                .fixedSize(horizontal: false, vertical: true)

                            Spacer(minLength: 8)

                            badgeView
                        }

                        VStack(alignment: .leading, spacing: 8) {
                            Text(event.summary)
                                .font(.body.weight(.semibold))
                                .multilineTextAlignment(.leading)
                                .fixedSize(horizontal: false, vertical: true)

                            badgeView
                        }
                    }
                    .accessibilityElement(children: .contain)
                    .accessibilitySortPriority(1)

                    VStack(alignment: .leading, spacing: 6) {
                        if let note = event.shutdownNote {
                            DetailLine(labelKey: "activity_detail_note", value: note)
                        }

                        if let sentTo = event.sentTo {
                            DetailLine(labelKey: "activity_detail_sent_to", value: sentTo)
                        }

                        if let precheckState = event.precheckState {
                            DetailLine(labelKey: "activity_detail_precheck", value: localizedPowerState(precheckState))
                        }

                        if let errorDetail = event.errorDetail {
                            DetailLine(labelKey: "activity_detail_error", value: errorDetail)
                        }
                    }

                    Text(
                        String(
                            format: NSLocalizedString("activity_detail_created_at_format", comment: ""),
                            event.createdAt.formatted(date: .abbreviated, time: .shortened)
                        )
                    )
                        .font(.footnote)
                        .foregroundStyle(.secondary)
                        .fixedSize(horizontal: false, vertical: true)

                    if !actions.isEmpty {
                        ViewThatFits(in: .horizontal) {
                            HStack(spacing: 8) {
                                actionButtons
                            }

                            VStack(alignment: .leading, spacing: 8) {
                                actionButtons
                            }
                        }
                    }
                }
            }
        }
        .padding(.vertical, 6)
        .accessibilityElement(children: .contain)
    }

    @ViewBuilder
    private var actionButtons: some View {
        ForEach(actions, id: \.self) { action in
            if action == .markResolved {
                Button {
                    onAction(action)
                } label: {
                    if isActionInFlight {
                        ProgressView()
                            .frame(maxWidth: .infinity)
                    } else {
                        Text(action.titleKey)
                            .frame(maxWidth: .infinity)
                    }
                }
                .buttonStyle(.borderedProminent)
                .disabled(isActionInFlight)
                .accessibilityHint(Text("activity_action_accessibility_hint"))
            } else {
                Button {
                    onAction(action)
                } label: {
                    if isActionInFlight {
                        ProgressView()
                            .frame(maxWidth: .infinity)
                    } else {
                        Text(action.titleKey)
                            .frame(maxWidth: .infinity)
                    }
                }
                .buttonStyle(.bordered)
                .disabled(isActionInFlight)
                .accessibilityHint(Text("activity_action_accessibility_hint"))
            }
        }
    }

    private var badgeView: some View {
        Text(badgeText)
            .font(.caption.weight(.semibold))
            .padding(.horizontal, 10)
            .padding(.vertical, 6)
            .background(eventTint.opacity(0.12), in: Capsule())
            .foregroundStyle(eventTint)
            .accessibilityLabel(Text(String(format: NSLocalizedString("activity_badge_accessibility_format", comment: ""), badgeAccessibilityText)))
    }

    private var badgeText: LocalizedStringKey {
        switch event.eventType {
        case "wake_sent":
            return "activity_badge_wake_sent"
        case "wake_already_on":
            return "activity_badge_wake_already_on"
        case "wake_failed":
            return "activity_badge_wake_failed"
        case "shutdown_poke_requested":
            return currentStatus == .resolved ? "activity_badge_poke_resolved" :
                currentStatus == .seen ? "activity_badge_poke_seen" : "activity_badge_poke_open"
        case "shutdown_poke_seen":
            return currentStatus == .resolved ? "activity_badge_poke_resolved" : "activity_badge_poke_seen"
        case "shutdown_poke_resolved":
            return "activity_badge_poke_resolved"
        default:
            return "activity_badge_generic"
        }
    }

    private var eventSymbol: String {
        switch event.eventType {
        case "wake_sent":
            return "bolt.fill"
        case "wake_already_on":
            return "checkmark.circle.fill"
        case "wake_failed":
            return "exclamationmark.triangle.fill"
        case "shutdown_poke_requested":
            return "bell.badge.fill"
        case "shutdown_poke_seen":
            return "eye.fill"
        case "shutdown_poke_resolved":
            return "checkmark.seal.fill"
        default:
            return "clock.arrow.circlepath"
        }
    }

    private var eventTint: Color {
        switch event.eventType {
        case "wake_sent", "wake_already_on", "shutdown_poke_resolved":
            return .green
        case "shutdown_poke_requested", "shutdown_poke_seen":
            return .orange
        case "wake_failed":
            return .red
        default:
            return .secondary
        }
    }

    private func localizedPowerState(_ state: PowerState) -> String {
        switch state {
        case .on:
            return NSLocalizedString("devices_state_on", comment: "")
        case .off:
            return NSLocalizedString("devices_state_off", comment: "")
        case .unknown:
            return NSLocalizedString("devices_state_unknown", comment: "")
        }
    }

    private var badgeAccessibilityText: String {
        switch event.eventType {
        case "wake_sent":
            return NSLocalizedString("activity_badge_wake_sent", comment: "")
        case "wake_already_on":
            return NSLocalizedString("activity_badge_wake_already_on", comment: "")
        case "wake_failed":
            return NSLocalizedString("activity_badge_wake_failed", comment: "")
        case "shutdown_poke_requested":
            if currentStatus == .resolved {
                return NSLocalizedString("activity_badge_poke_resolved", comment: "")
            }
            if currentStatus == .seen {
                return NSLocalizedString("activity_badge_poke_seen", comment: "")
            }
            return NSLocalizedString("activity_badge_poke_open", comment: "")
        case "shutdown_poke_seen":
            return currentStatus == .resolved
                ? NSLocalizedString("activity_badge_poke_resolved", comment: "")
                : NSLocalizedString("activity_badge_poke_seen", comment: "")
        case "shutdown_poke_resolved":
            return NSLocalizedString("activity_badge_poke_resolved", comment: "")
        default:
            return NSLocalizedString("activity_badge_generic", comment: "")
        }
    }
}

private struct DetailLine: View {
    let labelKey: String
    let value: String

    var body: some View {
        VStack(alignment: .leading, spacing: 2) {
            Text(LocalizedStringKey(labelKey))
                .font(.caption.weight(.semibold))
                .foregroundStyle(.secondary)

            Text(verbatim: value)
                .font(.subheadline)
                .foregroundStyle(.primary)
                .multilineTextAlignment(.leading)
        }
        .accessibilityElement(children: .combine)
    }
}
