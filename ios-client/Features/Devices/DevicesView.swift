import SwiftUI

struct DevicesView: View {
    @StateObject private var viewModel: DevicesViewModel
    @State private var shutdownTarget: MyDevice?
    @State private var shutdownNote = ""

    init(viewModel: DevicesViewModel) {
        _viewModel = StateObject(wrappedValue: viewModel)
    }

    var body: some View {
        NavigationStack {
            List {
                if let message = viewModel.feedbackMessage {
                    MessageBanner(message: message, tint: viewModel.feedbackTint)
                        .listRowInsets(EdgeInsets(top: 8, leading: 16, bottom: 8, trailing: 16))
                        .listRowBackground(Color.clear)
                }

                if let loadError = viewModel.loadErrorMessage, viewModel.devices.isEmpty && !viewModel.isLoading {
                    EmptyStateView(
                        systemImage: "desktopcomputer.trianglebadge.exclamationmark",
                        title: .localized("devices_error_title"),
                        message: loadError,
                        actionTitleKey: "devices_retry"
                    ) {
                        Task {
                            await viewModel.refresh(force: true)
                        }
                    }
                    .listRowBackground(Color.clear)
                } else if viewModel.devices.isEmpty && !viewModel.isLoading && viewModel.hasLoadedOnce {
                    EmptyStateView(
                        systemImage: "desktopcomputer.trianglebadge.exclamationmark",
                        title: .localized("devices_empty_title"),
                        message: .localized("devices_empty_message"),
                        actionTitleKey: "devices_refresh"
                    ) {
                        Task {
                            await viewModel.refresh(force: true)
                        }
                    }
                    .listRowBackground(Color.clear)
                } else {
                    ForEach(viewModel.deviceSections) { section in
                        Section {
                            ForEach(section.devices) { device in
                                DeviceRow(
                                    device: device,
                                    isWorking: viewModel.activeDeviceID == device.id
                                ) {
                                    Task {
                                        await viewModel.toggleFavorite(device: device)
                                    }
                                } onWake: {
                                    Task {
                                        await viewModel.wake(device: device)
                                    }
                                } onShutdown: {
                                    shutdownTarget = device
                                    shutdownNote = ""
                                }
                            }
                        } header: {
                            Text(section.title)
                        }
                    }
                }
            }
            .listStyle(.automatic)
            .overlay {
                if viewModel.isLoading && viewModel.devices.isEmpty {
                    ProgressView("devices_loading")
                        .accessibilityElement(children: .combine)
                }
            }
            .navigationTitle("devices_title")
            .toolbar {
                ToolbarItem(placement: .primaryAction) {
                    Button("devices_refresh") {
                        Task {
                            await viewModel.refresh(force: true)
                        }
                    }
                }
            }
            .task {
                await viewModel.refresh(force: false)
            }
            .refreshable {
                await viewModel.refresh(force: true)
            }
            .sheet(item: $shutdownTarget) { device in
                NavigationStack {
                    Form {
                        Section {
                            Text(device.displayTitle)
                                .font(.headline)
                                .fixedSize(horizontal: false, vertical: true)

                            Text("devices_shutdown_sheet_message")
                                .font(.subheadline)
                                .foregroundStyle(.secondary)
                                .fixedSize(horizontal: false, vertical: true)

                            TextField(
                                "",
                                text: $shutdownNote,
                                prompt: Text("devices_shutdown_note_placeholder"),
                                axis: .vertical
                            )
                            .lineLimit(3...6)
                            .accessibilityLabel(Text("devices_shutdown_note_label"))
                            .accessibilityHint(Text("devices_shutdown_note_hint"))
                        }
                    }
                    .navigationTitle("devices_shutdown_sheet_title")
                    .appInlineNavigationBarTitle()
                    .toolbar {
                        ToolbarItem(placement: .cancellationAction) {
                            Button("general_cancel") {
                                shutdownTarget = nil
                            }
                        }

                        ToolbarItem(placement: .confirmationAction) {
                            Button("devices_shutdown_send") {
                                Task {
                                    await viewModel.requestShutdown(device: device, note: shutdownNote)
                                    shutdownTarget = nil
                                }
                            }
                            .disabled(viewModel.isShutdownNoteTooLong(shutdownNote))
                        }
                    }

                    if viewModel.isShutdownNoteTooLong(shutdownNote) {
                        Text("devices_shutdown_note_limit")
                            .font(.footnote)
                            .foregroundStyle(.red)
                            .padding(.horizontal)
                            .fixedSize(horizontal: false, vertical: true)
                    }
                }
                .presentationDetents([.medium])
            }
        }
    }
}

private struct DeviceRow: View {
    let device: MyDevice
    let isWorking: Bool
    let onToggleFavorite: () -> Void
    let onWake: () -> Void
    let onShutdown: () -> Void

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            ViewThatFits(in: .horizontal) {
                HStack(alignment: .top, spacing: 12) {
                    titleBlock

                    Spacer(minLength: 8)

                    favoriteButton

                    stateBadge
                }

                VStack(alignment: .leading, spacing: 10) {
                    titleBlock
                    favoriteButton
                    stateBadge
                }
            }

            HStack(spacing: 8) {
                if let groupName = device.groupName, !groupName.isEmpty, device.displayTitle != device.name {
                    Label(groupName, systemImage: "folder")
                        .font(.footnote)
                        .foregroundStyle(.secondary)
                }

                if device.canViewStatus && device.isStale {
                    Label("devices_stale_badge", systemImage: "clock.badge.exclamationmark")
                        .font(.footnote.weight(.semibold))
                        .foregroundStyle(.orange)
                        .accessibilityLabel(Text("devices_stale_accessibility"))
                }
            }
            .accessibilityElement(children: .combine)

            Text(String(format: NSLocalizedString("devices_mac_format", comment: ""), device.mac))
                .font(.footnote.monospaced())
                .foregroundStyle(.secondary)
                .accessibilityLabel(Text(String(format: NSLocalizedString("devices_mac_accessibility_format", comment: ""), device.mac)))

            if let scheduleHint = device.scheduledWakeHint {
                Text(scheduleHint)
                    .font(.footnote.weight(.semibold))
                    .foregroundStyle(.tint)
                    .fixedSize(horizontal: false, vertical: true)
            }

            Text(lastCheckedText)
                .font(.footnote)
                .foregroundStyle(.secondary)
                .accessibilityLabel(Text(lastCheckedText))
                .fixedSize(horizontal: false, vertical: true)

            ViewThatFits(in: .horizontal) {
                HStack(spacing: 8) {
                    wakeButton
                    shutdownButton
                }

                VStack(alignment: .leading, spacing: 8) {
                    wakeButton
                    shutdownButton
                }
            }

            DevicePermissionHints(device: device)
        }
        .padding(.vertical, 6)
        .accessibilityElement(children: .contain)
    }

    private var titleBlock: some View {
        VStack(alignment: .leading, spacing: 4) {
            Text(device.displayTitle)
                .font(.headline)
                .lineLimit(2)
                .fixedSize(horizontal: false, vertical: true)

            if device.displayTitle != device.name {
                Text(device.name)
                    .font(.subheadline)
                    .foregroundStyle(.secondary)
                    .lineLimit(2)
                    .fixedSize(horizontal: false, vertical: true)
            } else if let groupName = device.groupName, !groupName.isEmpty {
                Text(groupName)
                    .font(.subheadline)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }
        }
    }

    private var stateBadge: some View {
        Label(stateLabel, systemImage: stateSymbol)
            .font(.caption.weight(.semibold))
            .padding(.horizontal, 10)
            .padding(.vertical, 6)
            .background(stateTint.opacity(0.15), in: Capsule())
            .foregroundStyle(stateTint)
            .accessibilityLabel(Text(stateAccessibilityLabel))
    }

    private var wakeButton: some View {
        Button(action: onWake) {
            if isWorking {
                ProgressView()
                    .frame(maxWidth: .infinity)
            } else {
                Text("devices_wake")
                    .frame(maxWidth: .infinity)
            }
        }
        .buttonStyle(.borderedProminent)
        .disabled(isWorking || !device.canWake)
        .accessibilityLabel(Text(String(format: NSLocalizedString("devices_wake_accessibility_format", comment: ""), device.displayTitle)))
        .accessibilityHint(
            Text(
                device.canWake
                    ? LocalizedStringKey("devices_wake_accessibility_hint")
                    : LocalizedStringKey("devices_wake_not_permitted")
            )
        )
    }

    private var shutdownButton: some View {
        Button("devices_shutdown", action: onShutdown)
            .frame(maxWidth: .infinity)
            .buttonStyle(.bordered)
            .disabled(isWorking || !device.canRequestShutdown)
            .accessibilityLabel(Text(String(format: NSLocalizedString("devices_shutdown_accessibility_format", comment: ""), device.displayTitle)))
            .accessibilityHint(
                Text(
                    device.canRequestShutdown
                        ? LocalizedStringKey("devices_shutdown_accessibility_hint")
                        : LocalizedStringKey("devices_shutdown_not_permitted")
                )
            )
    }

    private var favoriteButton: some View {
        Button(action: onToggleFavorite) {
            Image(systemName: device.isFavorite ? "star.fill" : "star")
                .foregroundStyle(device.isFavorite ? .yellow : .secondary)
                .imageScale(.medium)
        }
        .buttonStyle(.plain)
        .disabled(isWorking)
        .accessibilityLabel(Text(device.isFavorite ? "devices_unfavorite" : "devices_favorite"))
    }

    private var lastCheckedText: String {
        if !device.canViewStatus {
            return NSLocalizedString("devices_status_unavailable", comment: "")
        }
        let base: String
        if let lastCheckedAt = device.lastPowerCheckedAt {
            base = lastCheckedAt.formatted(date: .abbreviated, time: .shortened)
        } else {
            base = NSLocalizedString("devices_last_checked_never", comment: "")
        }
        let suffix = device.isStale ? NSLocalizedString("devices_stale_suffix", comment: "") : ""
        return String(
            format: NSLocalizedString("devices_last_checked_format", comment: ""),
            base,
            suffix
        )
    }

    private var stateLabel: String {
        guard device.canViewStatus else {
            return NSLocalizedString("devices_state_unavailable", comment: "")
        }
        return stateLabel(for: device.lastPowerState)
    }

    private var stateTint: Color {
        guard device.canViewStatus else {
            return .secondary
        }
        return stateTint(for: device.lastPowerState)
    }

    private var stateSymbol: String {
        guard device.canViewStatus else {
            return "lock.slash.fill"
        }
        return stateSymbol(for: device.lastPowerState)
    }

    private func stateLabel(for state: PowerState) -> String {
        switch state {
        case .on:
            return NSLocalizedString("devices_state_on", comment: "")
        case .off:
            return NSLocalizedString("devices_state_off", comment: "")
        case .unknown:
            return NSLocalizedString("devices_state_unknown", comment: "")
        }
    }

    private func stateTint(for state: PowerState) -> Color {
        switch state {
        case .on:
            return .green
        case .off:
            return .orange
        case .unknown:
            return .secondary
        }
    }

    private func stateSymbol(for state: PowerState) -> String {
        switch state {
        case .on:
            return "checkmark.circle.fill"
        case .off:
            return "moon.zzz.fill"
        case .unknown:
            return "questionmark.circle.fill"
        }
    }

    private var stateAccessibilityLabel: String {
        String(
            format: NSLocalizedString("devices_state_accessibility_format", comment: ""),
            stateLabel
        )
    }
}

private struct DevicePermissionHints: View {
    let device: MyDevice

    var body: some View {
        let hints = [
            device.canViewStatus ? nil : NSLocalizedString("devices_status_unavailable", comment: ""),
            device.canWake ? nil : NSLocalizedString("devices_wake_not_permitted", comment: ""),
            device.canRequestShutdown ? nil : NSLocalizedString("devices_shutdown_not_permitted", comment: "")
        ].compactMap { $0 }

        if hints.isEmpty {
            EmptyView()
        } else {
            Text(hints.joined(separator: " • "))
                .font(.footnote)
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
        }
    }
}
