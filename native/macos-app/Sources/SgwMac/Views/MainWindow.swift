import SwiftUI

struct MainWindow: View {
  @Environment(AppState.self) private var appState
  @State private var releaseNotesOpen = false

  var body: some View {
    @Bindable var state = appState
    ZStack {
      if !appState.initialStatusResolved {
        InitialStatusView()
      } else if appState.status == nil {
        StatusUnavailableView()
          .environment(appState)
      } else if appState.daemonRunning, let url = appState.consoleURL() {
        ConsoleWebAppView(url: url)
          .frame(maxWidth: .infinity, maxHeight: .infinity)
      } else {
        SetupView()
          .environment(appState)
      }
    }
    .ignoresSafeArea(.container, edges: .top)
    .sheet(isPresented: $state.addSecretSheetOpen) {
      AddSecretSheet()
        .environment(appState)
    }
    .sheet(isPresented: $state.commandPalettePresented) {
      CommandPaletteView()
        .environment(appState)
    }
    .sheet(isPresented: $releaseNotesOpen) {
      if let release = appState.availableUpdate {
        UpdateReleaseSheet(release: release)
          .environment(appState)
      }
    }
    .overlay(alignment: .top) {
      VStack(spacing: 6) {
        if let release = appState.availableUpdate, !appState.updateBannerDismissed {
          updateBanner(release)
        }
        if let message = appState.lastError {
          banner(message, systemImage: "exclamationmark.triangle", tint: SGWTheme.orange)
        }
        if let message = appState.operationMessage {
          banner(message, systemImage: "info.circle", tint: SGWTheme.teal)
        }
      }
      .padding(.top, 8)
    }
    .onReceive(NotificationCenter.default.publisher(for: .sgwRefreshPanel)) { _ in
      Task { await appState.refresh() }
    }
  }

  private func updateBanner(_ release: ReleaseInfo) -> some View {
    HStack(spacing: 10) {
      Image(systemName: "arrow.down.circle")
        .foregroundStyle(SGWTheme.teal)
      VStack(alignment: .leading, spacing: 2) {
        Text("s-gw \(release.version) is available")
          .font(.callout.weight(.semibold))
        Text("Installed \(appState.installedVersion)")
          .font(.caption)
          .foregroundStyle(.secondary)
        Text(release.isMacInstaller
          ? "Download the installer, quit s-gw, replace the app in Applications, then reopen it."
          : "This update stays available here until you dismiss it or install it.")
          .font(.caption)
          .foregroundStyle(.secondary)
      }
      Spacer()
      Button("Release Notes") {
        releaseNotesOpen = true
      }
      Button(appState.updateState.isBusy ? appState.updateState.label : (release.isMacInstaller ? "Download" : "Upgrade")) {
        appState.installAvailableUpdate()
      }
      .disabled(!release.hasVerifiedAsset || appState.updateState.isBusy)
      Button {
        appState.dismissUpdateBanner()
      } label: {
        Image(systemName: "xmark")
      }
      .buttonStyle(.borderless)
    }
    .font(.callout)
    .padding(10)
    .background(SGWTheme.raised, in: RoundedRectangle(cornerRadius: 8))
    .overlay(RoundedRectangle(cornerRadius: 8).strokeBorder(SGWTheme.teal.opacity(0.45)))
    .padding(.horizontal)
  }

  private func banner(_ text: String, systemImage: String, tint: Color) -> some View {
    HStack(spacing: 8) {
      Image(systemName: systemImage)
      Text(text)
        .lineLimit(2)
      Button {
        appState.operationMessage = nil
        appState.lastError = nil
      } label: {
        Image(systemName: "xmark")
      }
      .buttonStyle(.borderless)
    }
    .font(.callout)
    .padding(10)
    .background(SGWTheme.raised, in: RoundedRectangle(cornerRadius: 8))
    .overlay(RoundedRectangle(cornerRadius: 8).strokeBorder(tint.opacity(0.5)))
    .padding(.horizontal)
  }
}

private struct InitialStatusView: View {
  var body: some View {
    VStack(spacing: 12) {
      ProgressView()
      Text("Checking the local runtime")
        .font(.headline)
      Text("s-gw is reading status before it updates background services or agent connections.")
        .foregroundStyle(.secondary)
    }
    .frame(maxWidth: .infinity, maxHeight: .infinity)
    .background(SGWTheme.surface)
  }
}

private struct StatusUnavailableView: View {
  @Environment(AppState.self) private var appState

  var body: some View {
    VStack(spacing: 12) {
      Image(systemName: "exclamationmark.triangle")
        .font(.title)
        .foregroundStyle(SGWTheme.orange)
      Text("Status is unavailable")
        .font(.headline)
      Text("s-gw could not inspect the local runtime. No component is being reported as missing.")
        .foregroundStyle(.secondary)
      Button("Try Again") {
        Task { await appState.refresh() }
      }
    }
    .frame(maxWidth: .infinity, maxHeight: .infinity)
    .background(SGWTheme.surface)
  }
}

private struct UpdateReleaseSheet: View {
  @Environment(AppState.self) private var appState
  @Environment(\.dismiss) private var dismiss
  let release: ReleaseInfo

  var body: some View {
    VStack(alignment: .leading, spacing: 18) {
      HStack(alignment: .top, spacing: 12) {
        Image(systemName: "arrow.down.circle.fill")
          .font(.title)
          .foregroundStyle(SGWTheme.teal)
        VStack(alignment: .leading, spacing: 4) {
          Text("s-gw \(release.version)")
            .font(.title2.weight(.semibold))
          Text("Installed \(appState.installedVersion)")
            .foregroundStyle(.secondary)
        }
      }

      ScrollView {
        Text(release.notes.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty ? "No release notes were published for this version." : release.notes)
          .font(.body)
          .frame(maxWidth: .infinity, alignment: .leading)
          .textSelection(.enabled)
      }
      .frame(minHeight: 220)
      .padding(12)
      .background(SGWTheme.raised, in: RoundedRectangle(cornerRadius: 8))

      HStack {
        Button("Open Release") {
          appState.openAvailableRelease()
        }
        Spacer()
        Button("Not Now") {
          appState.dismissUpdateBanner()
          dismiss()
        }
        Button(appState.updateState.isBusy ? appState.updateState.label : (release.isMacInstaller ? "Download" : "Upgrade")) {
          dismiss()
          appState.installAvailableUpdate()
        }
        .keyboardShortcut(.defaultAction)
        .disabled(!release.hasVerifiedAsset || appState.updateState.isBusy)
      }
    }
    .padding(24)
    .frame(width: 560, height: 460)
  }
}
