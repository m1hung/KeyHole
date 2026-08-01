import SwiftUI
import UniformTypeIdentifiers
import UIKit
import KeyholeCore

struct SettingsView: View {
    @Environment(AppVaultSession.self) private var session
    var clipboard: ClipboardController

    @State private var autoLockMinutes: Double = 15
    @State private var clipboardClear: Double = 30
    @State private var lockOnHide = false
    @State private var breachCheckEnabled = false
    @State private var theme: ThemePreference = .system
    @State private var currentPassword = ""
    @State private var newPassword = ""
    @State private var confirmPassword = ""
    @State private var showImporter = false
    @State private var showExporter = false
    @State private var exportData: Data?
    @State private var confirmReset = false
    @State private var healthReport: VaultHealthReport?
    @State private var healthSelection: Set<String> = []
    @State private var confirmHealthTrash = false
    @State private var breachBusy = false
    @State private var breachError: String?
    @State private var breachHits: [BreachHit]?

    @State private var syncBaseUrl = ""
    @State private var syncAccountId = ""
    @State private var syncPassword = ""
    @State private var syncMessage: String?
    @State private var syncBusy = false
    @State private var biometricUnlockEnabled = BiometricUnlockStore.isReady
    @State private var showBiometricSetup = false
    @State private var biometricSetupPassword = ""
    @State private var biometricSetupError: String?
    @State private var editingEntry: Entry?
    @State private var autofillPublishMessage: String?
    @State private var autofillPublishBusy = false

    var body: some View {
        NavigationStack {
            Form {
                Section {
                    Stepper(
                        "Auto-lock: \(Int(autoLockMinutes)) min",
                        value: $autoLockMinutes,
                        in: 1...240,
                        step: 1
                    )
                    Stepper(
                        "Clipboard clear: \(Int(clipboardClear)) s",
                        value: $clipboardClear,
                        in: 0...600,
                        step: 5
                    )
                    Toggle("Lock when app backgrounds", isOn: $lockOnHide)
                    if BiometricUnlockStore.canUseBiometrics || BiometricUnlockStore.isEnabled {
                        Toggle(
                            "Unlock with \(BiometricUnlockStore.biometryTypeName)",
                            isOn: $biometricUnlockEnabled
                        )
                        .onChange(of: biometricUnlockEnabled) { _, enabled in
                            if enabled {
                                showBiometricSetup = true
                                biometricUnlockEnabled = BiometricUnlockStore.isReady
                            } else {
                                BiometricUnlockStore.disable()
                            }
                        }
                    }
                    Toggle("Check for leaked passwords", isOn: $breachCheckEnabled)
                    if breachCheckEnabled {
                        Button {
                            Task { await runBreachCheck() }
                        } label: {
                            HStack {
                                Text(breachHits == nil ? "Check now" : "Check again")
                                if breachBusy { ProgressView() }
                            }
                        }
                        .disabled(breachBusy || session.data == nil)
                        if let breachError {
                            Text(breachError)
                                .font(KeyholeFonts.meta)
                                .foregroundStyle(KeyholeColors.danger)
                        }
                        if let breachHits {
                            Text(
                                breachHits.isEmpty
                                    ? "No leaked passwords found."
                                    : "\(breachHits.count) leaked — tap to update."
                            )
                            .font(KeyholeFonts.meta)
                            .foregroundStyle(KeyholeColors.textDim)
                            ForEach(breachHits.prefix(40)) { hit in
                                HStack {
                                    VStack(alignment: .leading, spacing: 2) {
                                        Text(hit.title)
                                            .font(KeyholeFonts.bodySemibold)
                                            .foregroundStyle(KeyholeColors.text)
                                        Text("Seen in \(hit.count) breach\(hit.count == 1 ? "" : "es")")
                                            .font(KeyholeFonts.meta)
                                            .foregroundStyle(KeyholeColors.danger)
                                    }
                                    Spacer(minLength: 0)
                                    Image(systemName: "chevron.right")
                                        .font(.caption.weight(.semibold))
                                        .foregroundStyle(KeyholeColors.textDim)
                                }
                                .contentShape(Rectangle())
                                .onTapGesture {
                                    openEntry(id: hit.entryId)
                                }
                                .swipeActions(edge: .trailing, allowsFullSwipe: true) {
                                    Button(role: .destructive) {
                                        Task { await trashHealthEntry(id: hit.entryId) }
                                    } label: {
                                        Label {
                                            Text("Move to trash")
                                        } icon: {
                                            KeyholeIcon(name: .trash, size: 18)
                                        }
                                    }
                                }
                            }
                        }
                    }
                    Picker("Theme", selection: $theme) {
                        Text("System").tag(ThemePreference.system)
                        Text("Light").tag(ThemePreference.light)
                        Text("Dark").tag(ThemePreference.dark)
                    }
                    Button("Save") {
                        Task { await savePrefs() }
                    }
                    .foregroundStyle(KeyholeColors.accent)
                } header: {
                    KeyholeFieldLabel(text: "Security")
                }
                .listRowBackground(KeyholeColors.surface)

                Section {
                    SecureField("Current", text: $currentPassword)
                    SecureField("New (12+ characters)", text: $newPassword)
                    SecureField("Confirm", text: $confirmPassword)
                    Button("Change password") {
                        Task { await changePassword() }
                    }
                    .disabled(newPassword.count < MIN_MASTER_PASSWORD_LENGTH || newPassword != confirmPassword)
                    .foregroundStyle(KeyholeColors.accent)
                } header: {
                    KeyholeFieldLabel(text: "Master password")
                }
                .listRowBackground(KeyholeColors.surface)

                Section {
                    if let report = healthReport {
                        let findings = groupedHealthFindings(report.issues)
                        Text(
                            findings.isEmpty
                                ? "Looking good — no issues."
                                : "\(report.issues.count) issue\(report.issues.count == 1 ? "" : "s") across \(findings.count) \(findings.count == 1 ? "entry" : "entries")."
                        )
                        .font(KeyholeFonts.meta)
                        .foregroundStyle(KeyholeColors.textDim)

                        if !findings.isEmpty {
                            HStack {
                                Button {
                                    let allIds = Set(findings.map(\.entryId))
                                    healthSelection = healthSelection == allIds ? [] : allIds
                                } label: {
                                    HStack(spacing: 6) {
                                        Image(systemName: healthSelection.count == findings.count ? "checkmark.circle.fill" : "circle")
                                        Text(
                                            healthSelection.isEmpty
                                                ? "Select all \(findings.count)"
                                                : "\(healthSelection.count) of \(findings.count) selected"
                                        )
                                    }
                                }
                                .buttonStyle(.plain)
                                .font(KeyholeFonts.meta)
                                .foregroundStyle(KeyholeColors.accent)
                                Spacer(minLength: 8)
                                Button(role: .destructive) {
                                    confirmHealthTrash = true
                                } label: {
                                    HStack(spacing: 4) {
                                        KeyholeIcon(name: .trash, size: 14)
                                        Text(session.busy ? "Moving…" : "Move \(healthSelection.count) to trash")
                                    }
                                }
                                .disabled(healthSelection.isEmpty || session.busy)
                                .font(KeyholeFonts.meta)
                                .foregroundStyle(KeyholeColors.danger)
                            }

                            Button("Move all findings to trash") {
                                Task { await trashHealthEntries(ids: findings.map(\.entryId)) }
                            }
                            .font(KeyholeFonts.meta)
                            .foregroundStyle(KeyholeColors.danger)
                            .disabled(session.busy)
                        }

                        ForEach(findings.prefix(40)) { finding in
                            HStack(spacing: 12) {
                                Button {
                                    toggleHealthSelection(finding.entryId)
                                } label: {
                                    Image(systemName: healthSelection.contains(finding.entryId) ? "checkmark.circle.fill" : "circle")
                                        .foregroundStyle(
                                            healthSelection.contains(finding.entryId)
                                                ? KeyholeColors.accent
                                                : KeyholeColors.textDim
                                        )
                                }
                                .buttonStyle(.plain)
                                VStack(alignment: .leading, spacing: 2) {
                                    Text("\(finding.kinds.map(\.displayLabel).joined(separator: ", ")) · \(finding.title)")
                                        .font(KeyholeFonts.bodySemibold)
                                        .foregroundStyle(KeyholeColors.text)
                                    Text(finding.issues.map(\.detail).joined(separator: " "))
                                        .font(KeyholeFonts.meta)
                                        .foregroundStyle(KeyholeColors.textDim)
                                }
                                Spacer(minLength: 0)
                                Image(systemName: "chevron.right")
                                    .font(.caption.weight(.semibold))
                                    .foregroundStyle(KeyholeColors.textDim)
                            }
                            .contentShape(Rectangle())
                            .onTapGesture {
                                openEntry(id: finding.entryId)
                            }
                            .swipeActions(edge: .trailing, allowsFullSwipe: true) {
                                Button(role: .destructive) {
                                    Task { await trashHealthEntry(id: finding.entryId) }
                                } label: {
                                    Label {
                                        Text("Move to trash")
                                    } icon: {
                                        KeyholeIcon(name: .trash, size: 18)
                                    }
                                }
                            }
                        }
                    }
                    Button(healthReport == nil ? "Scan passwords" : "Scan again") {
                        healthReport = session.data.map { analyzeVaultHealth($0) }
                        healthSelection = []
                        session.registerActivity()
                    }
                    .foregroundStyle(KeyholeColors.accent)
                } header: {
                    KeyholeFieldLabel(text: "Password check")
                }
                .listRowBackground(KeyholeColors.surface)
                .confirmationDialog(
                    "Move \(healthSelection.count) \(healthSelection.count == 1 ? "entry" : "entries") to the trash?",
                    isPresented: $confirmHealthTrash,
                    titleVisibility: .visible
                ) {
                    Button("Move to trash", role: .destructive) {
                        let ids = Array(healthSelection)
                        confirmHealthTrash = false
                        Task { await trashHealthEntries(ids: ids) }
                    }
                } message: {
                    Text("They stop appearing in your list and in AutoFill right away. Restore any of them from the Trash filter within \(TRASH_RETENTION_DAYS) days.")
                }

                Section {
                    Button("Export backup…") {
                        Task { await prepareExport() }
                    }
                    Button("Import backup…") { showImporter = true }
                    Button("Lock now") { session.lock() }
                    Button("Delete vault", role: .destructive) {
                        confirmReset = true
                    }
                } header: {
                    KeyholeFieldLabel(text: "Backup")
                }
                .listRowBackground(KeyholeColors.surface)

                Section {
                    Text("Fill passwords and passkeys in apps and Safari. Turn on Keyhole in iPhone Settings:")
                        .font(KeyholeFonts.meta)
                        .foregroundStyle(KeyholeColors.textDim)
                    Text("Settings → AutoFill & Passwords → Keyhole")
                        .font(KeyholeFonts.meta)
                        .foregroundStyle(KeyholeColors.accent)
                    if VaultStore.shared.isSharedWithAutoFill {
                        Label("Ready", systemImage: "checkmark.circle.fill")
                            .font(KeyholeFonts.meta)
                            .foregroundStyle(KeyholeColors.ok)
                    } else {
                        Text("AutoFill isn’t available. Reinstall Keyhole and try again.")
                            .font(KeyholeFonts.meta)
                            .foregroundStyle(KeyholeColors.warn)
                    }
                    Button("Open iPhone Settings") {
                        openAutoFillPasswordsSettings()
                    }
                    .foregroundStyle(KeyholeColors.accent)
                    Button {
                        Task { await refreshAutoFillStatus() }
                    } label: {
                        HStack {
                            Text("Check status")
                            if autofillPublishBusy { ProgressView() }
                        }
                    }
                    .disabled(autofillPublishBusy)
                    .foregroundStyle(KeyholeColors.accent)
                    if let autofillPublishMessage {
                        Text(autofillPublishMessage)
                            .font(KeyholeFonts.meta)
                            .foregroundStyle(
                                autofillPublishMessage.localizedCaseInsensitiveContains("can’t")
                                    || autofillPublishMessage.localizedCaseInsensitiveContains("couldn’t")
                                    || autofillPublishMessage.localizedCaseInsensitiveContains("unavailable")
                                ? KeyholeColors.warn
                                : KeyholeColors.ok
                            )
                    }
                } header: {
                    KeyholeFieldLabel(text: "AutoFill")
                }
                .listRowBackground(KeyholeColors.surface)

                SyncSettingsSection(
                    syncBaseUrl: $syncBaseUrl,
                    syncAccountId: $syncAccountId,
                    syncPassword: $syncPassword,
                    syncMessage: $syncMessage,
                    syncBusy: $syncBusy,
                    session: session
                )

                if let err = session.errorMessage {
                    Section {
                        KeyholeErrorBanner(message: err)
                    }
                }
                if let remaining = clipboard.secondsRemaining {
                    Section {
                        Text("Clipboard clears in \(remaining)s")
                            .font(KeyholeFonts.meta)
                            .foregroundStyle(KeyholeColors.textDim)
                    }
                    .listRowBackground(KeyholeColors.surface2)
                }
            }
            .keyholeFormChrome()
            .navigationTitle("Settings")
            .onAppear {
                load()
                biometricUnlockEnabled = BiometricUnlockStore.isReady
            }
            .fileImporter(
                isPresented: $showImporter,
                allowedContentTypes: [.json, .data],
                allowsMultipleSelection: false
            ) { result in
                Task { await handleImport(result) }
            }
            .fileExporter(
                isPresented: $showExporter,
                document: exportData.map { VaultDocument(data: $0) },
                contentType: .json,
                defaultFilename: "keyhole-vault.keyhole"
            ) { _ in }
            .confirmationDialog("Delete vault?", isPresented: $confirmReset, titleVisibility: .visible) {
                Button("Delete permanently", role: .destructive) {
                    Task { await session.deleteVault() }
                }
            } message: {
                Text("This deletes your vault from this iPhone. Export a backup first if you need it.")
            }
            .sheet(isPresented: $showBiometricSetup) {
                NavigationStack {
                    Form {
                        Section {
                            SecureField("Master password", text: $biometricSetupPassword)
                                .textContentType(.password)
                                .foregroundStyle(KeyholeColors.text)
                            if let biometricSetupError {
                                Text(biometricSetupError)
                                    .font(KeyholeFonts.meta)
                                    .foregroundStyle(KeyholeColors.danger)
                            }
                        } footer: {
                            Text("Confirm your password to turn on \(BiometricUnlockStore.biometryTypeName).")
                                .font(KeyholeFonts.meta)
                                .foregroundStyle(KeyholeColors.textDim)
                        }
                        .listRowBackground(KeyholeColors.surface)
                    }
                    .keyholeFormChrome()
                    .navigationTitle(BiometricUnlockStore.biometryTypeName)
                    .navigationBarTitleDisplayMode(.inline)
                    .toolbar {
                        ToolbarItem(placement: .cancellationAction) {
                            Button("Cancel") {
                                biometricSetupPassword = ""
                                biometricSetupError = nil
                                biometricUnlockEnabled = BiometricUnlockStore.isReady
                                showBiometricSetup = false
                            }
                        }
                        ToolbarItem(placement: .confirmationAction) {
                            Button("Enable") {
                                Task { await enableBiometrics() }
                            }
                            .disabled(biometricSetupPassword.count < MIN_MASTER_PASSWORD_LENGTH)
                        }
                    }
                }
                .presentationDetents([.medium])
            }
            .sheet(item: $editingEntry) { entry in
                EntryEditorView(entry: entry, kind: entry.kind) {
                    editingEntry = nil
                    session.registerActivity()
                    if let data = session.data {
                        let liveIds = Set(liveEntries(data).map(\.id))
                        breachHits = breachHits?.filter { liveIds.contains($0.entryId) }
                        if healthReport != nil {
                            healthReport = analyzeVaultHealth(data)
                        }
                    }
                }
            }
        }
    }

    private func openEntry(id: String) {
        guard let data = session.data,
              let entry = liveEntries(data).first(where: { $0.id == id })
        else { return }
        editingEntry = entry
        session.registerActivity()
    }

    private func trashHealthEntry(id: String) async {
        await session.mutate { try deleteEntry(data: $0, id: id) }
        session.registerActivity()
        guard let data = session.data else {
            healthReport = nil
            return
        }
        healthReport = analyzeVaultHealth(data)
        let liveIds = Set(liveEntries(data).map(\.id))
        breachHits = breachHits?.filter { liveIds.contains($0.entryId) }
    }

    /// Bulk trash for the health panel — one edit for every selected finding,
    /// mirroring the desktop `SettingsPanel` "Move … to trash" action.
    private func trashHealthEntries(ids: [String]) async {
        guard !ids.isEmpty else { return }
        await session.mutate { deleteEntries(data: $0, ids: ids) }
        healthSelection.removeAll()
        session.registerActivity()
        guard let data = session.data else {
            healthReport = nil
            return
        }
        healthReport = analyzeVaultHealth(data)
        let liveIds = Set(liveEntries(data).map(\.id))
        breachHits = breachHits?.filter { liveIds.contains($0.entryId) }
    }

    private func toggleHealthSelection(_ entryId: String) {
        if !healthSelection.insert(entryId).inserted {
            healthSelection.remove(entryId)
        }
    }

    private func enableBiometrics() async {
        biometricSetupError = nil
        guard let file = session.exportVault() else {
            biometricSetupError = "No vault loaded."
            return
        }
        let password = biometricSetupPassword
        do {
            _ = try await Task.detached(priority: .userInitiated) {
                try unlockVault(file: file, masterPassword: password)
            }.value
            try BiometricUnlockStore.enable(storing: password)
            biometricUnlockEnabled = true
            biometricSetupPassword = ""
            showBiometricSetup = false
            session.registerActivity()
        } catch {
            biometricSetupError = error.localizedDescription
            biometricUnlockEnabled = false
        }
    }

    private func load() {
        guard let s = session.data?.settings else { return }
        autoLockMinutes = s.autoLockMinutes
        clipboardClear = s.clipboardClearSeconds
        lockOnHide = s.lockOnHide
        breachCheckEnabled = s.breachCheckEnabled
        theme = s.theme
        if let cfg = session.syncConfig {
            syncBaseUrl = cfg.baseUrl
            syncAccountId = cfg.accountId
        }
    }

    /// Opens Settings → General → AutoFill & Passwords when the OS allows it.
    private func openAutoFillPasswordsSettings() {
        // Prefer iOS 18+ Settings navigation, then legacy prefs deep links.
        let candidates = [
            "settings-navigation://com.apple.Settings.General/AUTOFILL",
            "App-prefs:root=General&path=AUTOFILL",
            "prefs:root=General&path=AUTOFILL",
            "App-prefs:General&path=AUTOFILL",
        ]

        func tryOpen(_ raw: String, completion: ((Bool) -> Void)? = nil) {
            guard let url = URL(string: raw) else {
                completion?(false)
                return
            }
            UIApplication.shared.open(url, options: [:], completionHandler: completion)
        }

        // Walk candidates until one succeeds; fall back to the app Settings page.
        func attempt(_ index: Int) {
            if index >= candidates.count {
                if let fallback = URL(string: UIApplication.openSettingsURLString) {
                    UIApplication.shared.open(fallback)
                }
                return
            }
            tryOpen(candidates[index]) { success in
                if success { return }
                attempt(index + 1)
            }
        }
        attempt(0)
    }

    private func refreshAutoFillStatus() async {
        autofillPublishBusy = true
        defer { autofillPublishBusy = false }
        autofillPublishMessage = await session.autoFillSyncStatus()
        session.registerActivity()
    }

    private func savePrefs() async {
        await session.mutate { data in
            updateSettings(data: data) {
                $0.autoLockMinutes = autoLockMinutes
                $0.clipboardClearSeconds = clipboardClear
                $0.lockOnHide = lockOnHide
                $0.breachCheckEnabled = breachCheckEnabled
                $0.theme = theme
            }
        }
        clipboard.updateClearAfter(Int(clipboardClear))
        session.registerActivity()
    }

    private func changePassword() async {
        guard newPassword == confirmPassword else {
            session.errorMessage = "New passwords do not match."
            return
        }
        await session.changeMasterPassword(current: currentPassword, next: newPassword)
        currentPassword = ""
        newPassword = ""
        confirmPassword = ""
    }

    private func runBreachCheck() async {
        guard breachCheckEnabled, let data = session.data else { return }
        breachBusy = true
        breachError = nil
        defer { breachBusy = false }
        var hits: [BreachHit] = []
        let logins = liveEntries(data).filter { $0.kind == .login && !$0.password.isEmpty }
        do {
            for entry in logins {
                let count = try await BreachClient.checkPasswordBreachCount(entry.password)
                if count > 0 {
                    hits.append(BreachHit(entryId: entry.id, title: entry.title, count: count))
                }
            }
            breachHits = hits
            session.registerActivity()
        } catch {
            breachError = error.localizedDescription
        }
    }

    private func prepareExport() async {
        guard let file = session.exportVault() else { return }
        do {
            exportData = try VaultStore.shared.exportJSON(file)
            showExporter = true
        } catch {
            session.errorMessage = error.localizedDescription
        }
    }

    private func handleImport(_ result: Result<[URL], Error>) async {
        do {
            let urls = try result.get()
            guard let url = urls.first else { return }
            let accessed = url.startAccessingSecurityScopedResource()
            defer { if accessed { url.stopAccessingSecurityScopedResource() } }
            let data = try Data(contentsOf: url)
            let file = try VaultStore.shared.importJSON(data)
            await session.importVault(file)
        } catch {
            session.errorMessage = error.localizedDescription
        }
    }
}

/// One row per flagged entry, folding together every reason it was flagged —
/// mirrors `groupIssuesByEntry` in core/src/health.ts, so a selection checkbox
/// maps to exactly one entry even when it has several findings.
struct HealthFinding: Identifiable {
    var entryId: String
    var title: String
    var kinds: [HealthIssueKind]
    var issues: [HealthIssue]
    var id: String { entryId }
}

func groupedHealthFindings(_ issues: [HealthIssue]) -> [HealthFinding] {
    var order: [String] = []
    var byEntry: [String: HealthFinding] = [:]
    for issue in issues {
        if var existing = byEntry[issue.entryId] {
            existing.issues.append(issue)
            if !existing.kinds.contains(issue.kind) { existing.kinds.append(issue.kind) }
            byEntry[issue.entryId] = existing
        } else {
            byEntry[issue.entryId] = HealthFinding(
                entryId: issue.entryId,
                title: issue.title,
                kinds: [issue.kind],
                issues: [issue]
            )
            order.append(issue.entryId)
        }
    }
    return order.compactMap { byEntry[$0] }
}

struct VaultDocument: FileDocument {
    static var readableContentTypes: [UTType] { [.json] }
    var data: Data

    init(data: Data) { self.data = data }

    init(configuration: ReadConfiguration) throws {
        data = configuration.file.regularFileContents ?? Data()
    }

    func fileWrapper(configuration: WriteConfiguration) throws -> FileWrapper {
        FileWrapper(regularFileWithContents: data)
    }
}

struct SyncSettingsSection: View {
    @Binding var syncBaseUrl: String
    @Binding var syncAccountId: String
    @Binding var syncPassword: String
    @Binding var syncMessage: String?
    @Binding var syncBusy: Bool
    var session: AppVaultSession
    @State private var vaultMismatch = false

    var body: some View {
        Section {
            TextField("Server URL", text: $syncBaseUrl)
                .textInputAutocapitalization(.never)
                .keyboardType(.URL)
            TextField("Account", text: $syncAccountId)
                .textInputAutocapitalization(.never)
            SecureField("Master password", text: $syncPassword)
            if syncBusy {
                HStack {
                    ProgressView()
                    Text("Working…")
                        .font(KeyholeFonts.meta)
                        .foregroundStyle(KeyholeColors.textDim)
                }
            }
            if let syncMessage {
                Text(syncMessage)
                    .font(KeyholeFonts.meta)
                    .foregroundStyle(KeyholeColors.textDim)
            }
            Button("Save") {
                let cfg = SyncConfigPrefs(baseUrl: syncBaseUrl, accountId: syncAccountId)
                cfg.save()
                session.syncConfig = cfg
                syncMessage = "Saved."
                session.registerActivity()
            }
            Button("Test connection") {
                Task {
                    syncBusy = true
                    defer { syncBusy = false }
                    let ok = await SyncClient.healthCheck(baseUrl: syncBaseUrl)
                    syncMessage = ok ? "Connected." : "Couldn’t reach the server."
                    session.registerActivity()
                }
            }
            .disabled(syncBusy || syncBaseUrl.isEmpty)
            Button("Set up on this server") {
                Task { await registerUpload() }
            }
            .disabled(syncBusy)
            Button("Sync now") {
                Task { await syncNow() }
            }
            .disabled(syncBusy)
            if vaultMismatch {
                Text("This account already has a different vault. Choose one:")
                    .font(KeyholeFonts.meta)
                    .foregroundStyle(KeyholeColors.warn)
                    .padding(.vertical, 4)
                Button("Use server vault") {
                    Task { await adoptRemote() }
                }
                .disabled(syncBusy || syncPassword.isEmpty)
                Button("Replace server vault", role: .destructive) {
                    Task { await overwriteRemote() }
                }
                .disabled(syncBusy || syncPassword.isEmpty)
            }
            Button("Turn off sync", role: .destructive) {
                SyncConfigPrefs.clear()
                session.syncConfig = nil
                syncBaseUrl = ""
                syncAccountId = ""
                syncMessage = "Sync turned off."
                vaultMismatch = false
            }
        } header: {
            KeyholeFieldLabel(text: "Sync")
        }
        .listRowBackground(KeyholeColors.surface)
    }

    private func registerUpload() async {
        syncBusy = true
        defer { syncBusy = false }
        guard let file = session.exportVault() else {
            syncMessage = "No vault on this device."
            return
        }
        do {
            let secret = try await session.ensureSyncAuth(masterPassword: syncPassword)
            let result = try await SyncClient.registerAccount(
                baseUrl: syncBaseUrl,
                accountId: syncAccountId.trimmingCharacters(in: .whitespacesAndNewlines).lowercased(),
                authSecretB64: secret,
                envelope: file
            )
            let cfg = SyncConfigPrefs(baseUrl: syncBaseUrl, accountId: result.accountId)
            cfg.save()
            session.syncConfig = cfg
            syncMessage = "Set up. You’re ready to sync."
            syncPassword = ""
            session.registerActivity()
        } catch {
            syncMessage = error.localizedDescription
        }
    }

    private func syncNow() async {
        syncBusy = true
        defer { syncBusy = false }
        guard session.exportVault() != nil,
              session.syncConfig != nil || (!syncBaseUrl.isEmpty && !syncAccountId.isEmpty)
        else {
            syncMessage = "Add your sync settings first."
            return
        }
        let cfg = session.syncConfig ?? SyncConfigPrefs(baseUrl: syncBaseUrl, accountId: syncAccountId)
        do {
            if syncPassword.isEmpty, session.getSyncAuthSecret() == nil {
                syncMessage = "Enter your master password to sync."
                return
            }
            let message = try await session.syncNow(
                baseUrl: cfg.baseUrl,
                accountId: cfg.accountId,
                masterPassword: syncPassword.isEmpty ? nil : syncPassword
            )
            syncMessage = message
            syncPassword = ""
            vaultMismatch = false
            session.registerActivity()
        } catch let err as SyncClientError where err.code == "vault_mismatch" {
            vaultMismatch = true
            syncMessage = err.message
        } catch {
            syncMessage = error.localizedDescription
        }
    }

    private func adoptRemote() async {
        syncBusy = true
        defer { syncBusy = false }
        let cfg = session.syncConfig ?? SyncConfigPrefs(baseUrl: syncBaseUrl, accountId: syncAccountId)
        guard !cfg.baseUrl.isEmpty, !cfg.accountId.isEmpty else {
            syncMessage = "Add your sync settings first."
            return
        }
        guard !syncPassword.isEmpty else {
            syncMessage = "Enter your master password to use the server vault."
            return
        }
        do {
            let message = try await session.adoptRemote(
                baseUrl: cfg.baseUrl,
                accountId: cfg.accountId,
                masterPassword: syncPassword
            )
            syncMessage = message
            syncPassword = ""
            vaultMismatch = false
            session.registerActivity()
        } catch {
            syncMessage = error.localizedDescription
        }
    }

    private func overwriteRemote() async {
        syncBusy = true
        defer { syncBusy = false }
        let cfg = session.syncConfig ?? SyncConfigPrefs(baseUrl: syncBaseUrl, accountId: syncAccountId)
        guard !cfg.baseUrl.isEmpty, !cfg.accountId.isEmpty else {
            syncMessage = "Add your sync settings first."
            return
        }
        guard !syncPassword.isEmpty else {
            syncMessage = "Enter your master password to replace the server vault."
            return
        }
        do {
            let message = try await session.overwriteRemote(
                baseUrl: cfg.baseUrl,
                accountId: cfg.accountId,
                masterPassword: syncPassword
            )
            syncMessage = message
            syncPassword = ""
            vaultMismatch = false
            session.registerActivity()
        } catch {
            syncMessage = error.localizedDescription
        }
    }
}
