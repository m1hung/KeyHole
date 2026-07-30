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
    @State private var breachBusy = false
    @State private var breachError: String?
    @State private var breachHits: [BreachHit]?

    @State private var syncBaseUrl = ""
    @State private var syncAccountId = ""
    @State private var syncPassword = ""
    @State private var syncMessage: String?
    @State private var syncBusy = false

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
                    Toggle("Enable breach checking", isOn: $breachCheckEnabled)
                    if breachCheckEnabled {
                        Text(
                            """
                            Opt-in Have I Been Pwned lookup. Nothing is sent automatically — \
                            each check requires an explicit tap, and only a 5-character hash prefix \
                            leaves the device.
                            """
                        )
                        .font(KeyholeFonts.meta)
                        .foregroundStyle(KeyholeColors.textDim)
                        Button {
                            Task { await runBreachCheck() }
                        } label: {
                            HStack {
                                Text(breachHits == nil ? "Check passwords" : "Check again")
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
                                    ? "No breached passwords found among checked logins."
                                    : "\(breachHits.count) password(s) found in known breaches."
                            )
                            .font(KeyholeFonts.meta)
                            .foregroundStyle(KeyholeColors.textDim)
                            ForEach(breachHits.prefix(40)) { hit in
                                VStack(alignment: .leading, spacing: 2) {
                                    Text(hit.title)
                                        .font(KeyholeFonts.bodySemibold)
                                    Text("Seen \(hit.count) time(s) in breaches.")
                                        .font(KeyholeFonts.meta)
                                        .foregroundStyle(KeyholeColors.danger)
                                }
                            }
                        }
                    }
                    Picker("Theme", selection: $theme) {
                        Text("System").tag(ThemePreference.system)
                        Text("Light").tag(ThemePreference.light)
                        Text("Dark").tag(ThemePreference.dark)
                    }
                    Button("Save preferences") {
                        Task { await savePrefs() }
                    }
                    .foregroundStyle(KeyholeColors.accent)
                } header: {
                    KeyholeFieldLabel(text: "Security")
                }
                .listRowBackground(KeyholeColors.surface)

                Section {
                    SecureField("Current", text: $currentPassword)
                    SecureField("New (≥12 chars)", text: $newPassword)
                    SecureField("Confirm new", text: $confirmPassword)
                    Button("Change master password") {
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
                        Text(
                            report.issues.isEmpty
                                ? "Checked \(report.loginCount) logins — no issues found."
                                : "Checked \(report.loginCount) logins — \(report.issues.count) finding(s)."
                        )
                        .font(KeyholeFonts.meta)
                        .foregroundStyle(KeyholeColors.textDim)

                        ForEach(report.issues.prefix(40), id: \.entryId) { issue in
                            VStack(alignment: .leading, spacing: 2) {
                                Text("\(issue.kind.rawValue.uppercased()) · \(issue.title)")
                                    .font(KeyholeFonts.bodySemibold)
                                Text(issue.detail)
                                    .font(KeyholeFonts.meta)
                                    .foregroundStyle(KeyholeColors.textDim)
                            }
                        }
                    }
                    Button(healthReport == nil ? "Check vault" : "Check again") {
                        healthReport = session.data.map { analyzeVaultHealth($0) }
                        session.registerActivity()
                    }
                    .foregroundStyle(KeyholeColors.accent)
                } header: {
                    KeyholeFieldLabel(text: "Vault health")
                }
                .listRowBackground(KeyholeColors.surface)

                Section {
                    if let url = session.exportVault().map({ _ in VaultStore.shared.vaultFileURL }) {
                        Text(url.path)
                            .font(KeyholeFonts.meta)
                            .foregroundStyle(KeyholeColors.textDim)
                    }
                    Button("Export vault…") {
                        Task { await prepareExport() }
                    }
                    Button("Import vault…") { showImporter = true }
                    Button("Lock now") { session.lock() }
                    Button("Delete vault from this device", role: .destructive) {
                        confirmReset = true
                    }
                } header: {
                    KeyholeFieldLabel(text: "Vault file")
                }
                .listRowBackground(KeyholeColors.surface)

                Section {
                    Text(
                        """
                        Keyhole can fill usernames and passwords in Safari and apps. \
                        After installing, enable it in iOS Settings:
                        """
                    )
                    .font(KeyholeFonts.meta)
                    .foregroundStyle(KeyholeColors.textDim)
                    Text("Settings → Passwords → Password Options → AutoFill Passwords → Keyhole")
                        .font(KeyholeFonts.meta)
                        .foregroundStyle(KeyholeColors.accent)
                    Text(
                        """
                        When a login form appears, choose Keyhole from the QuickType bar, \
                        unlock with your master password, and pick a matching entry. \
                        The vault stays sealed; AutoFill never keeps your master password.
                        """
                    )
                    .font(KeyholeFonts.meta)
                    .foregroundStyle(KeyholeColors.textDim)
                    Button("Open Password Settings") {
                        if let url = URL(string: UIApplication.openSettingsURLString) {
                            UIApplication.shared.open(url)
                        }
                    }
                    .foregroundStyle(KeyholeColors.accent)
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
            .scrollContentBackground(.hidden)
            .background(KeyholeColors.bg)
            .navigationTitle("Settings")
            .onAppear { load() }
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
                Text("This removes the sealed vault file from this device. Export a backup first if you need it.")
            }
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
            TextField("Account id", text: $syncAccountId)
                .textInputAutocapitalization(.never)
            SecureField("Master password (for sync auth)", text: $syncPassword)
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
            Button("Save sync settings") {
                let cfg = SyncConfigPrefs(baseUrl: syncBaseUrl, accountId: syncAccountId)
                cfg.save()
                session.syncConfig = cfg
                syncMessage = "Sync settings saved (auth secret is never persisted)."
                session.registerActivity()
            }
            Button("Test connection") {
                Task {
                    syncBusy = true
                    defer { syncBusy = false }
                    let ok = await SyncClient.healthCheck(baseUrl: syncBaseUrl)
                    syncMessage = ok ? "Server healthy." : "Server unreachable."
                    session.registerActivity()
                }
            }
            .disabled(syncBusy || syncBaseUrl.isEmpty)
            Button("Register & upload") {
                Task { await registerUpload() }
            }
            .disabled(syncBusy)
            Button("Sync now") {
                Task { await syncNow() }
            }
            .disabled(syncBusy)
            if vaultMismatch {
                Text("This account already has a different vault on the server. Pick one:")
                    .font(KeyholeFonts.meta)
                    .foregroundStyle(KeyholeColors.warn)
                    .padding(.vertical, 4)
                Button("Use server vault here") {
                    Task { await adoptRemote() }
                }
                .disabled(syncBusy || syncPassword.isEmpty)
                Button("Overwrite server with this device", role: .destructive) {
                    Task { await overwriteRemote() }
                }
                .disabled(syncBusy || syncPassword.isEmpty)
            }
            Button("Clear sync settings", role: .destructive) {
                SyncConfigPrefs.clear()
                session.syncConfig = nil
                syncBaseUrl = ""
                syncAccountId = ""
                syncMessage = "Cleared."
                vaultMismatch = false
            }
        } header: {
            KeyholeFieldLabel(text: "Sync (optional)")
        }
        .listRowBackground(KeyholeColors.surface)
    }

    private func registerUpload() async {
        syncBusy = true
        defer { syncBusy = false }
        guard let file = session.exportVault() else {
            syncMessage = "No vault file."
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
            syncMessage = "Registered. Server version \(result.version)."
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
            syncMessage = "Configure sync first."
            return
        }
        let cfg = session.syncConfig ?? SyncConfigPrefs(baseUrl: syncBaseUrl, accountId: syncAccountId)
        do {
            if syncPassword.isEmpty, session.getSyncAuthSecret() == nil {
                syncMessage = "Enter your master password once this session to enable sync."
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
            syncMessage = "Configure sync first."
            return
        }
        guard !syncPassword.isEmpty else {
            syncMessage = "Enter your master password to adopt the server vault."
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
            syncMessage = "Configure sync first."
            return
        }
        guard !syncPassword.isEmpty else {
            syncMessage = "Enter your master password to overwrite the server vault."
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
