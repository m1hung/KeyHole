import SwiftUI
import UniformTypeIdentifiers
import KeyholeCore

struct SettingsView: View {
    @Environment(AppVaultSession.self) private var session
    var clipboard: ClipboardController

    @State private var autoLockMinutes: Double = 15
    @State private var clipboardClear: Double = 30
    @State private var lockOnHide = false
    @State private var theme: ThemePreference = .system
    @State private var currentPassword = ""
    @State private var newPassword = ""
    @State private var confirmPassword = ""
    @State private var showImporter = false
    @State private var showExporter = false
    @State private var exportData: Data?
    @State private var confirmReset = false

    // Sync
    @State private var syncBaseUrl = ""
    @State private var syncAccountId = ""
    @State private var syncPassword = ""
    @State private var syncMessage: String?
    @State private var syncBusy = false

    var body: some View {
        NavigationStack {
            Form {
                Section("Security") {
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
                    Picker("Theme", selection: $theme) {
                        Text("System").tag(ThemePreference.system)
                        Text("Light").tag(ThemePreference.light)
                        Text("Dark").tag(ThemePreference.dark)
                    }
                    Button("Save preferences") {
                        Task { await savePrefs() }
                    }
                }

                Section("Master password") {
                    SecureField("Current", text: $currentPassword)
                    SecureField("New (≥12 chars)", text: $newPassword)
                    SecureField("Confirm new", text: $confirmPassword)
                    Button("Change master password") {
                        Task { await changePassword() }
                    }
                    .disabled(newPassword.count < MIN_MASTER_PASSWORD_LENGTH || newPassword != confirmPassword)
                }

                Section("Vault file") {
                    if let url = session.exportVault().map({ _ in VaultStore.shared.vaultFileURL }) {
                        Text(url.path)
                            .font(.caption2)
                            .foregroundStyle(.secondary)
                    }
                    Button("Export vault…") {
                        Task { await prepareExport() }
                    }
                    Button("Import vault…") { showImporter = true }
                    Button("Lock now") { session.lock() }
                    Button("Delete vault from this device", role: .destructive) {
                        confirmReset = true
                    }
                }

                SyncSettingsSection(
                    syncBaseUrl: $syncBaseUrl,
                    syncAccountId: $syncAccountId,
                    syncPassword: $syncPassword,
                    syncMessage: $syncMessage,
                    syncBusy: $syncBusy,
                    session: session
                )

                if let err = session.errorMessage {
                    Section { Text(err).foregroundStyle(.red) }
                }
                if let remaining = clipboard.secondsRemaining {
                    Section {
                        Text("Clipboard clears in \(remaining)s")
                            .font(.caption)
                    }
                }
            }
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
                $0.theme = theme
            }
        }
        clipboard.updateClearAfter(Int(clipboardClear))
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
        Section("Sync (optional)") {
            TextField("Server URL", text: $syncBaseUrl)
                .textInputAutocapitalization(.never)
                .keyboardType(.URL)
            TextField("Account id", text: $syncAccountId)
                .textInputAutocapitalization(.never)
            SecureField("Master password (for sync auth)", text: $syncPassword)
            if let syncMessage {
                Text(syncMessage)
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
            Button("Save sync settings") {
                let cfg = SyncConfigPrefs(baseUrl: syncBaseUrl, accountId: syncAccountId)
                cfg.save()
                session.syncConfig = cfg
                syncMessage = "Sync settings saved (auth secret is never persisted)."
            }
            Button("Test connection") {
                Task {
                    syncBusy = true
                    defer { syncBusy = false }
                    let ok = await SyncClient.healthCheck(baseUrl: syncBaseUrl)
                    syncMessage = ok ? "Server healthy." : "Server unreachable."
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
                    .font(.caption)
                    .foregroundStyle(.secondary)
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
        }
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
        } catch {
            syncMessage = error.localizedDescription
        }
    }
}
