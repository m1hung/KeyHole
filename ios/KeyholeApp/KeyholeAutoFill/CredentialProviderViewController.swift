import AuthenticationServices
import SwiftUI
import KeyholeCore

@objc(CredentialProviderViewController)
final class CredentialProviderViewController: ASCredentialProviderViewController {
    private var serviceIdentifiers: [ASCredentialServiceIdentifier] = []
    private var host: UIHostingController<AutoFillRootView>?

    override func prepareCredentialList(for serviceIdentifiers: [ASCredentialServiceIdentifier]) {
        self.serviceIdentifiers = serviceIdentifiers
        showRoot(mode: .list(serviceIdentifiers))
    }

    override func prepareInterfaceToProvideCredential(for credentialIdentity: ASPasswordCredentialIdentity) {
        showRoot(mode: .provide(credentialIdentity))
    }

    override func provideCredentialWithoutUserInteraction(for credentialIdentity: ASPasswordCredentialIdentity) {
        // Vault secrets are never cached unlocked — always require the UI.
        self.extensionContext.cancelRequest(
            withError: NSError(
                domain: ASExtensionErrorDomain,
                code: ASExtensionError.userInteractionRequired.rawValue
            )
        )
    }

    private enum Mode {
        case list([ASCredentialServiceIdentifier])
        case provide(ASPasswordCredentialIdentity)
    }

    private func showRoot(mode: Mode) {
        let pageURLs = pageURLs(for: mode)
        let root = AutoFillRootView(
            pageURLs: pageURLs,
            preferredUser: preferredUser(for: mode),
            onCancel: { [weak self] in
                self?.extensionContext.cancelRequest(
                    withError: NSError(
                        domain: ASExtensionErrorDomain,
                        code: ASExtensionError.userCanceled.rawValue
                    )
                )
            },
            onPick: { [weak self] user, password in
                let cred = ASPasswordCredential(user: user, password: password)
                self?.extensionContext.completeRequest(withSelectedCredential: cred, completionHandler: nil)
            }
        )
        let host = UIHostingController(rootView: root)
        host.view.backgroundColor = .systemBackground
        addChild(host)
        host.view.frame = view.bounds
        host.view.autoresizingMask = [.flexibleWidth, .flexibleHeight]
        view.addSubview(host.view)
        host.didMove(toParent: self)
        self.host = host
    }

    private func pageURLs(for mode: Mode) -> [String] {
        switch mode {
        case .list(let ids):
            return ids.map(\.identifier)
        case .provide(let identity):
            return [identity.serviceIdentifier.identifier]
        }
    }

    private func preferredUser(for mode: Mode) -> String? {
        if case .provide(let identity) = mode {
            return identity.user
        }
        return nil
    }
}

// MARK: - SwiftUI

private struct AutoFillRootView: View {
    let pageURLs: [String]
    let preferredUser: String?
    let onCancel: () -> Void
    let onPick: (String, String) -> Void

    @State private var password = ""
    @State private var error: String?
    @State private var busy = false
    @State private var session: VaultSession?
    @State private var matches: [AutofillMatch] = []
    @State private var showingAllLogins = false
    @State private var query = ""
    @State private var didAutoPromptBiometrics = false

    private var showBiometrics: Bool {
        BiometricUnlockStore.isReady && BiometricUnlockStore.canUseBiometrics
    }

    private var siteLabel: String {
        pageURLs.first.flatMap { parseTarget($0)?.hostname } ?? pageURLs.first ?? "this app"
    }

    private var displayed: [AutofillMatch] {
        let q = query.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        guard !q.isEmpty else { return matches }
        return matches.filter {
            $0.entry.title.lowercased().contains(q)
                || $0.entry.username.lowercased().contains(q)
                || $0.entry.urls.contains(where: { $0.lowercased().contains(q) })
        }
    }

    var body: some View {
        NavigationStack {
            Group {
                if session == nil {
                    unlockForm
                } else if matches.isEmpty {
                    ContentUnavailableView(
                        "No logins in vault",
                        systemImage: "key",
                        description: Text("Unlock succeeded, but this vault has no login entries to offer.")
                    )
                } else {
                    credentialsList
                }
            }
            .navigationTitle("Keyhole")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Cancel", action: onCancel)
                }
            }
            .onAppear { maybeAutoPromptBiometrics() }
        }
    }

    private var credentialsList: some View {
        List {
            if showingAllLogins {
                Section {
                    Text("No saved URL matched \(siteLabel). Pick a login below, or add \(siteLabel) to that entry’s URLs in Keyhole.")
                        .font(.footnote)
                        .foregroundStyle(.secondary)
                }
            }
            ForEach(displayed, id: \.entry.id) { match in
                Button {
                    onPick(match.entry.username, match.entry.password)
                } label: {
                    VStack(alignment: .leading, spacing: 4) {
                        Text(match.entry.title)
                            .font(.headline)
                            .foregroundStyle(.primary)
                        Text(match.entry.username.isEmpty ? "(no username)" : match.entry.username)
                            .font(.subheadline)
                            .foregroundStyle(.secondary)
                        if match.strength != .none {
                            Text(match.strength.rawValue)
                                .font(.caption2)
                                .foregroundStyle(.tertiary)
                        } else if let host = match.entry.urls.first.flatMap({ parseTarget($0)?.hostname }) {
                            Text(host)
                                .font(.caption2)
                                .foregroundStyle(.tertiary)
                        }
                    }
                }
            }
        }
        .searchable(text: $query, prompt: "Search logins")
    }

    private var unlockForm: some View {
        Form {
            if showBiometrics {
                Section {
                    Button {
                        Task { await unlockWithBiometrics() }
                    } label: {
                        HStack {
                            Image(systemName: BiometricUnlockStore.biometryTypeName == "Touch ID"
                                  ? "touchid" : "faceid")
                            Text("Unlock with \(BiometricUnlockStore.biometryTypeName)")
                        }
                    }
                    .disabled(busy)
                }
            }
            Section {
                SecureField("Master password", text: $password)
                    .textContentType(.password)
                if let error {
                    Text(error).foregroundStyle(.red).font(.footnote)
                }
                Button {
                    Task { await unlock(masterPassword: password) }
                } label: {
                    if busy {
                        ProgressView()
                    } else {
                        Text("Unlock")
                    }
                }
                .disabled(busy || password.count < MIN_MASTER_PASSWORD_LENGTH)
            } footer: {
                Text(
                    showBiometrics
                    ? "Uses the same Face ID / Touch ID setup as the Keyhole app. Secrets stay sealed until you unlock."
                    : "AutoFill unlocks your sealed vault on this device only. Enable Face ID in Keyhole Settings to skip typing."
                )
            }
        }
    }

    private func maybeAutoPromptBiometrics() {
        guard showBiometrics, !didAutoPromptBiometrics, !busy, session == nil else { return }
        didAutoPromptBiometrics = true
        Task { await unlockWithBiometrics() }
    }

    private func unlockWithBiometrics() async {
        error = nil
        do {
            let master = try await BiometricUnlockStore.unlockMasterPassword(
                reason: "Unlock Keyhole for AutoFill"
            )
            await unlock(masterPassword: master)
        } catch {
            if case BiometricUnlockError.cancelled = error {
                self.error = nil
            } else {
                self.error = error.localizedDescription
            }
        }
    }

    private func unlock(masterPassword: String) async {
        busy = true
        error = nil
        defer { busy = false }
        let file: VaultFile
        do {
            file = try VaultStore.load()
        } catch {
            self.error = error.localizedDescription
            return
        }
        do {
            let unlocked = try await Task.detached(priority: .userInitiated) {
                try unlockVault(file: file, masterPassword: masterPassword)
            }.value
            session = unlocked
            password = ""
            reloadMatches(from: unlocked.data)
        } catch {
            self.error = error.localizedDescription
            session = nil
        }
    }

    private func reloadMatches(from data: VaultData) {
        var found: [AutofillMatch] = []
        var seen = Set<String>()
        // Subdomain mode covers www / apex and hosts below a saved domain (e.g. old.reddit.com).
        for page in pageURLs {
            for match in matchEntriesForAutofill(data: data, pageUrl: page, mode: .subdomain) {
                if seen.insert(match.entry.id).inserted {
                    found.append(match)
                }
            }
        }
        if found.isEmpty {
            // Native apps often send a bundle id or an unmatched host — still let the user pick.
            found = allLoginEntriesForAutofill(data: data)
            showingAllLogins = !found.isEmpty
        } else {
            showingAllLogins = false
        }
        if let preferredUser, !preferredUser.isEmpty {
            found.sort {
                let a = $0.entry.username == preferredUser
                let b = $1.entry.username == preferredUser
                if a != b { return a && !b }
                return $0.entry.title < $1.entry.title
            }
        }
        matches = found
    }
}
