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

    var body: some View {
        NavigationStack {
            Group {
                if session == nil {
                    unlockForm
                } else if matches.isEmpty {
                    ContentUnavailableView(
                        "No logins for this site",
                        systemImage: "key",
                        description: Text("No unlocked login URLs match \(pageURLs.first ?? "this page").")
                    )
                } else {
                    List(matches, id: \.entry.id) { match in
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
                                Text(match.strength.rawValue)
                                    .font(.caption2)
                                    .foregroundStyle(.tertiary)
                            }
                        }
                    }
                }
            }
            .navigationTitle("Keyhole")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Cancel", action: onCancel)
                }
            }
        }
    }

    private var unlockForm: some View {
        Form {
            Section {
                SecureField("Master password", text: $password)
                    .textContentType(.password)
                if let error {
                    Text(error).foregroundStyle(.red).font(.footnote)
                }
                Button {
                    Task { await unlock() }
                } label: {
                    if busy {
                        ProgressView()
                    } else {
                        Text("Unlock")
                    }
                }
                .disabled(busy || password.count < MIN_MASTER_PASSWORD_LENGTH)
            } footer: {
                Text("AutoFill unlocks your sealed vault on this device only. The master password is never stored.")
            }
        }
    }

    private func unlock() async {
        busy = true
        error = nil
        defer { busy = false }
        guard let file = VaultStore.shared.load() else {
            error = "No vault found. Open Keyhole and create or import a vault first."
            return
        }
        do {
            let unlocked = try await Task.detached(priority: .userInitiated) {
                try unlockVault(file: file, masterPassword: password)
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
        for page in pageURLs {
            for match in matchEntriesForAutofill(data: data, pageUrl: page, mode: .host) {
                if seen.insert(match.entry.id).inserted {
                    found.append(match)
                }
            }
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
