import AuthenticationServices
import CryptoKit
import KeyholeCore
import SwiftUI

@objc(CredentialProviderViewController)
final class CredentialProviderViewController: ASCredentialProviderViewController {
    private var host: UIHostingController<AnyView>?

    // MARK: - Passwords

    override func prepareCredentialList(for serviceIdentifiers: [ASCredentialServiceIdentifier]) {
        show(
            AutoFillRootView(
                mode: .passwordList(serviceIdentifiers),
                onCancel: { [weak self] in self?.cancel(.userCanceled) },
                onPickPassword: { [weak self] user, password in
                    self?.extensionContext.completeRequest(
                        withSelectedCredential: ASPasswordCredential(user: user, password: password),
                        completionHandler: nil
                    )
                },
                onCompleteRegistration: { [weak self] cred in
                    self?.extensionContext.completeRegistrationRequest(using: cred, completionHandler: nil)
                },
                onCompleteAssertion: { [weak self] cred in
                    self?.extensionContext.completeAssertionRequest(using: cred, completionHandler: nil)
                }
            )
        )
    }

    override func prepareInterfaceToProvideCredential(for credentialIdentity: ASPasswordCredentialIdentity) {
        show(
            AutoFillRootView(
                mode: .passwordProvide(credentialIdentity),
                onCancel: { [weak self] in self?.cancel(.userCanceled) },
                onPickPassword: { [weak self] user, password in
                    self?.extensionContext.completeRequest(
                        withSelectedCredential: ASPasswordCredential(user: user, password: password),
                        completionHandler: nil
                    )
                },
                onCompleteRegistration: { _ in },
                onCompleteAssertion: { _ in }
            )
        )
    }

    override func provideCredentialWithoutUserInteraction(for credentialIdentity: ASPasswordCredentialIdentity) {
        cancel(.userInteractionRequired)
    }

    // MARK: - Passkeys (iOS 17+)

    override func prepareInterface(forPasskeyRegistration registrationRequest: ASCredentialRequest) {
        guard let request = registrationRequest as? ASPasskeyCredentialRequest,
              let identity = request.credentialIdentity as? ASPasskeyCredentialIdentity
        else {
            cancel(.failed)
            return
        }
        show(
            AutoFillRootView(
                mode: .passkeyRegister(request, identity),
                onCancel: { [weak self] in self?.cancel(.userCanceled) },
                onPickPassword: { _, _ in },
                onCompleteRegistration: { [weak self] cred in
                    self?.extensionContext.completeRegistrationRequest(using: cred, completionHandler: nil)
                },
                onCompleteAssertion: { _ in }
            )
        )
    }

    override func prepareCredentialList(
        for serviceIdentifiers: [ASCredentialServiceIdentifier],
        requestParameters: ASPasskeyCredentialRequestParameters
    ) {
        show(
            AutoFillRootView(
                mode: .passkeyList(serviceIdentifiers, requestParameters),
                onCancel: { [weak self] in self?.cancel(.userCanceled) },
                onPickPassword: { _, _ in },
                onCompleteRegistration: { _ in },
                onCompleteAssertion: { [weak self] cred in
                    self?.extensionContext.completeAssertionRequest(using: cred, completionHandler: nil)
                }
            )
        )
    }

    override func prepareInterfaceToProvideCredential(for credentialRequest: ASCredentialRequest) {
        if let passwordIdentity = credentialRequest.credentialIdentity as? ASPasswordCredentialIdentity {
            prepareInterfaceToProvideCredential(for: passwordIdentity)
            return
        }
        guard let request = credentialRequest as? ASPasskeyCredentialRequest,
              let identity = request.credentialIdentity as? ASPasskeyCredentialIdentity
        else {
            cancel(.failed)
            return
        }
        show(
            AutoFillRootView(
                mode: .passkeyProvide(request, identity),
                onCancel: { [weak self] in self?.cancel(.userCanceled) },
                onPickPassword: { _, _ in },
                onCompleteRegistration: { _ in },
                onCompleteAssertion: { [weak self] cred in
                    self?.extensionContext.completeAssertionRequest(using: cred, completionHandler: nil)
                }
            )
        )
    }

    override func provideCredentialWithoutUserInteraction(for credentialRequest: ASCredentialRequest) {
        // Vault secrets are never cached unlocked — always require the UI.
        cancel(.userInteractionRequired)
    }

    // MARK: - Helpers

    private func show<Content: View>(_ root: Content) {
        children.forEach { child in
            child.willMove(toParent: nil)
            child.view.removeFromSuperview()
            child.removeFromParent()
        }
        let host = UIHostingController(rootView: AnyView(root))
        host.view.backgroundColor = UIColor(KeyholeColors.bg)
        addChild(host)
        host.view.frame = view.bounds
        host.view.autoresizingMask = [.flexibleWidth, .flexibleHeight]
        view.addSubview(host.view)
        host.didMove(toParent: self)
        self.host = host
    }

    private func cancel(_ code: ASExtensionError.Code) {
        extensionContext.cancelRequest(
            withError: NSError(domain: ASExtensionErrorDomain, code: code.rawValue)
        )
    }
}

// MARK: - SwiftUI

private enum AutoFillMode {
    case passwordList([ASCredentialServiceIdentifier])
    case passwordProvide(ASPasswordCredentialIdentity)
    case passkeyRegister(ASPasskeyCredentialRequest, ASPasskeyCredentialIdentity)
    case passkeyProvide(ASPasskeyCredentialRequest, ASPasskeyCredentialIdentity)
    case passkeyList([ASCredentialServiceIdentifier], ASPasskeyCredentialRequestParameters)
}

private struct AutoFillRootView: View {
    let mode: AutoFillMode
    let onCancel: () -> Void
    let onPickPassword: (String, String) -> Void
    let onCompleteRegistration: (ASPasskeyRegistrationCredential) -> Void
    let onCompleteAssertion: (ASPasskeyAssertionCredential) -> Void

    @State private var password = ""
    @State private var error: String?
    @State private var busy = false
    @State private var session: VaultSession?
    @State private var previousFile: VaultFile?
    @State private var matches: [AutofillMatch] = []
    @State private var passkeyMatches: [(entry: Entry, passkey: PasskeyRecord)] = []
    @State private var showingAllLogins = false
    @State private var query = ""
    @State private var didAutoPromptBiometrics = false
    @State private var didAutoComplete = false

    private var showBiometrics: Bool {
        BiometricUnlockStore.isReady && BiometricUnlockStore.canUseBiometrics
    }

    private var pageURLs: [String] {
        switch mode {
        case .passwordList(let ids):
            return ids.map(\.identifier)
        case .passwordProvide(let identity):
            return [identity.serviceIdentifier.identifier]
        case .passkeyRegister(_, let identity):
            return [identity.relyingPartyIdentifier]
        case .passkeyProvide(_, let identity):
            return [identity.relyingPartyIdentifier]
        case .passkeyList(let ids, let params):
            return [params.relyingPartyIdentifier] + ids.map(\.identifier)
        }
    }

    private var siteLabel: String {
        switch mode {
        case .passkeyRegister(_, let identity), .passkeyProvide(_, let identity):
            return identity.relyingPartyIdentifier
        case .passkeyList(_, let params):
            return params.relyingPartyIdentifier
        default:
            return pageURLs.first.flatMap { parseTarget($0)?.hostname } ?? pageURLs.first ?? "this app"
        }
    }

    private var preferredUser: String? {
        if case .passwordProvide(let identity) = mode { return identity.user }
        return nil
    }

    private var preferredRecordId: String? {
        if case .passwordProvide(let identity) = mode { return identity.recordIdentifier }
        return nil
    }

    private var isPasskeyFlow: Bool {
        switch mode {
        case .passkeyRegister, .passkeyProvide, .passkeyList: return true
        default: return false
        }
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
                } else {
                    unlockedContent
                }
            }
            .navigationTitle("Keyhole")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Cancel", action: onCancel)
                        .foregroundStyle(KeyholeColors.accent)
                }
            }
            .toolbarBackground(KeyholeColors.surface, for: .navigationBar)
            .toolbarBackground(.visible, for: .navigationBar)
            .background(KeyholeColors.bg.ignoresSafeArea())
            .tint(KeyholeColors.accent)
            .onAppear {
                KeyholeAppearance.apply()
                maybeAutoPromptBiometrics()
            }
        }
    }

    @ViewBuilder
    private var unlockedContent: some View {
        switch mode {
        case .passkeyRegister(_, let identity):
            passkeyRegisterConfirm(identity: identity)
        case .passkeyProvide, .passkeyList:
            if passkeyMatches.isEmpty {
                ContentUnavailableView {
                    Label {
                        Text("No passkeys")
                    } icon: {
                        KeyholeIcon(name: .key, size: 36)
                            .foregroundStyle(KeyholeColors.textDim)
                    }
                } description: {
                    Text("No passkey saved for \(siteLabel).")
                        .foregroundStyle(KeyholeColors.textDim)
                }
                .frame(maxWidth: .infinity, maxHeight: .infinity)
                .background(KeyholeColors.bg)
            } else {
                passkeyList
            }
        default:
            if matches.isEmpty {
                ContentUnavailableView {
                    Label {
                        Text("No logins")
                    } icon: {
                        KeyholeIcon(name: .key, size: 36)
                            .foregroundStyle(KeyholeColors.textDim)
                    }
                } description: {
                    Text("Add a login in Keyhole, then try again.")
                        .foregroundStyle(KeyholeColors.textDim)
                }
                .frame(maxWidth: .infinity, maxHeight: .infinity)
                .background(KeyholeColors.bg)
            } else {
                credentialsList
            }
        }
    }

    private var credentialsList: some View {
        List {
            if showingAllLogins {
                Section {
                    Text("No saved login matched \(siteLabel). Pick one below.")
                        .font(KeyholeFonts.meta)
                        .foregroundStyle(KeyholeColors.textDim)
                }
                .listRowBackground(KeyholeColors.accentSoft)
            }
            ForEach(displayed, id: \.entry.id) { match in
                Button {
                    onPickPassword(match.entry.username, match.entry.password)
                } label: {
                    HStack(spacing: 12) {
                        KeyholeIcon(name: .key, size: 18)
                            .foregroundStyle(KeyholeColors.textDim)
                        VStack(alignment: .leading, spacing: 2) {
                            Text(match.entry.title)
                                .font(KeyholeFonts.bodySemibold)
                                .foregroundStyle(KeyholeColors.text)
                            Text(match.entry.username.isEmpty ? "(no username)" : match.entry.username)
                                .font(KeyholeFonts.meta)
                                .foregroundStyle(KeyholeColors.textDim)
                            if match.strength != .none {
                                Text(match.strength.rawValue)
                                    .font(KeyholeFonts.caption)
                                    .foregroundStyle(KeyholeColors.textDim)
                            } else if let host = match.entry.urls.first.flatMap({ parseTarget($0)?.hostname }) {
                                Text(host)
                                    .font(KeyholeFonts.caption)
                                    .foregroundStyle(KeyholeColors.textDim)
                            }
                        }
                    }
                }
                .listRowBackground(KeyholeColors.surface)
            }
        }
        .listStyle(.plain)
        .keyholeFormChrome()
        .searchable(text: $query, prompt: "Search logins")
    }

    private var passkeyList: some View {
        List {
            ForEach(passkeyMatches, id: \.passkey.id) { item in
                Button {
                    Task { await completePasskeyAssertion(entry: item.entry, passkey: item.passkey) }
                } label: {
                    HStack(spacing: 12) {
                        KeyholeIcon(name: .key, size: 18)
                            .foregroundStyle(KeyholeColors.textDim)
                        VStack(alignment: .leading, spacing: 2) {
                            Text(item.passkey.userName.isEmpty ? item.entry.title : item.passkey.userName)
                                .font(KeyholeFonts.bodySemibold)
                                .foregroundStyle(KeyholeColors.text)
                            Text(item.passkey.relyingPartyId)
                                .font(KeyholeFonts.meta)
                                .foregroundStyle(KeyholeColors.textDim)
                        }
                    }
                }
                .disabled(busy)
                .listRowBackground(KeyholeColors.surface)
            }
        }
        .listStyle(.plain)
        .keyholeFormChrome()
    }

    private func passkeyRegisterConfirm(identity: ASPasskeyCredentialIdentity) -> some View {
        Form {
            Section {
                LabeledContent("Website", value: identity.relyingPartyIdentifier)
                LabeledContent("Account", value: identity.userName.isEmpty ? "—" : identity.userName)
            } footer: {
                Text("Keyhole will create a passkey and save it in your vault.")
                    .font(KeyholeFonts.meta)
                    .foregroundStyle(KeyholeColors.textDim)
            }
            .listRowBackground(KeyholeColors.surface)
            if let error {
                Section {
                    KeyholeErrorBanner(message: error)
                }
                .listRowBackground(KeyholeColors.surface)
            }
            Section {
                Button {
                    Task { await completePasskeyRegistration(identity: identity) }
                } label: {
                    if busy {
                        ProgressView()
                            .tint(KeyholeColors.accent)
                    } else {
                        Text("Save passkey")
                    }
                }
                .foregroundStyle(KeyholeColors.accent)
                .disabled(busy)
            }
            .listRowBackground(KeyholeColors.surface)
        }
        .keyholeFormChrome()
    }

    private var unlockForm: some View {
        Form {
            if showBiometrics {
                Section {
                    Button {
                        Task { await unlockWithBiometrics() }
                    } label: {
                        HStack(spacing: 8) {
                            Image(systemName: BiometricUnlockStore.biometryTypeName == "Touch ID"
                                  ? "touchid" : "faceid")
                            Text("Unlock with \(BiometricUnlockStore.biometryTypeName)")
                        }
                        .font(KeyholeFonts.bodySemibold)
                        .foregroundStyle(KeyholeColors.accent)
                    }
                    .disabled(busy)
                }
                .listRowBackground(KeyholeColors.surface)
            }
            Section {
                SecureField("Master password", text: $password)
                    .textContentType(.password)
                    .foregroundStyle(KeyholeColors.text)
                if let error {
                    KeyholeErrorBanner(message: error)
                }
                Button {
                    Task { await unlock(masterPassword: password) }
                } label: {
                    if busy {
                        ProgressView()
                            .tint(KeyholeColors.accent)
                    } else {
                        Text("Unlock")
                            .font(KeyholeFonts.bodySemibold)
                    }
                }
                .foregroundStyle(KeyholeColors.accent)
                .disabled(busy || password.count < MIN_MASTER_PASSWORD_LENGTH)
            } footer: {
                Text(
                    showBiometrics
                    ? "Unlock with \(BiometricUnlockStore.biometryTypeName) or your password."
                    : isPasskeyFlow
                      ? "Enter your master password to continue with this passkey."
                      : "Enter your master password to fill this login."
                )
                .font(KeyholeFonts.meta)
                .foregroundStyle(KeyholeColors.textDim)
            }
            .listRowBackground(KeyholeColors.surface)
        }
        .keyholeFormChrome()
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
            previousFile = file
            password = ""

            if case .passwordProvide = mode,
               let preferredRecordId,
               let entry = liveEntries(unlocked.data).first(where: { $0.id == preferredRecordId && $0.kind == .login })
            {
                onPickPassword(entry.username, entry.password)
                return
            }

            if case .passkeyProvide(_, let identity) = mode,
               !didAutoComplete,
               let found = findPasskey(credentialId: identity.credentialID, in: unlocked.data)
            {
                didAutoComplete = true
                await completePasskeyAssertion(entry: found.entry, passkey: found.passkey)
                return
            }

            reloadMatches(from: unlocked.data)
        } catch {
            self.error = error.localizedDescription
            session = nil
            previousFile = nil
        }
    }

    private func reloadMatches(from data: VaultData) {
        switch mode {
        case .passkeyRegister:
            passkeyMatches = []
            matches = []
        case .passkeyProvide(_, let identity):
            if let found = findPasskey(credentialId: identity.credentialID, in: data) {
                passkeyMatches = [found]
            } else {
                passkeyMatches = findPasskeys(forRelyingParty: identity.relyingPartyIdentifier, in: data)
            }
        case .passkeyList(_, let params):
            passkeyMatches = findPasskeys(forRelyingParty: params.relyingPartyIdentifier, in: data)
        default:
            var found: [AutofillMatch] = []
            var seen = Set<String>()
            for page in pageURLs {
                for match in matchEntriesForAutofill(data: data, pageUrl: page, mode: .subdomain) {
                    if seen.insert(match.entry.id).inserted {
                        found.append(match)
                    }
                }
            }
            if found.isEmpty {
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

    private func completePasskeyRegistration(identity: ASPasskeyCredentialIdentity) async {
        guard var sess = session, let previous = previousFile,
              case .passkeyRegister(let request, _) = mode
        else { return }
        busy = true
        error = nil
        defer { busy = false }
        do {
            let privateKey = P256.Signing.PrivateKey()
            let credentialId = WebAuthnCrypto.generateCredentialId()
            let attestation = WebAuthnCrypto.buildRegistration(
                relyingPartyId: identity.relyingPartyIdentifier,
                privateKey: privateKey,
                credentialId: credentialId
            )
            let record = PasskeyRecord(
                id: KeyholeCrypto.randomUuid(),
                credentialIdB64: credentialId.base64EncodedString(),
                relyingPartyId: identity.relyingPartyIdentifier,
                relyingPartyName: identity.relyingPartyIdentifier,
                userName: identity.userName,
                userDisplayName: identity.userName,
                userHandleB64: identity.userHandle.base64EncodedString(),
                privateKeyB64: privateKey.rawRepresentation.base64EncodedString(),
                signCount: 0,
                createdAt: nowISO(),
                lastUsedAt: nil
            )
            let stored = try storePasskey(data: sess.data, record: record)
            sess.data = stored.data
            let saved = try saveVault(session: &sess, previous: previous)
            try VaultStore.save(saved)
            session = sess
            previousFile = saved
            await QuickTypeCredentialStore.publish(from: sess.data)

            let registration = ASPasskeyRegistrationCredential(
                relyingParty: identity.relyingPartyIdentifier,
                clientDataHash: request.clientDataHash,
                credentialID: credentialId,
                attestationObject: attestation
            )
            onCompleteRegistration(registration)
        } catch {
            self.error = error.localizedDescription
        }
    }

    private func completePasskeyAssertion(entry: Entry, passkey: PasskeyRecord) async {
        guard var sess = session, let previous = previousFile else { return }
        busy = true
        error = nil
        defer { busy = false }

        let clientDataHash: Data
        let relyingParty: String
        switch mode {
        case .passkeyProvide(let request, let identity):
            clientDataHash = request.clientDataHash
            relyingParty = identity.relyingPartyIdentifier
        case .passkeyList(_, let params):
            clientDataHash = params.clientDataHash
            relyingParty = params.relyingPartyIdentifier
        default:
            return
        }

        do {
            guard let keyData = Data(base64Encoded: passkey.privateKeyB64),
                  let credentialId = Data(base64Encoded: passkey.credentialIdB64),
                  let userHandle = Data(base64Encoded: passkey.userHandleB64)
            else {
                throw KeyholeError.validation("Passkey data is damaged.")
            }
            let privateKey = try P256.Signing.PrivateKey(rawRepresentation: keyData)
            let nextCount = passkey.signCount &+ 1
            let usedAt = nowISO()
            let (authData, signature) = try WebAuthnCrypto.buildAssertion(
                relyingPartyId: relyingParty,
                clientDataHash: clientDataHash,
                signCount: nextCount,
                privateKey: privateKey
            )
            sess.data = try updatePasskeySignCount(
                data: sess.data,
                entryId: entry.id,
                passkeyId: passkey.id,
                signCount: nextCount,
                lastUsedAt: usedAt
            )
            let saved = try saveVault(session: &sess, previous: previous)
            try VaultStore.save(saved)
            session = sess
            previousFile = saved

            let assertion = ASPasskeyAssertionCredential(
                userHandle: userHandle,
                relyingParty: relyingParty,
                signature: signature,
                clientDataHash: clientDataHash,
                authenticatorData: authData,
                credentialID: credentialId
            )
            onCompleteAssertion(assertion)
        } catch {
            self.error = error.localizedDescription
        }
    }
}
