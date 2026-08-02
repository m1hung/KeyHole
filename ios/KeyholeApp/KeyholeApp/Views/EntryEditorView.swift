import SwiftUI
import UniformTypeIdentifiers
import KeyholeCore

private struct DraftCustomField: Identifiable, Equatable {
    var id: String
    var label: String
    var value: String
    var secret: Bool
}

private struct DraftAttachment: Identifiable, Equatable {
    var id: String
    var name: String
    var mimeType: String
    var sizeBytes: Int
    var dataB64: String
}

struct EntryEditorView: View {
    @Environment(AppVaultSession.self) private var session
    @Environment(\.dismiss) private var dismiss

    let entry: Entry?
    let kind: EntryKind
    var initialFolderId: String? = nil
    var onDone: () -> Void

    @State private var title = ""
    @State private var username = ""
    @State private var password = ""
    @State private var revealPassword = false
    @State private var urlsText = ""
    @State private var notes = ""
    @State private var tagsText = ""
    @State private var totpSecret = ""
    @State private var totpDigits = 6
    @State private var totpPeriod = 30
    @State private var totpAlgorithm: TotpAlgorithm = .sha1
    @State private var folderId: String? = nil
    @State private var customFields: [DraftCustomField] = []
    @State private var attachments: [DraftAttachment] = []
    @State private var generatorOptions = DEFAULT_GENERATOR_OPTIONS
    @State private var strength: StrengthResult?
    @State private var showFileImporter = false
    @State private var error: String?

    private var titleValid: Bool {
        !title.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
    }

    var body: some View {
        NavigationStack {
            Form {
                Section {
                    TextField("Title", text: $title)
                    if kind == .login {
                        TextField("Username", text: $username)
                            .textContentType(.username)
                            .textInputAutocapitalization(.never)
                        HStack {
                            if revealPassword {
                                TextField("Password", text: $password)
                                    .textInputAutocapitalization(.never)
                                    .font(KeyholeFonts.secret)
                            } else {
                                SecureField("Password", text: $password)
                                    .textContentType(.password)
                            }
                            Button {
                                revealPassword.toggle()
                            } label: {
                                KeyholeIcon(name: revealPassword ? .eyeOff : .eye, size: 18)
                                    .foregroundStyle(KeyholeColors.accent)
                            }
                            .buttonStyle(.plain)
                        }
                        KeyholeStrengthMeter(strength: strength)
                        HStack {
                            Button("Generate") { generateInline() }
                                .foregroundStyle(KeyholeColors.accent)
                            Button {
                                generateInline()
                            } label: {
                                KeyholeIcon(name: .refresh, size: 16)
                                    .foregroundStyle(KeyholeColors.accent)
                            }
                            .buttonStyle(.plain)
                            .accessibilityLabel("Regenerate")
                            Spacer()
                            Text("\(generatorOptions.length)")
                                .font(KeyholeFonts.meta)
                                .foregroundStyle(KeyholeColors.textDim)
                            Stepper("Len \(generatorOptions.length)", value: $generatorOptions.length, in: MIN_LENGTH...MAX_LENGTH)
                                .labelsHidden()
                        }
                        TextField("URLs (one per line)", text: $urlsText, axis: .vertical)
                            .lineLimit(2...6)
                            .textInputAutocapitalization(.never)
                    }
                } header: {
                    KeyholeFieldLabel(text: kind == .note ? "Note" : "Login")
                }
                .listRowBackground(KeyholeColors.surface)

                if kind == .login {
                    Section {
                        TextField("Authenticator key or otpauth:// URI", text: $totpSecret, axis: .vertical)
                            .lineLimit(1...3)
                            .textInputAutocapitalization(.never)
                            .onChange(of: totpSecret) { _, newValue in
                                applyOtpAuthIfNeeded(newValue)
                            }
                        Stepper("Digits: \(totpDigits)", value: $totpDigits, in: 6...8)
                        Stepper("Period: \(totpPeriod)s", value: $totpPeriod, in: 15...60, step: 15)
                        Picker("Algorithm", selection: $totpAlgorithm) {
                            Text("SHA-1").tag(TotpAlgorithm.sha1)
                            Text("SHA-256").tag(TotpAlgorithm.sha256)
                            Text("SHA-512").tag(TotpAlgorithm.sha512)
                        }
                    } header: {
                        KeyholeFieldLabel(text: "Authenticator")
                    }
                    .listRowBackground(KeyholeColors.surface)
                }

                Section {
                    Picker("Folder", selection: $folderId) {
                        Text("None").tag(Optional<String>.none)
                        if let folders = session.data?.folders {
                            ForEach(folders) { folder in
                                Text(folder.name).tag(Optional(folder.id))
                            }
                        }
                    }
                    TextField("Tags (comma-separated)", text: $tagsText)
                } header: {
                    KeyholeFieldLabel(text: "Organization")
                }
                .listRowBackground(KeyholeColors.surface)

                Section {
                    TextField(kind == .note ? "Write your note…" : "Add a note…", text: $notes, axis: .vertical)
                        .lineLimit(4...12)
                } header: {
                    KeyholeFieldLabel(text: kind == .note ? "Note" : "Notes")
                }
                .listRowBackground(KeyholeColors.surface)

                Section {
                    ForEach($customFields) { $field in
                        VStack(alignment: .leading, spacing: 8) {
                            TextField("Label", text: $field.label)
                            if field.secret {
                                SecureField("Value", text: $field.value)
                            } else {
                                TextField("Value", text: $field.value)
                            }
                            Toggle("Secret", isOn: $field.secret)
                            Button("Remove", role: .destructive) {
                                customFields.removeAll { $0.id == field.id }
                            }
                            .font(KeyholeFonts.meta)
                            .foregroundStyle(KeyholeColors.danger)
                        }
                    }
                    Button("Add custom field") {
                        customFields.append(
                            DraftCustomField(
                                id: UUID().uuidString.lowercased(),
                                label: "",
                                value: "",
                                secret: false
                            )
                        )
                    }
                    .foregroundStyle(KeyholeColors.accent)
                } header: {
                    KeyholeFieldLabel(text: "Custom fields")
                }
                .listRowBackground(KeyholeColors.surface)

                Section {
                    ForEach(attachments) { att in
                        HStack {
                            VStack(alignment: .leading) {
                                Text(att.name)
                                Text("\(att.sizeBytes) bytes")
                                    .font(KeyholeFonts.meta)
                                    .foregroundStyle(KeyholeColors.textDim)
                            }
                            Spacer()
                            Button("Remove", role: .destructive) {
                                attachments.removeAll { $0.id == att.id }
                            }
                            .font(KeyholeFonts.meta)
                            .foregroundStyle(KeyholeColors.danger)
                        }
                    }
                    Button("Add attachment…") { showFileImporter = true }
                        .foregroundStyle(KeyholeColors.accent)
                } header: {
                    KeyholeFieldLabel(text: "Attachments")
                } footer: {
                    Text("Up to \(MAX_ATTACHMENT_BYTES / 1024) KB each.")
                        .font(KeyholeFonts.meta)
                }
                .listRowBackground(KeyholeColors.surface)

                if let entry, !entry.passkeys.isEmpty {
                    Section {
                        Text("Sign in with Safari or AutoFill. Remove here if you no longer need one.")
                            .font(KeyholeFonts.meta)
                            .foregroundStyle(KeyholeColors.textDim)
                        ForEach(entry.passkeys) { pk in
                            VStack(alignment: .leading, spacing: 4) {
                                Text(pk.userDisplayName.isEmpty
                                     ? (pk.userName.isEmpty ? pk.relyingPartyId : pk.userName)
                                     : pk.userDisplayName)
                                    .font(KeyholeFonts.bodySemibold)
                                    .foregroundStyle(KeyholeColors.text)
                                Text(pk.relyingPartyId)
                                    .font(KeyholeFonts.meta)
                                    .foregroundStyle(KeyholeColors.textDim)
                                Button("Remove passkey", role: .destructive) {
                                    Task {
                                        await session.mutate { data in
                                            try removePasskey(data: data, entryId: entry.id, passkeyId: pk.id)
                                        }
                                        onDone()
                                        dismiss()
                                    }
                                }
                                .font(KeyholeFonts.meta)
                                .foregroundStyle(KeyholeColors.danger)
                            }
                        }
                    } header: {
                        KeyholeFieldLabel(text: "Passkeys")
                    }
                    .listRowBackground(KeyholeColors.surface)
                }

                if entry.map({ !$0.history.isEmpty }) == true {
                    Section {
                        Text("Older passwords are saved when you change this one.")
                            .font(KeyholeFonts.meta)
                            .foregroundStyle(KeyholeColors.textDim)
                    } header: {
                        KeyholeFieldLabel(text: "Password history")
                    }
                    .listRowBackground(KeyholeColors.surface)
                }

                if let error {
                    Section {
                        KeyholeErrorBanner(message: error)
                    }
                    .listRowBackground(KeyholeColors.surface)
                }
            }
            .keyholeFormChrome()
            .navigationTitle(entry == nil ? "New \(kind == .note ? "note" : "login")" : "Edit")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Cancel") {
                        onDone()
                        dismiss()
                    }
                }
                ToolbarItem(placement: .confirmationAction) {
                    Button("Save") { Task { await save() } }
                        .disabled(!titleValid || session.busy)
                }
            }
            .onAppear { load() }
            .onChange(of: password) { _, newValue in
                strength = newValue.isEmpty ? nil : estimateStrength(newValue)
            }
            .fileImporter(
                isPresented: $showFileImporter,
                allowedContentTypes: [.data, .item, .content],
                allowsMultipleSelection: false
            ) { result in
                handleImport(result)
            }
        }
    }

    private func load() {
        if let g = session.data?.settings.generator {
            generatorOptions = g
        }
        guard let entry else {
            folderId = initialFolderId
            return
        }
        title = entry.title
        username = entry.username
        password = entry.password
        urlsText = entry.urls.joined(separator: "\n")
        notes = entry.notes
        tagsText = entry.tags.joined(separator: ", ")
        totpSecret = entry.totpSecret ?? ""
        if let cfg = entry.totpConfig {
            totpDigits = cfg.digits
            totpPeriod = cfg.periodSeconds
            totpAlgorithm = cfg.algorithm
        }
        folderId = entry.folderId
        customFields = entry.customFields.map {
            DraftCustomField(id: $0.id, label: $0.label, value: $0.value, secret: $0.secret)
        }
        attachments = entry.attachments.map {
            DraftAttachment(
                id: $0.id,
                name: $0.name,
                mimeType: $0.mimeType,
                sizeBytes: $0.sizeBytes,
                dataB64: $0.dataB64
            )
        }
        strength = password.isEmpty ? nil : estimateStrength(password)
    }

    private func applyOtpAuthIfNeeded(_ raw: String) {
        let trimmed = raw.trimmingCharacters(in: .whitespacesAndNewlines)
        guard trimmed.lowercased().hasPrefix("otpauth://"),
              let parsed = parseOtpAuthUri(trimmed)
        else { return }
        totpSecret = parsed.secret
        totpDigits = parsed.options.digits
        totpPeriod = parsed.options.periodSeconds
        totpAlgorithm = parsed.options.algorithm
        if title.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty, !parsed.label.isEmpty {
            title = parsed.label
        }
    }

    private func generateInline() {
        do {
            password = try generatePassword(generatorOptions)
            strength = strengthFromBits(generatorEntropyBits(generatorOptions))
            revealPassword = true
            error = nil
        } catch {
            self.error = error.localizedDescription
        }
    }

    private func handleImport(_ result: Result<[URL], Error>) {
        do {
            let urls = try result.get()
            guard let url = urls.first else { return }
            let accessed = url.startAccessingSecurityScopedResource()
            defer { if accessed { url.stopAccessingSecurityScopedResource() } }
            let data = try Data(contentsOf: url)
            if data.count > MAX_ATTACHMENT_BYTES {
                error = "Attachment is too large (max \(MAX_ATTACHMENT_BYTES) bytes)."
                return
            }
            let name = url.lastPathComponent
            let mime = UTType(filenameExtension: url.pathExtension)?.preferredMIMEType ?? "application/octet-stream"
            attachments.append(
                DraftAttachment(
                    id: UUID().uuidString.lowercased(),
                    name: name,
                    mimeType: mime,
                    sizeBytes: data.count,
                    dataB64: data.base64EncodedString()
                )
            )
            error = nil
        } catch {
            self.error = error.localizedDescription
        }
    }

    private func save() async {
        let trimmedTitle = title.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmedTitle.isEmpty else {
            error = "Entry title must not be empty."
            return
        }
        let urls = urlsText
            .split(whereSeparator: \.isNewline)
            .map { $0.trimmingCharacters(in: .whitespacesAndNewlines) }
            .filter { !$0.isEmpty }
        let tags = tagsText
            .split(separator: ",")
            .map { $0.trimmingCharacters(in: .whitespacesAndNewlines) }
            .filter { !$0.isEmpty }

        var secret = totpSecret.trimmingCharacters(in: .whitespacesAndNewlines)
        if secret.lowercased().hasPrefix("otpauth://"), let parsed = parseOtpAuthUri(secret) {
            secret = parsed.secret
            totpDigits = parsed.options.digits
            totpPeriod = parsed.options.periodSeconds
            totpAlgorithm = parsed.options.algorithm
        }
        let totp: String? = secret.isEmpty ? nil : secret
        let config = normalizeTotpConfig(
            TotpOptions(digits: totpDigits, periodSeconds: totpPeriod, algorithm: totpAlgorithm)
        )

        let fields = customFields
            .map {
                CustomField(
                    id: $0.id,
                    label: $0.label.trimmingCharacters(in: .whitespacesAndNewlines),
                    value: $0.value,
                    secret: $0.secret
                )
            }
            .filter { !$0.label.isEmpty }
        let atts = attachments.map {
            Attachment(
                id: $0.id,
                name: $0.name,
                mimeType: $0.mimeType,
                sizeBytes: $0.sizeBytes,
                dataB64: $0.dataB64
            )
        }

        if let entry {
            await session.mutate { data in
                try updateEntry(
                    data: data,
                    id: entry.id,
                    patch: UpdateEntryPatch(
                        title: trimmedTitle,
                        username: username,
                        password: password,
                        urls: urls,
                        notes: notes,
                        tags: tags,
                        folderId: .some(folderId),
                        totpSecret: .some(totp),
                        totpConfig: .some(config),
                        customFields: fields,
                        attachments: atts
                    )
                )
            }
        } else {
            await session.mutate { data in
                try createEntry(
                    data: data,
                    input: EntryInput(
                        title: trimmedTitle,
                        kind: kind,
                        username: username,
                        password: password,
                        urls: urls,
                        notes: notes,
                        tags: tags,
                        folderId: folderId,
                        totpSecret: totp,
                        totpConfig: config,
                        customFields: fields,
                        attachments: atts
                    )
                ).data
            }
        }
        if session.errorMessage != nil {
            error = session.errorMessage
            return
        }
        onDone()
        dismiss()
    }
}
