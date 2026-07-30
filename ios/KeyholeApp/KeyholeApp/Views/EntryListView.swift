import SwiftUI
import KeyholeCore

enum VaultListFilter: Equatable {
    case all
    case logins
    case notes
    case trash
    case folder(String)
}

struct EntryListView: View {
    @Environment(AppVaultSession.self) private var session
    var clipboard: ClipboardController
    @State private var query = ""
    @State private var filter: VaultListFilter = .all
    @State private var showEditor = false
    @State private var newKind: EntryKind = .login
    @State private var newFolderName = ""
    @State private var showNewFolder = false
    @State private var purgeTarget: Entry?
    @State private var purgeConfirmTitle = ""

    private var data: VaultData? { session.data }

    private var trashed: [Entry] {
        guard let data else { return [] }
        return trashedEntries(data)
    }

    private var displayed: [Entry] {
        guard let data else { return [] }
        let q = query.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        let base: [Entry]
        switch filter {
        case .trash:
            base = trashed
        case .all:
            base = searchEntries(data: data, query: query)
            return base
        case .logins:
            base = liveEntries(data).filter { $0.kind == .login }
        case .notes:
            base = liveEntries(data).filter { $0.kind == .note }
        case .folder(let id):
            base = liveEntries(data).filter { $0.folderId == id }
        }
        guard !q.isEmpty else {
            return base.sorted { $0.title.localizedCaseInsensitiveCompare($1.title) == .orderedAscending }
        }
        return base.filter { e in
            e.title.lowercased().contains(q)
                || e.username.lowercased().contains(q)
                || e.tags.contains(where: { $0.lowercased().contains(q) })
                || e.urls.contains(where: { $0.lowercased().contains(q) })
        }.sorted { $0.title.localizedCaseInsensitiveCompare($1.title) == .orderedAscending }
    }

    var body: some View {
        NavigationStack {
            VStack(spacing: 0) {
                filterBar
                Divider().overlay(KeyholeColors.border)
                listBody
            }
            .background(KeyholeColors.bg)
            .navigationTitle("Vault")
            .searchable(text: $query, prompt: "Search titles, usernames, URLs, tags")
            .toolbar { toolbarContent }
            .sheet(isPresented: $showEditor) {
                EntryEditorView(entry: nil, kind: newKind, initialFolderId: folderIdForNew) {
                    showEditor = false
                    session.registerActivity()
                }
            }
            .alert("New folder", isPresented: $showNewFolder) {
                TextField("Folder name", text: $newFolderName)
                Button("Cancel", role: .cancel) { newFolderName = "" }
                Button("Add") {
                    let name = newFolderName
                    newFolderName = ""
                    Task {
                        await session.mutate { try createFolder(data: $0, name: name).data }
                        session.registerActivity()
                    }
                }
            }
            .alert(
                "Permanently delete?",
                isPresented: Binding(
                    get: { purgeTarget != nil },
                    set: { if !$0 { purgeTarget = nil; purgeConfirmTitle = "" } }
                )
            ) {
                TextField("Type entry title to confirm", text: $purgeConfirmTitle)
                Button("Cancel", role: .cancel) {
                    purgeTarget = nil
                    purgeConfirmTitle = ""
                }
                Button("Purge forever", role: .destructive) {
                    guard let target = purgeTarget, purgeConfirmTitle == target.title else { return }
                    let id = target.id
                    purgeTarget = nil
                    purgeConfirmTitle = ""
                    Task {
                        await session.mutate { try purgeEntry(data: $0, id: id) }
                        session.registerActivity()
                    }
                }
                .disabled(purgeTarget.map { purgeConfirmTitle != $0.title } ?? true)
            } message: {
                if let target = purgeTarget {
                    Text("This permanently deletes \"\(target.title)\" and its password history.")
                }
            }
        }
    }

    private var folderIdForNew: String? {
        if case .folder(let id) = filter { return id }
        return nil
    }

    private var filterBar: some View {
        ScrollView(.horizontal, showsIndicators: false) {
            HStack(spacing: 8) {
                KeyholeFilterChip(title: "All", active: filter == .all) {
                    filter = .all
                    session.registerActivity()
                }
                KeyholeFilterChip(title: "Logins", icon: .key, active: filter == .logins) {
                    filter = .logins
                    session.registerActivity()
                }
                KeyholeFilterChip(title: "Notes", icon: .secureNote, active: filter == .notes) {
                    filter = .notes
                    session.registerActivity()
                }
                if !trashed.isEmpty {
                    KeyholeFilterChip(
                        title: "Trash",
                        count: trashed.count,
                        icon: .trash,
                        active: filter == .trash
                    ) {
                        filter = .trash
                        session.registerActivity()
                    }
                }
                if let data {
                    ForEach(data.folders) { folder in
                        let count = liveEntries(data).filter { $0.folderId == folder.id }.count
                        KeyholeFilterChip(
                            title: folder.name,
                            count: count,
                            active: filter == .folder(folder.id)
                        ) {
                            filter = .folder(folder.id)
                            session.registerActivity()
                        }
                    }
                }
                Button {
                    showNewFolder = true
                } label: {
                    HStack(spacing: 4) {
                        KeyholeIcon(name: .folderPlus, size: 12)
                        Text("Folder")
                    }
                    .font(KeyholeFonts.caption)
                    .foregroundStyle(KeyholeColors.accent)
                    .padding(.horizontal, 10)
                    .padding(.vertical, 6)
                }
                .buttonStyle(.plain)

                if case .folder(let id) = filter {
                    Button("Delete folder", role: .destructive) {
                        filter = .all
                        Task {
                            await session.mutate { deleteFolder(data: $0, id: id) }
                            session.registerActivity()
                        }
                    }
                    .font(KeyholeFonts.caption)
                }
            }
            .padding(.horizontal, 16)
            .padding(.vertical, 10)
        }
        .background(KeyholeColors.surface)
    }

    @ViewBuilder
    private var listBody: some View {
        if displayed.isEmpty {
            ContentUnavailableView {
                Label {
                    Text(emptyTitle)
                } icon: {
                    KeyholeIcon(name: emptyIcon, size: 40)
                        .foregroundStyle(KeyholeColors.textDim)
                }
            } description: {
                Text(emptyDescription)
            }
            .frame(maxWidth: .infinity, maxHeight: .infinity)
            .background(KeyholeColors.bg)
        } else if filter == .trash {
            List {
                ForEach(displayed) { entry in
                    trashRow(entry)
                }
            }
            .listStyle(.plain)
            .scrollContentBackground(.hidden)
        } else {
            List {
                if let version = session.foreignSchemaVersion {
                    Section {
                        Label {
                            Text(
                                """
                                Written by a newer version of Keyhole (vault format \(version)). \
                                Everything still works and nothing is lost, but newer fields are not shown here.
                                """
                            )
                        } icon: {
                            KeyholeIcon(name: .refresh, size: 16)
                        }
                        .font(KeyholeFonts.meta)
                        .foregroundStyle(KeyholeColors.textDim)
                        .listRowBackground(KeyholeColors.accentSoft)
                    }
                }
                ForEach(displayed) { entry in
                    NavigationLink {
                        EntryDetailView(entryId: entry.id, clipboard: clipboard)
                    } label: {
                        entryRow(entry)
                    }
                    .listRowBackground(KeyholeColors.surface)
                    .swipeActions(edge: .trailing, allowsFullSwipe: true) {
                        Button(role: .destructive) {
                            Task {
                                await session.mutate { try deleteEntry(data: $0, id: entry.id) }
                                session.registerActivity()
                            }
                        } label: {
                            Label {
                                Text("Move to Trash")
                            } icon: {
                                KeyholeIcon(name: .trash, size: 18)
                            }
                        }
                    }
                }
            }
            .listStyle(.plain)
            .scrollContentBackground(.hidden)
        }
    }

    private func entryRow(_ entry: Entry) -> some View {
        HStack(spacing: 12) {
            KeyholeIcon(name: entry.kind == .note ? .secureNote : .key, size: 18)
                .foregroundStyle(KeyholeColors.textDim)
                .frame(width: 18)
            VStack(alignment: .leading, spacing: 2) {
                Text(entry.title)
                    .font(KeyholeFonts.bodySemibold)
                    .foregroundStyle(KeyholeColors.text)
                    .lineLimit(1)
                if entry.kind == .login, !entry.username.isEmpty {
                    Text(entry.username)
                        .font(KeyholeFonts.meta)
                        .foregroundStyle(KeyholeColors.textDim)
                        .lineLimit(1)
                } else if entry.kind == .note {
                    Text("Note")
                        .font(KeyholeFonts.meta)
                        .foregroundStyle(KeyholeColors.textDim)
                }
            }
            Spacer(minLength: 0)
            if !entry.tags.isEmpty {
                Text(entry.tags.prefix(2).joined(separator: ", "))
                    .font(KeyholeFonts.caption)
                    .foregroundStyle(KeyholeColors.accent)
                    .padding(.horizontal, 8)
                    .padding(.vertical, 3)
                    .background(KeyholeColors.accentSoft)
                    .clipShape(Capsule())
            }
        }
        .padding(.vertical, 4)
    }

    private func trashRow(_ entry: Entry) -> some View {
        VStack(alignment: .leading, spacing: 8) {
            Text(entry.title)
                .font(KeyholeFonts.bodySemibold)
                .foregroundStyle(KeyholeColors.text)
            if let deleted = entry.deletedAt {
                Text("Deleted \(deleted)")
                    .font(KeyholeFonts.meta)
                    .foregroundStyle(KeyholeColors.textDim)
            }
            HStack {
                Button("Restore") {
                    Task {
                        await session.mutate { try restoreEntry(data: $0, id: entry.id) }
                        session.registerActivity()
                    }
                }
                .buttonStyle(KeyholeGhostButtonStyle())
                Button("Purge", role: .destructive) {
                    purgeTarget = entry
                    purgeConfirmTitle = ""
                }
                .foregroundStyle(KeyholeColors.danger)
            }
        }
        .listRowBackground(KeyholeColors.surface)
    }

    private var emptyTitle: String {
        if !query.isEmpty { return "No matches" }
        switch filter {
        case .trash: return "Trash is empty"
        case .folder: return "This folder is empty"
        default: return "No entries yet"
        }
    }

    private var emptyIcon: KeyholeIconName {
        if !query.isEmpty { return .eye }
        switch filter {
        case .trash: return .trash
        case .folder: return .folder
        default: return .vault
        }
    }

    private var emptyDescription: String {
        if !query.isEmpty { return "Try a different search." }
        switch filter {
        case .trash: return "Deleted entries appear here for 30 days."
        case .folder: return "Add an entry and assign it to this folder."
        default: return "Tap + to add a login or note."
        }
    }

    @ToolbarContentBuilder
    private var toolbarContent: some ToolbarContent {
        if let secs = session.secondsUntilLock {
            ToolbarItem(placement: .topBarLeading) {
                Button {
                    session.lock()
                } label: {
                    HStack(spacing: 4) {
                        KeyholeIcon(name: .clock, size: 14)
                        Text("\(secs)s")
                            .font(KeyholeFonts.caption)
                            .monospacedDigit()
                    }
                    .foregroundStyle(secs <= 30 ? KeyholeColors.warn : KeyholeColors.textDim)
                }
                .accessibilityLabel("Lock vault now, auto-locks in \(secs) seconds")
            }
        }
        ToolbarItem(placement: .topBarTrailing) {
            Menu {
                Button("Login") {
                    newKind = .login
                    showEditor = true
                }
                Button("Secure note") {
                    newKind = .note
                    showEditor = true
                }
            } label: {
                KeyholeIcon(name: .plus, size: 20)
                    .foregroundStyle(KeyholeColors.accent)
            }
            .disabled(filter == .trash)
            .accessibilityLabel("Add entry")
        }
        ToolbarItem(placement: .topBarTrailing) {
            Button {
                session.lock()
            } label: {
                KeyholeIcon(name: .lock, size: 20)
                    .foregroundStyle(KeyholeColors.accent)
            }
            .accessibilityLabel("Lock vault")
        }
    }
}

struct EntryDetailView: View {
    let entryId: String
    var clipboard: ClipboardController
    @Environment(AppVaultSession.self) private var session
    @State private var revealPassword = false
    @State private var revealedHistory: Set<String> = []
    @State private var totpCode: TotpCode?
    @State private var totpError: String?
    @State private var showEditor = false
    @State private var timer: Timer?
    @State private var shareItem: SharePayload?

    private var entry: Entry? {
        session.data.flatMap { getEntry(data: $0, id: entryId) }
    }

    private var folderName: String? {
        guard let entry, let id = entry.folderId else { return nil }
        return session.data?.folders.first(where: { $0.id == id })?.name
    }

    var body: some View {
        Group {
            if let entry {
                Form {
                    Section {
                        Text(entry.title)
                            .font(KeyholeFonts.detailTitle)
                            .foregroundStyle(KeyholeColors.text)
                        if let folderName {
                            HStack(spacing: 6) {
                                KeyholeIcon(name: .folder, size: 14)
                                Text(folderName)
                            }
                            .font(KeyholeFonts.meta)
                            .foregroundStyle(KeyholeColors.textDim)
                        }
                        Text("Updated \(entry.updatedAt)")
                            .font(KeyholeFonts.meta)
                            .foregroundStyle(KeyholeColors.textDim)
                    }
                    .listRowBackground(KeyholeColors.surface)

                    if entry.kind == .login {
                        Section {
                            if !entry.username.isEmpty {
                                LabeledContent("Username") {
                                    Text(entry.username)
                                        .font(KeyholeFonts.body)
                                }
                                Button("Copy username") {
                                    clipboard.copy(entry.username, label: "Username")
                                    session.registerActivity()
                                }
                            }
                            HStack {
                                Text("Password")
                                Spacer()
                                Text(revealPassword ? entry.password : String(repeating: "•", count: max(8, entry.password.count)))
                                    .font(KeyholeFonts.secret)
                                    .tracking(revealPassword ? 0 : 1.2)
                            }
                            Button {
                                revealPassword.toggle()
                            } label: {
                                KeyholeIcon(name: revealPassword ? .eyeOff : .eye, size: 18)
                            }
                            Button {
                                clipboard.copy(entry.password, label: "Password")
                                session.registerActivity()
                            } label: {
                                Label {
                                    Text("Copy password")
                                } icon: {
                                    KeyholeIcon(name: .copy, size: 16)
                                }
                            }
                        } header: {
                            KeyholeFieldLabel(text: "Login")
                        }
                        .listRowBackground(KeyholeColors.surface)
                    }

                    if entry.kind == .login, let secret = entry.totpSecret, !secret.isEmpty {
                        Section {
                            if let totpCode {
                                HStack {
                                    Text(totpCode.code)
                                        .font(KeyholeFonts.totp)
                                        .tracking(1.5)
                                    Spacer()
                                    Text("\(totpCode.secondsRemaining)s")
                                        .foregroundStyle(KeyholeColors.textDim)
                                }
                                Button("Copy code") {
                                    clipboard.copy(totpCode.code, label: "TOTP")
                                    session.registerActivity()
                                }
                            } else if let totpError {
                                Text(totpError)
                                    .foregroundStyle(KeyholeColors.danger)
                                    .font(KeyholeFonts.meta)
                            }
                        } header: {
                            KeyholeFieldLabel(text: "Authenticator")
                        }
                        .listRowBackground(KeyholeColors.surface)
                    }

                    if !entry.urls.isEmpty {
                        Section {
                            ForEach(entry.urls, id: \.self) { url in
                                if let link = URL(string: url), link.scheme != nil {
                                    Link(url, destination: link)
                                        .font(KeyholeFonts.meta)
                                } else {
                                    Text(url)
                                        .font(KeyholeFonts.meta)
                                        .foregroundStyle(KeyholeColors.accent)
                                }
                            }
                        } header: {
                            KeyholeFieldLabel(text: "URLs")
                        }
                        .listRowBackground(KeyholeColors.surface)
                    }

                    if !entry.customFields.isEmpty {
                        Section {
                            ForEach(entry.customFields) { field in
                                VStack(alignment: .leading, spacing: 4) {
                                    Text(field.label)
                                        .font(KeyholeFonts.meta)
                                        .foregroundStyle(KeyholeColors.textDim)
                                    if field.secret {
                                        Text(String(repeating: "•", count: max(6, field.value.count)))
                                            .font(KeyholeFonts.secret)
                                        Button("Copy") {
                                            clipboard.copy(field.value, label: field.label)
                                            session.registerActivity()
                                        }
                                    } else {
                                        Text(field.value)
                                    }
                                }
                            }
                        } header: {
                            KeyholeFieldLabel(text: "Custom fields")
                        }
                        .listRowBackground(KeyholeColors.surface)
                    }

                    if !entry.attachments.isEmpty {
                        Section {
                            ForEach(entry.attachments) { att in
                                HStack {
                                    VStack(alignment: .leading) {
                                        Text(att.name)
                                        Text(byteLabel(att.sizeBytes))
                                            .font(KeyholeFonts.meta)
                                            .foregroundStyle(KeyholeColors.textDim)
                                    }
                                    Spacer()
                                    Button("Share") {
                                        if let data = Data(base64Encoded: att.dataB64) {
                                            shareItem = SharePayload(data: data, name: att.name)
                                        }
                                    }
                                }
                            }
                        } header: {
                            KeyholeFieldLabel(text: "Attachments")
                        }
                        .listRowBackground(KeyholeColors.surface)
                    }

                    if !entry.notes.isEmpty {
                        Section {
                            Text(entry.notes)
                        } header: {
                            KeyholeFieldLabel(text: "Notes")
                        }
                        .listRowBackground(KeyholeColors.surface)
                    }

                    if !entry.tags.isEmpty {
                        Section {
                            Text(entry.tags.joined(separator: ", "))
                        } header: {
                            KeyholeFieldLabel(text: "Tags")
                        }
                        .listRowBackground(KeyholeColors.surface)
                    }

                    if !entry.history.isEmpty {
                        Section {
                            ForEach(Array(entry.history.enumerated()), id: \.offset) { _, hist in
                                VStack(alignment: .leading, spacing: 4) {
                                    Text(hist.changedAt)
                                        .font(KeyholeFonts.meta)
                                        .foregroundStyle(KeyholeColors.textDim)
                                    Text(revealedHistory.contains(hist.changedAt + hist.password)
                                          ? hist.password
                                          : String(repeating: "•", count: max(8, hist.password.count)))
                                        .font(KeyholeFonts.secret)
                                    HStack {
                                        Button(revealedHistory.contains(hist.changedAt + hist.password) ? "Hide" : "Show") {
                                            let key = hist.changedAt + hist.password
                                            if revealedHistory.contains(key) {
                                                revealedHistory.remove(key)
                                            } else {
                                                revealedHistory.insert(key)
                                            }
                                        }
                                        Button("Copy") {
                                            clipboard.copy(hist.password, label: "Previous password")
                                            session.registerActivity()
                                        }
                                    }
                                    .font(KeyholeFonts.meta)
                                }
                            }
                        } header: {
                            KeyholeFieldLabel(text: "Password history")
                        }
                        .listRowBackground(KeyholeColors.surface)
                    }

                    if let remaining = clipboard.secondsRemaining, clipboard.lastCopied != nil {
                        Section {
                            Text("Clipboard clears in \(remaining)s (\(clipboard.lastCopied ?? ""))")
                                .font(KeyholeFonts.meta)
                                .foregroundStyle(KeyholeColors.textDim)
                        }
                        .listRowBackground(KeyholeColors.surface2)
                    }
                }
                .scrollContentBackground(.hidden)
                .background(KeyholeColors.bg)
                .navigationTitle(entry.title)
                .navigationBarTitleDisplayMode(.inline)
                .toolbar {
                    Button("Edit") { showEditor = true }
                }
                .sheet(isPresented: $showEditor) {
                    EntryEditorView(entry: entry, kind: entry.kind) {
                        showEditor = false
                        session.registerActivity()
                    }
                }
                .sheet(item: $shareItem) { item in
                    ActivityView(items: [item.data])
                }
                .onAppear { startTotp(entry) }
                .onDisappear { timer?.invalidate() }
                .onChange(of: entry.totpSecret) { _, _ in startTotp(entry) }
                .onChange(of: entry.totpConfig?.digits) { _, _ in startTotp(entry) }
            } else {
                ContentUnavailableView {
                    Label {
                        Text("Entry removed")
                    } icon: {
                        KeyholeIcon(name: .trash, size: 40)
                            .foregroundStyle(KeyholeColors.textDim)
                    }
                }
            }
        }
    }

    private func byteLabel(_ n: Int) -> String {
        if n < 1024 { return "\(n) B" }
        return String(format: "%.1f KB", Double(n) / 1024)
    }

    private func startTotp(_ entry: Entry) {
        timer?.invalidate()
        totpError = nil
        totpCode = nil
        guard let secret = entry.totpSecret, !secret.isEmpty else { return }
        let options = totpOptions(from: entry.totpConfig)
        func tick() {
            do {
                totpCode = try generateTotp(base32Secret: secret, options: options)
                totpError = nil
            } catch {
                totpCode = nil
                totpError = error.localizedDescription
            }
        }
        tick()
        timer = Timer.scheduledTimer(withTimeInterval: 1, repeats: true) { _ in
            Task { @MainActor in tick() }
        }
    }
}

struct SharePayload: Identifiable {
    let id = UUID()
    let data: Data
    let name: String
}

struct ActivityView: UIViewControllerRepresentable {
    let items: [Any]

    func makeUIViewController(context: Context) -> UIActivityViewController {
        UIActivityViewController(activityItems: items, applicationActivities: nil)
    }

    func updateUIViewController(_ uiViewController: UIActivityViewController, context: Context) {}
}
