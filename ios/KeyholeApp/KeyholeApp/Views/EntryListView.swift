import SwiftUI
import KeyholeCore

struct EntryListView: View {
    @Environment(AppVaultSession.self) private var session
    var clipboard: ClipboardController
    @State private var query = ""
    @State private var showEditor = false
    @State private var editingEntry: Entry?
    @State private var newKind: EntryKind = .login

    private var entries: [Entry] {
        guard let data = session.data else { return [] }
        return searchEntries(data: data, query: query)
    }

    var body: some View {
        NavigationStack {
            List {
                ForEach(entries) { entry in
                    NavigationLink {
                        EntryDetailView(entryId: entry.id, clipboard: clipboard)
                    } label: {
                        VStack(alignment: .leading, spacing: 4) {
                            Text(entry.title)
                                .font(.headline)
                            if entry.kind == .login, !entry.username.isEmpty {
                                Text(entry.username)
                                    .font(.subheadline)
                                    .foregroundStyle(.secondary)
                            } else if entry.kind == .note {
                                Text("Note")
                                    .font(.caption)
                                    .foregroundStyle(.secondary)
                            }
                        }
                    }
                    .swipeActions(edge: .trailing, allowsFullSwipe: true) {
                        Button(role: .destructive) {
                            Task {
                                await session.mutate { try deleteEntry(data: $0, id: entry.id) }
                            }
                        } label: {
                            Label("Delete", systemImage: "trash")
                        }
                    }
                }
            }
            .searchable(text: $query, prompt: "Search titles, usernames, URLs, tags")
            .navigationTitle("Vault")
            .toolbar {
                ToolbarItem(placement: .topBarLeading) {
                    if let secs = session.secondsUntilLock {
                        Text("Lock in \(secs)s")
                            .font(.caption2)
                            .foregroundStyle(.secondary)
                    }
                }
                ToolbarItem(placement: .topBarTrailing) {
                    Menu {
                        Button("Login") {
                            newKind = .login
                            editingEntry = nil
                            showEditor = true
                        }
                        Button("Secure note") {
                            newKind = .note
                            editingEntry = nil
                            showEditor = true
                        }
                    } label: {
                        Image(systemName: "plus")
                    }
                }
                ToolbarItem(placement: .topBarTrailing) {
                    Button("Lock") { session.lock() }
                }
            }
            .sheet(isPresented: $showEditor) {
                EntryEditorView(entry: editingEntry, kind: newKind) { showEditor = false }
            }
            .overlay {
                if entries.isEmpty {
                    ContentUnavailableView(
                        query.isEmpty ? "No entries yet" : "No matches",
                        systemImage: "magnifyingglass",
                        description: Text(query.isEmpty ? "Tap + to add a login or note." : "Try a different search.")
                    )
                }
            }
        }
    }
}

struct EntryDetailView: View {
    let entryId: String
    var clipboard: ClipboardController
    @Environment(AppVaultSession.self) private var session
    @State private var revealPassword = false
    @State private var totpCode: TotpCode?
    @State private var showEditor = false
    @State private var timer: Timer?

    private var entry: Entry? {
        session.data.flatMap { getEntry(data: $0, id: entryId) }
    }

    var body: some View {
        Group {
            if let entry {
                Form {
                    Section("Details") {
                        LabeledContent("Title", value: entry.title)
                        if entry.kind == .login {
                            LabeledContent("Username", value: entry.username)
                            HStack {
                                Text("Password")
                                Spacer()
                                Text(revealPassword ? entry.password : String(repeating: "•", count: max(8, entry.password.count)))
                                    .font(.body.monospaced())
                                Button(revealPassword ? "Hide" : "Show") { revealPassword.toggle() }
                                    .font(.caption)
                            }
                            Button("Copy password") {
                                clipboard.copy(entry.password, label: "Password")
                                session.registerActivity()
                            }
                            if !entry.username.isEmpty {
                                Button("Copy username") {
                                    clipboard.copy(entry.username, label: "Username")
                                }
                            }
                        }
                    }

                    if entry.kind == .login, let secret = entry.totpSecret, !secret.isEmpty {
                        Section("Authenticator") {
                            if let totpCode {
                                HStack {
                                    Text(totpCode.code)
                                        .font(.title.monospaced())
                                    Spacer()
                                    Text("\(totpCode.secondsRemaining)s")
                                        .foregroundStyle(.secondary)
                                }
                                Button("Copy code") {
                                    clipboard.copy(totpCode.code, label: "TOTP")
                                }
                            }
                        }
                    }

                    if !entry.urls.isEmpty {
                        Section("URLs") {
                            ForEach(entry.urls, id: \.self) { url in
                                Text(url)
                                    .font(.footnote)
                                    .foregroundStyle(.blue)
                            }
                        }
                    }

                    if !entry.notes.isEmpty {
                        Section("Notes") {
                            Text(entry.notes)
                        }
                    }

                    if !entry.tags.isEmpty {
                        Section("Tags") {
                            Text(entry.tags.joined(separator: ", "))
                        }
                    }

                    if let remaining = clipboard.secondsRemaining, clipboard.lastCopied != nil {
                        Section {
                            Text("Clipboard clears in \(remaining)s (\(clipboard.lastCopied ?? ""))")
                                .font(.caption)
                                .foregroundStyle(.secondary)
                        }
                    }
                }
                .navigationTitle(entry.title)
                .toolbar {
                    Button("Edit") { showEditor = true }
                }
                .sheet(isPresented: $showEditor) {
                    EntryEditorView(entry: entry, kind: entry.kind) { showEditor = false }
                }
                .onAppear { startTotp(entry) }
                .onDisappear { timer?.invalidate() }
            } else {
                ContentUnavailableView("Entry removed", systemImage: "trash")
            }
        }
    }

    private func startTotp(_ entry: Entry) {
        timer?.invalidate()
        guard let secret = entry.totpSecret, !secret.isEmpty else { return }
        func tick() {
            totpCode = try? generateTotp(base32Secret: secret)
        }
        tick()
        timer = Timer.scheduledTimer(withTimeInterval: 1, repeats: true) { _ in
            Task { @MainActor in tick() }
        }
    }
}
