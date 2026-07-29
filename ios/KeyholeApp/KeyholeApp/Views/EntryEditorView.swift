import SwiftUI
import KeyholeCore

struct EntryEditorView: View {
    @Environment(AppVaultSession.self) private var session
    @Environment(\.dismiss) private var dismiss

    let entry: Entry?
    let kind: EntryKind
    var onDone: () -> Void

    @State private var title = ""
    @State private var username = ""
    @State private var password = ""
    @State private var urlsText = ""
    @State private var notes = ""
    @State private var tagsText = ""
    @State private var totpSecret = ""
    @State private var error: String?

    var body: some View {
        NavigationStack {
            Form {
                Section {
                    TextField("Title", text: $title)
                    if kind == .login {
                        TextField("Username", text: $username)
                            .textContentType(.username)
                            .autocapitalization(.none)
                        SecureField("Password", text: $password)
                            .textContentType(.password)
                        TextField("URLs (one per line)", text: $urlsText, axis: .vertical)
                            .lineLimit(2...6)
                        TextField("TOTP secret (base32)", text: $totpSecret)
                            .autocapitalization(.none)
                    }
                    TextField(kind == .note ? "Note body" : "Notes", text: $notes, axis: .vertical)
                        .lineLimit(3...10)
                    TextField("Tags (comma-separated)", text: $tagsText)
                }
                if let error {
                    Section {
                        Text(error).foregroundStyle(.red)
                    }
                }
            }
            .navigationTitle(entry == nil ? "New \(kind == .note ? "note" : "login")" : "Edit")
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Cancel") {
                        onDone()
                        dismiss()
                    }
                }
                ToolbarItem(placement: .confirmationAction) {
                    Button("Save") { Task { await save() } }
                }
            }
            .onAppear { load() }
        }
    }

    private func load() {
        guard let entry else {
            title = ""
            return
        }
        title = entry.title
        username = entry.username
        password = entry.password
        urlsText = entry.urls.joined(separator: "\n")
        notes = entry.notes
        tagsText = entry.tags.joined(separator: ", ")
        totpSecret = entry.totpSecret ?? ""
    }

    private func save() async {
        let urls = urlsText
            .split(whereSeparator: \.isNewline)
            .map { $0.trimmingCharacters(in: .whitespacesAndNewlines) }
            .filter { !$0.isEmpty }
        let tags = tagsText
            .split(separator: ",")
            .map { $0.trimmingCharacters(in: .whitespacesAndNewlines) }
            .filter { !$0.isEmpty }
        let totp: String? = totpSecret.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
            ? nil
            : totpSecret.trimmingCharacters(in: .whitespacesAndNewlines)

        if let entry {
            await session.mutate { data in
                try updateEntry(
                    data: data,
                    id: entry.id,
                        patch: UpdateEntryPatch(
                            title: title,
                            username: username,
                            password: password,
                            urls: urls,
                            notes: notes,
                            tags: tags,
                            totpSecret: .some(totp)
                        )
                )
            }
        } else {
            await session.mutate { data in
                try createEntry(
                    data: data,
                    input: EntryInput(
                        title: title,
                        kind: kind,
                        username: username,
                        password: password,
                        urls: urls,
                        notes: notes,
                        tags: tags,
                        totpSecret: totp
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
