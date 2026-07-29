import SwiftUI
import KeyholeCore

struct GeneratorView: View {
    @Environment(AppVaultSession.self) private var session
    @State private var options = DEFAULT_GENERATOR_OPTIONS
    @State private var password = ""
    @State private var strength: StrengthResult?
    @State private var passphrase = ""
    @State private var wordCount = 5
    @State private var error: String?

    var body: some View {
        NavigationStack {
            Form {
                Section("Password") {
                    Toggle("Lowercase", isOn: $options.lowercase)
                    Toggle("Uppercase", isOn: $options.uppercase)
                    Toggle("Digits", isOn: $options.digits)
                    Toggle("Symbols", isOn: $options.symbols)
                    Toggle("Exclude ambiguous", isOn: $options.excludeAmbiguous)
                    Stepper("Length: \(options.length)", value: $options.length, in: MIN_LENGTH...MAX_LENGTH)
                    Button("Generate password") { generatePw() }
                    if !password.isEmpty {
                        Text(password)
                            .font(.body.monospaced())
                            .textSelection(.enabled)
                        if let strength {
                            Text("\(strength.label) · \(String(format: "%.0f", strength.bits)) bits · \(strength.crackTimeDisplay)")
                                .font(.caption)
                                .foregroundStyle(.secondary)
                        }
                    }
                }
                Section("Passphrase") {
                    Stepper("Words: \(wordCount)", value: $wordCount, in: 3...12)
                    Button("Generate passphrase") { generatePhrase() }
                    if !passphrase.isEmpty {
                        Text(passphrase)
                            .font(.body.monospaced())
                            .textSelection(.enabled)
                    }
                }
                if let error {
                    Section { Text(error).foregroundStyle(.red) }
                }
            }
            .navigationTitle("Generator")
            .onAppear {
                if let g = session.data?.settings.generator {
                    options = g
                }
            }
            .onChange(of: options) { _, newValue in
                Task {
                    await session.mutate { data in
                        updateSettings(data: data) { $0.generator = newValue }
                    }
                }
            }
        }
    }

    private func generatePw() {
        do {
            password = try generatePassword(options)
            strength = strengthFromBits(generatorEntropyBits(options))
            error = nil
            session.registerActivity()
        } catch {
            self.error = error.localizedDescription
        }
    }

    private func generatePhrase() {
        do {
            passphrase = try generatePassphrase(wordlist: PassphraseWordlist.words, words: wordCount)
            error = nil
            session.registerActivity()
        } catch {
            self.error = error.localizedDescription
        }
    }
}
