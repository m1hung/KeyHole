import SwiftUI
import KeyholeCore

struct GeneratorView: View {
    @Environment(AppVaultSession.self) private var session
    var clipboard: ClipboardController

    @State private var mode: Mode = .password
    @State private var options = DEFAULT_GENERATOR_OPTIONS
    @State private var password = ""
    @State private var strength: StrengthResult?
    @State private var passphrase = ""
    @State private var wordCount = 5
    @State private var error: String?
    @State private var persistTask: Task<Void, Never>?
    @State private var loaded = false

    private enum Mode {
        case password
        case passphrase
    }

    var body: some View {
        NavigationStack {
            Form {
                Section {
                    Picker("Mode", selection: $mode) {
                        Text("Password").tag(Mode.password)
                        Text("Passphrase").tag(Mode.passphrase)
                    }
                    .pickerStyle(.segmented)
                }
                .listRowBackground(KeyholeColors.surface)

                if mode == .password {
                    Section {
                        Toggle("Lowercase", isOn: $options.lowercase)
                        Toggle("Uppercase", isOn: $options.uppercase)
                        Toggle("Digits", isOn: $options.digits)
                        Toggle("Symbols", isOn: $options.symbols)
                        Toggle("Exclude ambiguous", isOn: $options.excludeAmbiguous)
                        Stepper("Length: \(options.length)", value: $options.length, in: MIN_LENGTH...MAX_LENGTH)
                        Button {
                            generatePw()
                        } label: {
                            Label {
                                Text("Generate")
                            } icon: {
                                KeyholeIcon(name: .refresh, size: 16)
                            }
                        }
                        .foregroundStyle(KeyholeColors.accent)
                        if !password.isEmpty {
                            Text(password)
                                .font(KeyholeFonts.secret)
                                .textSelection(.enabled)
                                .padding(.vertical, 4)
                            KeyholeStrengthMeter(strength: strength)
                            Button {
                                clipboard.copy(password, label: "Password")
                                session.registerActivity()
                            } label: {
                                Label {
                                    Text("Copy password")
                                } icon: {
                                    KeyholeIcon(name: .copy, size: 16)
                                }
                            }
                        }
                    } header: {
                        KeyholeFieldLabel(text: "Password")
                    }
                    .listRowBackground(KeyholeColors.surface)
                } else {
                    Section {
                        Stepper("Words: \(wordCount)", value: $wordCount, in: 3...12)
                        Button {
                            generatePhrase()
                        } label: {
                            Label {
                                Text("Generate")
                            } icon: {
                                KeyholeIcon(name: .refresh, size: 16)
                            }
                        }
                        .foregroundStyle(KeyholeColors.accent)
                        if !passphrase.isEmpty {
                            Text(passphrase)
                                .font(KeyholeFonts.secret)
                                .textSelection(.enabled)
                            Button {
                                clipboard.copy(passphrase, label: "Passphrase")
                                session.registerActivity()
                            } label: {
                                Label {
                                    Text("Copy passphrase")
                                } icon: {
                                    KeyholeIcon(name: .copy, size: 16)
                                }
                            }
                        }
                    } header: {
                        KeyholeFieldLabel(text: "Passphrase")
                    }
                    .listRowBackground(KeyholeColors.surface)
                }

                if let error {
                    Section {
                        KeyholeErrorBanner(message: error)
                    }
                }
            }
            .keyholeFormChrome()
            .navigationTitle("Generator")
            .onAppear {
                if let g = session.data?.settings.generator {
                    options = g
                }
                loaded = true
                if password.isEmpty { generatePw() }
            }
            .onChange(of: options) { _, newValue in
                guard loaded else { return }
                persistTask?.cancel()
                persistTask = Task {
                    try? await Task.sleep(nanoseconds: 1_000_000_000)
                    guard !Task.isCancelled else { return }
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
