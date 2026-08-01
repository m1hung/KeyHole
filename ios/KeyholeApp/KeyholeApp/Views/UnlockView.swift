import SwiftUI
import KeyholeCore

struct UnlockView: View {
    @Environment(AppVaultSession.self) private var session
    @State private var password = ""
    @State private var confirm = ""
    @State private var isCreateMode = false
    @State private var overwriteAck = ""
    @State private var shake = 0
    @State private var didAutoPromptBiometrics = false
    @FocusState private var focused: Bool

    private var creating: Bool {
        session.status == .noVault || session.status == .damaged || isCreateMode
    }

    private var needsOverwriteConfirm: Bool {
        (isCreateMode && session.status == .locked) || session.status == .damaged
    }

    private var showBiometrics: Bool {
        session.status == .locked && !isCreateMode && BiometricUnlockStore.isReady && BiometricUnlockStore.canUseBiometrics
    }

    var body: some View {
        ZStack {
            KeyholeColors.bg.ignoresSafeArea()
            VStack {
                Spacer(minLength: 24)
                KeyholeCard {
                    HStack(spacing: 10) {
                        KeyholeBrandMark(size: 26)
                        Text("Keyhole")
                            .font(KeyholeFonts.brand)
                            .foregroundStyle(KeyholeColors.text)
                        Spacer(minLength: 0)
                    }

                    Text(subtitle)
                        .font(KeyholeFonts.meta)
                        .foregroundStyle(KeyholeColors.textDim)
                        .fixedSize(horizontal: false, vertical: true)

                    KeyholeLocalBadge()

                    if showBiometrics {
                        Button {
                            Task { await session.unlockWithBiometrics() }
                        } label: {
                            HStack(spacing: 8) {
                                Image(systemName: BiometricUnlockStore.biometryTypeName == "Touch ID"
                                      ? "touchid" : "faceid")
                                Text("Unlock with \(BiometricUnlockStore.biometryTypeName)")
                            }
                            .frame(maxWidth: .infinity)
                        }
                        .buttonStyle(KeyholePrimaryButtonStyle(disabled: session.busy))
                        .disabled(session.busy)

                        Text("or enter password")
                            .font(KeyholeFonts.caption)
                            .foregroundStyle(KeyholeColors.textDim)
                            .frame(maxWidth: .infinity)
                    }

                    VStack(alignment: .leading, spacing: 8) {
                        KeyholeFieldLabel(text: "Master password")
                        SecureField("Master password", text: $password)
                            .textContentType(creating ? .newPassword : .password)
                            .textInputAutocapitalization(.never)
                            .foregroundStyle(KeyholeColors.text)
                            .keyholeFieldBackground()
                            .focused($focused)
                    }

                    if creating {
                        VStack(alignment: .leading, spacing: 8) {
                            KeyholeFieldLabel(text: "Confirm")
                            SecureField("Confirm master password", text: $confirm)
                                .textContentType(.newPassword)
                                .textInputAutocapitalization(.never)
                                .foregroundStyle(KeyholeColors.text)
                                .keyholeFieldBackground()
                        }
                    }

                    if needsOverwriteConfirm {
                        VStack(alignment: .leading, spacing: 8) {
                            Text(
                                session.status == .damaged
                                ? "Type OVERWRITE to replace this vault, or import a backup later."
                                : "This replaces your existing vault. Type OVERWRITE to confirm."
                            )
                            .font(KeyholeFonts.meta)
                            .foregroundStyle(KeyholeColors.warn)
                            TextField("OVERWRITE", text: $overwriteAck)
                                .textInputAutocapitalization(.characters)
                                .autocorrectionDisabled()
                                .foregroundStyle(KeyholeColors.text)
                                .keyholeFieldBackground(emphasized: true)
                        }
                    }

                    if let err = session.errorMessage {
                        KeyholeErrorBanner(message: err)
                    }

                    Button {
                        Task { await submit() }
                    } label: {
                        if session.busy {
                            ProgressView()
                                .tint(KeyholeColors.accentText)
                        } else {
                            Text(creating ? "Create vault" : "Unlock")
                        }
                    }
                    .buttonStyle(KeyholePrimaryButtonStyle(disabled: !canSubmit))
                    .disabled(!canSubmit || session.busy)

                    if session.status == .locked {
                        Button(isCreateMode ? "Unlock existing vault" : "Create a new vault") {
                            isCreateMode.toggle()
                            overwriteAck = ""
                            confirm = ""
                            session.clearError()
                        }
                        .buttonStyle(KeyholeGhostButtonStyle())
                        .frame(maxWidth: .infinity)
                    }
                }
                .offset(x: shake == 0 ? 0 : (shake % 2 == 0 ? 8 : -8))
                .padding(.horizontal, 24)
                Spacer()
            }
        }
        .onAppear {
            focused = !showBiometrics
            maybeAutoPromptBiometrics()
        }
        .onChange(of: session.errorMessage) { _, msg in
            if msg != nil, !creating {
                withAnimation(.default) { shake += 1 }
            }
        }
    }

    private var subtitle: String {
        if session.status == .damaged {
            return "This vault file can’t be read. Import a backup, or create a new vault."
        }
        if creating {
            return isCreateMode && session.status == .locked
                ? "Creating a new vault replaces the one on this iPhone."
                : "Choose a master password to create your vault."
        }
        if showBiometrics {
            return "Your vault is locked."
        }
        return "Your vault is locked."
    }

    private var canSubmit: Bool {
        if password.count < MIN_MASTER_PASSWORD_LENGTH { return false }
        if creating {
            if password != confirm { return false }
            if needsOverwriteConfirm, overwriteAck != "OVERWRITE" {
                return false
            }
        }
        return true
    }

    private func maybeAutoPromptBiometrics() {
        guard showBiometrics, !didAutoPromptBiometrics, !session.busy else { return }
        didAutoPromptBiometrics = true
        Task { await session.unlockWithBiometrics() }
    }

    private func submit() async {
        if creating {
            guard password == confirm else {
                session.errorMessage = "Passwords do not match."
                return
            }
            if needsOverwriteConfirm, overwriteAck != "OVERWRITE" {
                session.errorMessage = "Type OVERWRITE to replace the existing vault."
                return
            }
            if session.status == .damaged {
                await session.deleteVault()
            }
            await session.createVault(masterPassword: password)
            password = ""
            confirm = ""
            overwriteAck = ""
            isCreateMode = false
        } else {
            await session.unlock(masterPassword: password)
            password = ""
        }
    }
}
