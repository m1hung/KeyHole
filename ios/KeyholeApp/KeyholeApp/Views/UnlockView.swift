import SwiftUI
import KeyholeCore

struct UnlockView: View {
    @Environment(AppVaultSession.self) private var session
    @State private var password = ""
    @State private var confirm = ""
    @State private var isCreateMode = false
    @FocusState private var focused: Bool

    var body: some View {
        NavigationStack {
            VStack(spacing: 24) {
                Spacer(minLength: 40)
                Text("Keyhole")
                    .font(.system(.largeTitle, design: .serif).weight(.bold))
                Text(session.status == .noVault || isCreateMode
                     ? "Create a local vault. Your master password is never stored."
                     : "Enter your master password to unlock.")
                    .font(.subheadline)
                    .foregroundStyle(.secondary)
                    .multilineTextAlignment(.center)
                    .padding(.horizontal)

                SecureField("Master password", text: $password)
                    .textContentType(.password)
                    .textFieldStyle(.roundedBorder)
                    .focused($focused)
                    .padding(.horizontal, 32)

                if session.status == .noVault || isCreateMode {
                    SecureField("Confirm master password", text: $confirm)
                        .textContentType(.newPassword)
                        .textFieldStyle(.roundedBorder)
                        .padding(.horizontal, 32)
                }

                if let err = session.errorMessage {
                    Text(err)
                        .font(.footnote)
                        .foregroundStyle(.red)
                        .padding(.horizontal)
                }

                Button {
                    Task { await submit() }
                } label: {
                    if session.busy {
                        ProgressView()
                            .frame(maxWidth: .infinity)
                    } else {
                        Text(session.status == .noVault || isCreateMode ? "Create vault" : "Unlock")
                            .frame(maxWidth: .infinity)
                    }
                }
                .buttonStyle(.borderedProminent)
                .disabled(session.busy || password.count < MIN_MASTER_PASSWORD_LENGTH)
                .padding(.horizontal, 32)

                if session.status == .locked {
                    Button(isCreateMode ? "Unlock existing vault" : "Create a new vault instead") {
                        isCreateMode.toggle()
                        session.clearError()
                    }
                    .font(.footnote)
                }

                Spacer()
            }
            .onAppear { focused = true }
            .navigationBarTitleDisplayMode(.inline)
        }
    }

    private func submit() async {
        if session.status == .noVault || isCreateMode {
            guard password == confirm else {
                session.errorMessage = "Passwords do not match."
                return
            }
            await session.createVault(masterPassword: password)
            password = ""
            confirm = ""
        } else {
            await session.unlock(masterPassword: password)
            password = ""
        }
    }
}
