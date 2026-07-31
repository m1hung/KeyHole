import SwiftUI
import KeyholeCore

struct RootView: View {
    @Environment(AppVaultSession.self) private var session

    var body: some View {
        Group {
            switch session.status {
            case .loading:
                ZStack {
                    KeyholeColors.bg.ignoresSafeArea()
                    ProgressView("Loading…")
                        .tint(KeyholeColors.accent)
                        .foregroundStyle(KeyholeColors.textDim)
                }
            case .noVault, .locked, .damaged:
                UnlockView()
            case .unlocked:
                MainTabView()
            }
        }
        .animation(.easeInOut(duration: 0.2), value: session.status)
    }
}
