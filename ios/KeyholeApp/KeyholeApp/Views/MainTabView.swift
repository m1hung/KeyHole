import SwiftUI
import KeyholeCore

struct MainTabView: View {
    @Environment(AppVaultSession.self) private var session
    @State private var clipboard = ClipboardController()
    @State private var selectedTab = 0

    var body: some View {
        ZStack(alignment: .top) {
            TabView(selection: $selectedTab) {
                EntryListView(clipboard: clipboard)
                    .tabItem {
                        KeyholeIconImage.image(name: .vault, size: 24)
                        Text("Vault")
                    }
                    .tag(0)
                GeneratorView(clipboard: clipboard)
                    .tabItem {
                        KeyholeIconImage.image(name: .generator, size: 24)
                        Text("Generator")
                    }
                    .tag(1)
                SettingsView(clipboard: clipboard)
                    .tabItem {
                        KeyholeIconImage.image(name: .settings, size: 24)
                        Text("Settings")
                    }
                    .tag(2)
            }
            .tint(KeyholeColors.accent)
            .toolbarBackground(KeyholeColors.surface, for: .tabBar)
            .toolbarBackground(.visible, for: .tabBar)

            if let toast = clipboard.toastMessage {
                KeyholeToastBanner(message: toast)
                    .padding(.top, 8)
                    .zIndex(1)
            }
        }
        .background(KeyholeColors.bg.ignoresSafeArea())
        .onAppear {
            if let secs = session.data?.settings.clipboardClearSeconds {
                clipboard.updateClearAfter(Int(secs))
            }
            session.registerActivity()
        }
        .onChange(of: session.data?.settings.clipboardClearSeconds) { _, secs in
            if let secs {
                clipboard.updateClearAfter(Int(secs))
            }
        }
        .onChange(of: selectedTab) { _, _ in
            session.registerActivity()
        }
    }
}
