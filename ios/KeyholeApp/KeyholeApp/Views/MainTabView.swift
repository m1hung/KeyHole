import SwiftUI
import KeyholeCore

struct MainTabView: View {
    @Environment(AppVaultSession.self) private var session
    @State private var clipboard = ClipboardController()
    @State private var selectedTab = 0

    var body: some View {
        TabView(selection: $selectedTab) {
            EntryListView(clipboard: clipboard)
                .tabItem { Label("Vault", systemImage: "lock.rectangle.stack") }
                .tag(0)
            GeneratorView()
                .tabItem { Label("Generator", systemImage: "key") }
                .tag(1)
            SettingsView(clipboard: clipboard)
                .tabItem { Label("Settings", systemImage: "gearshape") }
                .tag(2)
        }
        .onAppear {
            if let secs = session.data?.settings.clipboardClearSeconds {
                clipboard.updateClearAfter(Int(secs))
            }
        }
        .onChange(of: session.data?.settings.clipboardClearSeconds) { _, secs in
            if let secs {
                clipboard.updateClearAfter(Int(secs))
            }
        }
        .simultaneousGesture(
            DragGesture(minimumDistance: 0).onChanged { _ in session.registerActivity() }
        )
        .onTapGesture { session.registerActivity() }
    }
}
