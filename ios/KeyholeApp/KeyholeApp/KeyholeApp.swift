import SwiftUI
import KeyholeCore

@main
struct KeyholeApp: App {
    @State private var session = AppVaultSession()
    @Environment(\.scenePhase) private var scenePhase

    var body: some Scene {
        WindowGroup {
            RootView()
                .environment(session)
                .preferredColorScheme(colorScheme(for: session.data?.settings.theme))
                .onAppear {
                    KeyholeAppearance.apply()
                    session.bootstrap()
                }
                .onChange(of: scenePhase) { _, phase in
                    switch phase {
                    case .background:
                        session.handleScenePhase(.background)
                    case .inactive:
                        session.handleScenePhase(.inactive)
                    case .active:
                        session.handleScenePhase(.active)
                        session.registerActivity()
                    @unknown default:
                        break
                    }
                }
        }
    }

    private func colorScheme(for theme: ThemePreference?) -> ColorScheme? {
        switch theme {
        case .light: return .light
        case .dark: return .dark
        default: return nil
        }
    }
}
