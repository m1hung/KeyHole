import SwiftUI
import UIKit

/// Applies Keyhole cool-slate chrome to UIKit-hosted controls (nav, tab, search, switches).
enum KeyholeAppearance {
    static func apply() {
        let accent = UIColor(KeyholeColors.accent)
        let bg = UIColor(KeyholeColors.bg)
        let surface = UIColor(KeyholeColors.surface)
        let text = UIColor(KeyholeColors.text)
        let textDim = UIColor(KeyholeColors.textDim)
        let border = UIColor(KeyholeColors.border)

        let nav = UINavigationBarAppearance()
        nav.configureWithOpaqueBackground()
        nav.backgroundColor = surface
        nav.shadowColor = border
        nav.titleTextAttributes = [.foregroundColor: text]
        nav.largeTitleTextAttributes = [.foregroundColor: text]
        UINavigationBar.appearance().standardAppearance = nav
        UINavigationBar.appearance().scrollEdgeAppearance = nav
        UINavigationBar.appearance().compactAppearance = nav
        UINavigationBar.appearance().tintColor = accent

        let tab = UITabBarAppearance()
        tab.configureWithOpaqueBackground()
        tab.backgroundColor = surface
        tab.shadowColor = border
        let tabItem = UITabBarItemAppearance()
        tabItem.normal.iconColor = textDim
        tabItem.normal.titleTextAttributes = [.foregroundColor: textDim]
        tabItem.selected.iconColor = accent
        tabItem.selected.titleTextAttributes = [.foregroundColor: accent]
        tab.stackedLayoutAppearance = tabItem
        tab.inlineLayoutAppearance = tabItem
        tab.compactInlineLayoutAppearance = tabItem
        UITabBar.appearance().standardAppearance = tab
        UITabBar.appearance().scrollEdgeAppearance = tab
        UITabBar.appearance().tintColor = accent

        UISearchBar.appearance().tintColor = accent
        UITextField.appearance(whenContainedInInstancesOf: [UISearchBar.self]).backgroundColor = bg

        UISwitch.appearance().onTintColor = accent
        UISegmentedControl.appearance().selectedSegmentTintColor = accent
        UITableView.appearance().backgroundColor = bg
        UITableView.appearance().separatorColor = border
        UICollectionView.appearance().backgroundColor = bg
    }
}

extension View {
    /// Shared Form chrome: cool slate canvas, no system grouped grey.
    /// Inline titles avoid large-title rubber-banding that hides the title
    /// and leaves empty space above the form.
    func keyholeFormChrome(titleDisplayMode: NavigationBarItem.TitleDisplayMode = .inline) -> some View {
        self
            .scrollContentBackground(.hidden)
            .background(KeyholeColors.bg)
            .tint(KeyholeColors.accent)
            .navigationBarTitleDisplayMode(titleDisplayMode)
            .toolbarBackground(KeyholeColors.surface, for: .navigationBar)
            .toolbarBackground(.visible, for: .navigationBar)
    }

    func keyholeListRowSurface() -> some View {
        listRowBackground(KeyholeColors.surface)
    }
}
