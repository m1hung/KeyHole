import Foundation

/// App Group shared by the main app and AutoFill extension.
public enum AppGroup {
    public static let id = "group.app.keyhole.vault"

    /// Shared container root, or nil when the App Group entitlement is missing /
    /// not provisioned for this signing team.
    public static var containerURL: URL? {
        FileManager.default.containerURL(forSecurityApplicationGroupIdentifier: id)
    }

    public static var isAvailable: Bool { containerURL != nil }

    /// UserDefaults shared across the app and AutoFill when the group is live.
    public static var defaults: UserDefaults {
        if isAvailable, let suite = UserDefaults(suiteName: id) {
            return suite
        }
        return .standard
    }
}
