import Foundation

/// Human-readable formatting for vault ISO-8601 timestamps.
enum KeyholeDateFormat {
    private static let relative: RelativeDateTimeFormatter = {
        let f = RelativeDateTimeFormatter()
        f.unitsStyle = .full
        f.dateTimeStyle = .named
        return f
    }()

    private static let absolute: DateFormatter = {
        let f = DateFormatter()
        f.dateStyle = .medium
        f.timeStyle = .short
        return f
    }()

    private static let dayOnly: DateFormatter = {
        let f = DateFormatter()
        f.dateStyle = .medium
        f.timeStyle = .none
        return f
    }()

    static func parseISO(_ iso: String) -> Date? {
        let withFraction = ISO8601DateFormatter()
        withFraction.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        if let date = withFraction.date(from: iso) { return date }
        let plain = ISO8601DateFormatter()
        plain.formatOptions = [.withInternetDateTime]
        return plain.date(from: iso)
    }

    /// “2 hours ago”, “yesterday”, or a medium date for older timestamps.
    static func relativeOrAbsolute(_ iso: String, relativeTo now: Date = Date()) -> String {
        guard let date = parseISO(iso) else { return iso }
        let age = now.timeIntervalSince(date)
        if abs(age) < 7 * 24 * 60 * 60 {
            return relative.localizedString(for: date, relativeTo: now)
        }
        return absolute.string(from: date)
    }

    static func updatedLabel(_ iso: String) -> String {
        "Updated \(relativeOrAbsolute(iso))"
    }

    static func passwordChangedLabel(_ iso: String) -> String {
        guard let date = parseISO(iso) else { return "Password changed \(iso)" }
        return "Password changed \(dayOnly.string(from: date))"
    }
}
