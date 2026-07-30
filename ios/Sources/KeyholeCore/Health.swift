import Foundation

/// Offline vault health checks — run only while the vault is unlocked.
/// Never phones home; never persists analysis results.
///
/// A port of `core/src/health.ts`, kept deliberately line-for-line with it: the
/// thresholds are a product decision, and two surfaces disagreeing about what
/// counts as a weak or stale password would be worse than either rule alone.
public enum HealthIssueKind: String, Sendable, Equatable {
    case reused
    case weak
    case stale
    case empty
}

public struct HealthIssue: Sendable, Equatable, Identifiable {
    public var kind: HealthIssueKind
    public var entryId: String
    public var title: String
    public var detail: String

    /// Distinct per finding, since one entry can be flagged for several reasons.
    public var id: String { "\(kind.rawValue)-\(entryId)" }

    public init(kind: HealthIssueKind, entryId: String, title: String, detail: String) {
        self.kind = kind
        self.entryId = entryId
        self.title = title
        self.detail = detail
    }
}

public struct VaultHealthReport: Sendable, Equatable {
    public var issues: [HealthIssue]
    public var checkedAt: String
    public var loginCount: Int

    public init(issues: [HealthIssue], checkedAt: String, loginCount: Int) {
        self.issues = issues
        self.checkedAt = checkedAt
        self.loginCount = loginCount
    }
}

private let STALE_SECONDS: TimeInterval = 365 * 24 * 60 * 60
private let WEAK_MAX_SCORE = 1

/// ISO-8601 with and without fractional seconds — vaults contain both, depending
/// on which surface wrote the timestamp. File-private to match how Sync.swift and
/// Vault.swift already keep their own copies.
private func parseISODate(_ iso: String) -> Date? {
    let withFraction = ISO8601DateFormatter()
    withFraction.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
    if let date = withFraction.date(from: iso) { return date }
    let plain = ISO8601DateFormatter()
    plain.formatOptions = [.withInternetDateTime]
    return plain.date(from: iso)
}

private func isoString(from date: Date) -> String {
    let formatter = ISO8601DateFormatter()
    formatter.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
    return formatter.string(from: date)
}

public func analyzeVaultHealth(_ data: VaultData, now: Date = Date()) -> VaultHealthReport {
    let logins = data.entries.filter { $0.kind == .login }
    var issues: [HealthIssue] = []

    var byPassword: [String: [Entry]] = [:]

    for entry in logins {
        if entry.password.isEmpty {
            issues.append(
                HealthIssue(kind: .empty, entryId: entry.id, title: entry.title, detail: "No password stored.")
            )
            continue
        }

        byPassword[entry.password, default: []].append(entry)

        let strength = estimateStrength(entry.password)
        if strength.score <= WEAK_MAX_SCORE {
            issues.append(
                HealthIssue(
                    kind: .weak,
                    entryId: entry.id,
                    title: entry.title,
                    detail: "Password looks \(strength.label) (~\(strength.bits) bits)."
                )
            )
        }

        if let updated = parseISODate(entry.passwordUpdatedAt) {
            let age = now.timeIntervalSince(updated)
            if age > STALE_SECONDS {
                let years = Int(age / STALE_SECONDS)
                issues.append(
                    HealthIssue(
                        kind: .stale,
                        entryId: entry.id,
                        title: entry.title,
                        detail: years <= 1
                            ? "Password not changed in over a year."
                            : "Password not changed in ~\(years) years."
                    )
                )
            }
        }
    }

    for (_, group) in byPassword where group.count >= 2 {
        for entry in group {
            let others = group.count - 1
            issues.append(
                HealthIssue(
                    kind: .reused,
                    entryId: entry.id,
                    title: entry.title,
                    detail: "Same password as \(others) other login\(others == 1 ? "" : "s")."
                )
            )
        }
    }

    let order: [HealthIssueKind: Int] = [.empty: 0, .reused: 1, .weak: 2, .stale: 3]
    issues.sort { a, b in
        let rankA = order[a.kind] ?? 0
        let rankB = order[b.kind] ?? 0
        if rankA != rankB { return rankA < rankB }
        return a.title.localizedCompare(b.title) == .orderedAscending
    }

    return VaultHealthReport(issues: issues, checkedAt: isoString(from: now), loginCount: logins.count)
}
