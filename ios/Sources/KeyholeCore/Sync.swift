import Foundation

public let TOMBSTONE_TTL_DAYS = 180

private let dayMs: Double = 24 * 60 * 60 * 1000

private func time(_ iso: String) -> Double {
    let f1 = ISO8601DateFormatter()
    f1.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
    if let d = f1.date(from: iso) {
        return d.timeIntervalSince1970 * 1000
    }
    let f2 = ISO8601DateFormatter()
    f2.formatOptions = [.withInternetDateTime]
    if let d = f2.date(from: iso) {
        return d.timeIntervalSince1970 * 1000
    }
    return 0
}

private func latest(_ a: String, _ b: String) -> String {
    time(a) >= time(b) ? a : b
}

/// Union two password histories, newest first, capped. Keyed on
/// (changedAt, password) exactly as `mergeHistory` does in core/src/sync.ts, so
/// both implementations converge on the same result.
private func mergeHistory(
    _ a: [PasswordHistoryEntry],
    _ b: [PasswordHistoryEntry]
) -> [PasswordHistoryEntry] {
    var seen = Set<String>()
    var merged: [PasswordHistoryEntry] = []
    for row in a + b {
        let key = (try? VaultJSON.canonicalString([row.changedAt, row.password])) ?? "\(row.changedAt)|\(row.password)"
        if seen.contains(key) { continue }
        seen.insert(key)
        merged.append(row)
    }
    merged.sort { time($0.changedAt) > time($1.changedAt) }
    return Array(merged.prefix(PASSWORD_HISTORY_LIMIT))
}

/// Union passkeys by credential id. Prefer the higher sign count (more uses);
/// when equal, keep the side with the later `lastUsedAt` / `createdAt`.
private func mergePasskeys(_ a: [PasskeyRecord], _ b: [PasskeyRecord]) -> [PasskeyRecord] {
    var byCred: [String: PasskeyRecord] = [:]
    for row in a + b {
        if let existing = byCred[row.credentialIdB64] {
            if row.signCount > existing.signCount {
                byCred[row.credentialIdB64] = row
            } else if row.signCount == existing.signCount {
                let rowUsed = time(row.lastUsedAt ?? row.createdAt)
                let existingUsed = time(existing.lastUsedAt ?? existing.createdAt)
                if rowUsed > existingUsed {
                    byCred[row.credentialIdB64] = row
                } else if rowUsed == existingUsed {
                    byCred[row.credentialIdB64] = breakTie(existing, row)
                }
            }
        } else {
            byCred[row.credentialIdB64] = row
        }
    }
    return byCred.values.sorted { $0.credentialIdB64 < $1.credentialIdB64 }
}

private func breakTie<T: Encodable>(_ a: T, _ b: T) -> T {
    let sa = (try? VaultJSON.canonicalString(a)) ?? ""
    let sb = (try? VaultJSON.canonicalString(b)) ?? ""
    return sa >= sb ? a : b
}

private func mergeTombstones(_ a: [Tombstone], _ b: [Tombstone]) -> [Tombstone] {
    var byKey: [String: Tombstone] = [:]
    for t in a + b {
        let key = "\(t.kind.rawValue):\(t.id)"
        if let existing = byKey[key] {
            if time(t.deletedAt) > time(existing.deletedAt) {
                byKey[key] = t
            }
        } else {
            byKey[key] = t
        }
    }
    return byKey.values.sorted {
        "\($0.kind.rawValue):\($0.id)" < "\($1.kind.rawValue):\($1.id)"
    }
}

private func pruneTombstones(_ tombstones: [Tombstone], nowMs: Double) -> [Tombstone] {
    let cutoff = nowMs - Double(TOMBSTONE_TTL_DAYS) * dayMs
    return tombstones.filter { time($0.deletedAt) >= cutoff }
}

public struct MergeStats: Sendable, Equatable {
    public var entriesKept: Int
    public var entriesDeleted: Int
    public var entriesReconciled: Int
    public var foldersKept: Int
    public var tombstones: Int

    public init(
        entriesKept: Int,
        entriesDeleted: Int,
        entriesReconciled: Int,
        foldersKept: Int,
        tombstones: Int
    ) {
        self.entriesKept = entriesKept
        self.entriesDeleted = entriesDeleted
        self.entriesReconciled = entriesReconciled
        self.foldersKept = foldersKept
        self.tombstones = tombstones
    }
}

public struct MergeResult: Sendable {
    public var data: VaultData
    public var stats: MergeStats

    public init(data: VaultData, stats: MergeStats) {
        self.data = data
        self.stats = stats
    }
}

public func mergeVaultData(_ a: VaultData, _ b: VaultData, nowMs: Double = Date().timeIntervalSince1970 * 1000) -> MergeResult {
    let tombstones = pruneTombstones(mergeTombstones(a.tombstones, b.tombstones), nowMs: nowMs)
    var deletedAt: [String: Double] = [:]
    for t in tombstones {
        deletedAt["\(t.kind.rawValue):\(t.id)"] = time(t.deletedAt)
    }

    var entryById: [String: Entry] = [:]
    var entriesReconciled = 0

    for entry in a.entries + b.entries {
        if let existing = entryById[entry.id] {
            let sa = (try? VaultJSON.canonicalString(existing)) ?? ""
            let sb = (try? VaultJSON.canonicalString(entry)) ?? ""
            if sa != sb { entriesReconciled += 1 }
            let ta = time(existing.updatedAt)
            let tb = time(entry.updatedAt)
            var winner = ta == tb ? breakTie(existing, entry) : (ta > tb ? existing : entry)
            // History is a log, not a state: last-write-wins would drop whichever
            // device's rotation lost the comparison. Mirrors core/src/sync.ts.
            winner.history = mergeHistory(existing.history, entry.history)
            // Passkeys are also a set of credentials — union by credential id so a
            // registration on one device is not dropped when the other side wins LWW.
            winner.passkeys = mergePasskeys(existing.passkeys, entry.passkeys)
            entryById[entry.id] = winner
        } else {
            entryById[entry.id] = entry
        }
    }

    var entriesDeleted = 0
    var entries: [Entry] = []
    for entry in entryById.values {
        if let tomb = deletedAt["entry:\(entry.id)"], tomb >= time(entry.updatedAt) {
            entriesDeleted += 1
            continue
        }
        entries.append(entry)
    }

    var folderById: [String: Folder] = [:]
    for folder in a.folders + b.folders {
        if let existing = folderById[folder.id] {
            folderById[folder.id] = breakTie(existing, folder)
        } else {
            folderById[folder.id] = folder
        }
    }

    var folders: [Folder] = []
    for folder in folderById.values {
        if let tomb = deletedAt["folder:\(folder.id)"], tomb >= time(folder.createdAt) {
            continue
        }
        folders.append(folder)
    }

    let liveFolders = Set(folders.map(\.id))
    var reconciledEntries = entries.map { e -> Entry in
        var copy = e
        if let fid = copy.folderId, !liveFolders.contains(fid) {
            copy.folderId = nil
        }
        return copy
    }

    reconciledEntries.sort { $0.id < $1.id }
    folders.sort { $0.id < $1.id }

    let newer = time(a.updatedAt) >= time(b.updatedAt) ? a : b

    return MergeResult(
        data: VaultData(
            schemaVersion: SCHEMA_VERSION,
            entries: reconciledEntries,
            folders: folders,
            tombstones: tombstones,
            settings: newer.settings,
            updatedAt: latest(a.updatedAt, b.updatedAt)
        ),
        stats: MergeStats(
            entriesKept: reconciledEntries.count,
            entriesDeleted: entriesDeleted,
            entriesReconciled: entriesReconciled,
            foldersKept: folders.count,
            tombstones: tombstones.count
        )
    )
}
