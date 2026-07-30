import Foundation

/// URL matching for autofill — port of `core/src/url-match.ts` (host / subdomain / exact).
/// Domain (eTLD+1) mode is omitted until a public-suffix list ships in KeyholeCore.

public enum MatchStrength: String, Sendable {
    case exact, host, subdomain, none
}

public enum MatchMode: String, Sendable {
    case exact, host, subdomain
}

public struct ParsedTarget: Sendable, Equatable {
    public var origin: String
    public var hostname: String
    public var pathname: String
    public var protocolScheme: String
}

private let allowedProtocols: Set<String> = ["https:", "http:"]

public func parseTarget(_ rawUrl: String) -> ParsedTarget? {
    let url: URL?
    if let direct = URL(string: rawUrl), direct.scheme != nil {
        url = direct
    } else {
        url = URL(string: "https://\(rawUrl)")
    }
    guard let url,
          let scheme = url.scheme?.lowercased(),
          allowedProtocols.contains(scheme + ":"),
          var host = url.host?.lowercased(),
          !host.isEmpty
    else { return nil }
    if host.hasSuffix(".") { host.removeLast() }
    let port = url.port.map { ":\($0)" } ?? ""
    let origin = "\(scheme)://\(host)\(port)"
    return ParsedTarget(
        origin: origin,
        hostname: host,
        pathname: url.path.isEmpty ? "/" : url.path,
        protocolScheme: scheme + ":"
    )
}

private func isSubdomainOf(candidate: String, base: String) -> Bool {
    candidate.count > base.count + 1 && candidate.hasSuffix(".\(base)")
}

public func matchUrl(entryUrl: String, pageUrl: String, mode: MatchMode = .host) -> MatchStrength {
    guard let entry = parseTarget(entryUrl), let page = parseTarget(pageUrl) else {
        return .none
    }
    if entry.origin == page.origin { return .exact }
    if mode == .exact { return .none }
    if entry.hostname == page.hostname { return .host }
    if mode == .host { return .none }
    if isSubdomainOf(candidate: page.hostname, base: entry.hostname) {
        return .subdomain
    }
    return .none
}

public struct AutofillMatch: Sendable {
    public var entry: Entry
    public var strength: MatchStrength
}

/// Rank matching live logins for a page URL. Trashed entries are never offered.
public func matchEntriesForAutofill(
    data: VaultData,
    pageUrl: String,
    mode: MatchMode = .host
) -> [AutofillMatch] {
    var ranked: [AutofillMatch] = []
    for entry in liveEntries(data) where entry.kind == .login {
        var best: MatchStrength = .none
        for url in entry.urls {
            let s = matchUrl(entryUrl: url, pageUrl: pageUrl, mode: mode)
            if strengthRank(s) > strengthRank(best) { best = s }
        }
        if best != .none {
            ranked.append(AutofillMatch(entry: entry, strength: best))
        }
    }
    return ranked.sorted {
        if strengthRank($0.strength) != strengthRank($1.strength) {
            return strengthRank($0.strength) > strengthRank($1.strength)
        }
        return $0.entry.title.localizedCaseInsensitiveCompare($1.entry.title) == .orderedAscending
    }
}

private func strengthRank(_ s: MatchStrength) -> Int {
    switch s {
    case .exact: return 4
    case .host: return 3
    case .subdomain: return 2
    case .none: return 0
    }
}
