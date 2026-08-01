import Foundation

/// Registrable-domain ("same site") detection — port of `core/src/public-suffix.ts`.
///
/// This exists for one job: the loosest autofill match mode, where a login saved
/// for `accounts.example.com` should also be offered on `billing.example.com`.
/// That question cannot be answered by counting labels. `a.example.com` and
/// `b.example.com` are the same site; `a.co.uk` and `b.co.uk` are two unrelated
/// registrants; `a.github.io` and `b.github.io` are two unrelated people. Where
/// the public suffix ends is the whole answer, and getting it wrong hands a
/// credential to a stranger.
///
/// So this module is deliberately FAIL-CLOSED: when it cannot prove where the
/// suffix ends it returns nil, and the caller falls back to the stricter modes
/// (exact origin / same host / subdomain of the entry) which need no list at all.
///
/// Keep this in sync with `core/src/public-suffix.ts` — same three layers,
/// same lists.

/// Longest listed suffix, in labels. Bounds the lookup loop.
private let MAX_SUFFIX_LABELS = 3

/// Namespaces that are never "the same site" — reserved, internal, or otherwise
/// not a registry where a shared parent implies a shared owner.
private let RESERVED_TLDS: Set<String> = [
    "arpa", "corp", "example", "home", "internal", "intranet", "invalid", "lan",
    "local", "localdomain", "localhost", "onion", "private", "test",
]

/// Public suffixes of two or more labels.
///
/// Over-listing is safe (it only makes matching stricter, costing a suggestion);
/// under-listing is what the fallback guards below are there to catch.
private let MULTI_LABEL_SUFFIXES: Set<String> = [
    // --- ICANN: ccTLD second levels -----------------------------------------
    // United Kingdom
    "co.uk", "org.uk", "me.uk", "ltd.uk", "plc.uk", "net.uk", "sch.uk", "ac.uk", "gov.uk",
    "mod.uk", "nic.uk",
    // Ireland, Europe
    "gov.ie", "ac.at", "co.at", "gv.at", "or.at", "asso.fr", "com.fr", "gouv.fr", "nom.fr",
    "prd.fr", "tm.fr", "com.es", "nom.es", "org.es", "gob.es", "edu.es", "gov.pl", "com.pl",
    "net.pl", "org.pl", "edu.pl", "gov.pt", "com.pt", "edu.pt", "org.pt", "gov.gr", "com.gr",
    "edu.gr", "net.gr", "org.gr", "gov.it", "edu.it", "gov.ua", "com.ua", "net.ua", "org.ua",
    "in.ua", "kiev.ua", "gov.ru", "com.ru", "net.ru", "org.ru", "edu.ru", "ac.ru", "msk.ru",
    "spb.ru", "gov.by", "com.by", "com.hr", "com.cy", "ac.cy", "gov.cy", "net.cy", "org.cy",
    "gov.se", "com.se",
    // Asia-Pacific
    "co.jp", "ne.jp", "or.jp", "ac.jp", "ad.jp", "ed.jp", "go.jp", "gr.jp", "lg.jp",
    "co.kr", "ne.kr", "or.kr", "re.kr", "pe.kr", "go.kr", "ac.kr", "hs.kr", "ms.kr", "es.kr",
    "sc.kr", "kg.kr", "mil.kr",
    "com.cn", "net.cn", "org.cn", "gov.cn", "edu.cn", "ac.cn", "mil.cn",
    "com.hk", "net.hk", "org.hk", "edu.hk", "gov.hk", "idv.hk",
    "com.tw", "net.tw", "org.tw", "edu.tw", "gov.tw", "idv.tw",
    "com.sg", "net.sg", "org.sg", "edu.sg", "gov.sg", "per.sg",
    "com.my", "net.my", "org.my", "edu.my", "gov.my", "mil.my", "name.my",
    "co.id", "or.id", "ac.id", "web.id", "my.id", "biz.id", "net.id", "sch.id", "go.id", "desa.id",
    "com.ph", "net.ph", "org.ph", "edu.ph", "gov.ph",
    "com.vn", "net.vn", "org.vn", "edu.vn", "gov.vn",
    "co.th", "in.th", "ac.th", "go.th", "or.th", "net.th", "mi.th",
    "co.in", "net.in", "org.in", "firm.in", "gen.in", "ind.in", "ac.in", "edu.in", "gov.in",
    "mil.in", "res.in", "nic.in",
    "com.pk", "net.pk", "org.pk", "edu.pk", "gov.pk",
    "com.bd", "net.bd", "org.bd", "edu.bd", "gov.bd",
    "com.lk", "net.lk", "org.lk", "edu.lk", "gov.lk", "ac.lk",
    "com.np", "org.np", "edu.np", "gov.np",
    "com.au", "net.au", "org.au", "edu.au", "gov.au", "asn.au", "id.au", "csiro.au",
    "co.nz", "net.nz", "org.nz", "ac.nz", "geek.nz", "gen.nz", "kiwi.nz", "school.nz",
    "govt.nz", "health.nz", "iwi.nz", "maori.nz", "mil.nz", "parliament.nz",
    // Middle East, Africa
    "co.il", "org.il", "net.il", "ac.il", "gov.il", "muni.il", "k12.il", "idf.il",
    "com.tr", "net.tr", "org.tr", "gen.tr", "gov.tr", "edu.tr", "k12.tr", "av.tr", "bel.tr",
    "biz.tr", "info.tr", "web.tr", "tv.tr",
    "com.sa", "net.sa", "org.sa", "edu.sa", "gov.sa", "med.sa", "sch.sa",
    "com.ae", "net.ae", "org.ae", "ac.ae", "gov.ae", "sch.ae",
    "com.eg", "net.eg", "org.eg", "edu.eg", "gov.eg", "sci.eg",
    "co.za", "org.za", "net.za", "web.za", "ac.za", "gov.za", "edu.za", "mil.za", "nom.za",
    "school.za",
    "co.ke", "or.ke", "ac.ke", "go.ke", "ne.ke", "sc.ke",
    "com.ng", "net.ng", "org.ng", "edu.ng", "gov.ng",
    "com.gh", "org.gh", "edu.gh", "gov.gh",
    "co.tz", "ac.tz", "go.tz", "or.tz",
    "co.ug", "or.ug", "ac.ug", "go.ug", "ne.ug", "sc.ug",
    "co.zw", "org.zw", "ac.zw", "gov.zw",
    "com.ma", "net.ma", "org.ma", "ac.ma", "gov.ma",
    // Americas
    "com.br", "net.br", "org.br", "gov.br", "edu.br", "art.br", "blog.br", "dev.br", "eco.br",
    "emp.br", "eng.br", "esp.br", "ind.br", "inf.br", "jus.br", "leg.br", "mil.br", "mp.br",
    "mus.br", "rec.br", "srv.br", "tur.br", "tv.br", "wiki.br",
    "com.mx", "org.mx", "net.mx", "edu.mx", "gob.mx",
    "com.ar", "net.ar", "org.ar", "gob.ar", "edu.ar", "int.ar", "mil.ar", "tur.ar",
    "com.co", "net.co", "org.co", "nom.co", "edu.co", "gov.co", "mil.co", "arts.co", "firm.co",
    "info.co", "int.co", "rec.co", "web.co",
    "com.pe", "net.pe", "org.pe", "edu.pe", "gob.pe", "nom.pe", "mil.pe", "sld.pe",
    "com.ve", "net.ve", "org.ve", "edu.ve", "gob.ve", "info.ve", "web.ve",
    "com.uy", "net.uy", "org.uy", "edu.uy", "gub.uy", "mil.uy",
    "com.ec", "net.ec", "org.ec", "edu.ec", "gob.ec", "fin.ec", "med.ec", "pro.ec", "info.ec",
    "k12.ec", "mil.ec",
    "co.cl", "gob.cl", "gov.cl", "mil.cl",
    "com.bo", "net.bo", "org.bo", "edu.bo", "gob.bo", "gov.bo",
    "com.py", "net.py", "org.py", "edu.py", "gov.py",
    "com.do", "net.do", "org.do", "edu.do", "gob.do", "gov.do",
    "com.gt", "net.gt", "org.gt", "edu.gt", "gob.gt",
    "com.cu", "net.cu", "org.cu", "edu.cu", "gov.cu",
    "com.pa", "net.pa", "org.pa", "edu.pa", "gob.pa", "ac.pa",
    "com.pr", "net.pr", "org.pr", "edu.pr", "gov.pr",
    // Flat-ish registries that still carve out a second level
    "com.io", "com.ai", "net.ai", "org.ai", "off.ai", "co.me", "net.me", "org.me", "edu.me",
    "ac.me", "gov.me", "its.me", "priv.me", "co.gg", "net.gg", "org.gg", "co.je", "net.je",
    "org.je", "co.im", "net.im", "org.im", "ac.im", "gov.im", "com.fm", "net.fm", "org.fm",
    "edu.fm",

    // --- Private: multi-tenant hosts, where siblings are separate owners ------
    // Code hosting / static sites
    "github.io", "githubusercontent.com", "github.dev", "gitlab.io", "pages.dev", "workers.dev",
    "r2.dev", "netlify.app", "vercel.app", "now.sh", "surge.sh", "js.org", "readthedocs.io",
    "sourceforge.io", "codeberg.page", "neocities.org",
    // PaaS / app hosting
    "herokuapp.com", "appspot.com", "run.app", "web.app", "firebaseapp.com", "fly.dev",
    "onrender.com", "railway.app", "up.railway.app", "koyeb.app", "deta.app",
    "pythonanywhere.com", "glitch.me", "repl.co", "replit.dev", "stackblitz.io", "csb.app",
    "azurewebsites.net", "azurestaticapps.net", "cloudapp.azure.com", "cloudapp.net",
    "elasticbeanstalk.com", "amazonaws.com", "s3.amazonaws.com", "compute.amazonaws.com",
    "compute-1.amazonaws.com", "elb.amazonaws.com", "cloudfront.net",
    // Tunnels and previews — an attacker can trivially get a sibling here
    "ngrok.io", "ngrok.app", "ngrok-free.app", "trycloudflare.com", "loca.lt", "serveo.net",
    // Site builders and SaaS tenants
    "blogspot.com", "wordpress.com", "wpcomstaging.com", "wixsite.com", "editorx.io",
    "webflow.io", "myshopify.com", "shopifypreview.com", "notion.site", "atlassian.net",
    "force.com", "my.salesforce.com", "translate.goog",
]

/// Registry-generic labels. If the single-label fallback lands on one of these as
/// the *base* label, we almost certainly hit a second-level suffix we failed to
/// list — `a.co.ug` would otherwise resolve to `co.ug` and pool every Ugandan
/// commercial site into one "site". Refuse instead.
///
/// Cost of a false positive: a site literally named `store.com` loses similar-site
/// suggestions. Cost of a false negative: a credential leak. Easy trade.
private let GENERIC_REGISTRY_LABELS: Set<String> = [
    "ac", "ad", "asn", "asso", "av", "bel", "biz", "co", "com", "desa", "ed", "edu", "eng",
    "ens", "firm", "gen", "geek", "go", "gob", "gouv", "gov", "govt", "gr", "gub", "gv", "hs",
    "id", "idv", "in", "ind", "inf", "info", "int", "jus", "k12", "kg", "leg", "lg", "ltd",
    "med", "mi", "mil", "ms", "muni", "name", "ne", "net", "nic", "nom", "of", "off", "or",
    "org", "pe", "per", "plc", "pol", "pp", "prd", "pri", "priv", "pro", "pub", "re", "rec",
    "res", "sc", "sch", "school", "sci", "sld", "srv", "store", "tm", "tur", "tv", "web", "www",
]

/// IPv4/IPv6 literals have no registrable domain — same-host matching covers them.
private func isIpLiteral(_ host: String) -> Bool {
    if host.contains(":") { return true } // bracketed IPv6 arrives as [::1]
    return host.range(of: "^\\d+(?:\\.\\d+){3}$", options: .regularExpression) != nil
}

/// The registrable domain (public suffix + one label) of `hostname`, or nil when
/// that cannot be established safely.
///
/// Nil is not an error — it means "do not treat any two hosts here as the same
/// site". Callers must fall back to a stricter rule, never to a looser one.
public func registrableDomain(_ hostname: String) -> String? {
    var host = hostname.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
    if host.hasSuffix(".") { host.removeLast() }
    guard !host.isEmpty else { return nil }
    if isIpLiteral(host) { return nil }

    let labels = host.split(separator: ".", omittingEmptySubsequences: false).map(String.init)
    if labels.count < 2 { return nil } // bare host: `localhost`, an intranet name
    if labels.contains(where: { $0.isEmpty }) { return nil }

    let tld = labels[labels.count - 1]
    if RESERVED_TLDS.contains(tld) { return nil }
    // A real TLD is alphabetic (or an `xn--` A-label, which also starts alphabetic).
    guard tld.range(of: "^[a-z][a-z0-9-]{1,}$", options: .regularExpression) != nil else { return nil }

    // Longest listed suffix wins, so `www.github.io` resolves against `github.io`
    // rather than `io`.
    let firstStart = max(0, labels.count - MAX_SUFFIX_LABELS)
    var start = firstStart
    while start < labels.count - 1 {
        let candidate = labels[start...].joined(separator: ".")
        if MULTI_LABEL_SUFFIXES.contains(candidate) {
            // The host *is* a public suffix (`co.uk`, `github.io`) — nothing to register.
            if start == 0 { return nil }
            return labels[(start - 1)...].joined(separator: ".")
        }
        start += 1
    }

    // Fallback: the TLD alone is the suffix. Guard against having missed one.
    let base = labels[labels.count - 2]
    if GENERIC_REGISTRY_LABELS.contains(base) { return nil }
    // Every Italian province suffix (`mi.it`, `rm.it`) and most unlisted ccTLD
    // second levels are two letters. Under a two-letter ccTLD, refuse them.
    if tld.count == 2 && base.count <= 2 { return nil }
    return "\(base).\(tld)"
}

/// True when two hostnames belong to the same registrable domain.
///
/// False whenever either side is unresolvable, so an unknown namespace can never
/// widen a match.
public func isSameSite(_ hostA: String, _ hostB: String) -> Bool {
    guard let a = registrableDomain(hostA) else { return false }
    return a == registrableDomain(hostB)
}
