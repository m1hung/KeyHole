/**
 * Registrable-domain ("same site") detection.
 *
 * This exists for one job: the loosest autofill match mode, where a login saved
 * for `accounts.example.com` should also be offered on `billing.example.com`.
 * That question cannot be answered by counting labels. `a.example.com` and
 * `b.example.com` are the same site; `a.co.uk` and `b.co.uk` are two unrelated
 * registrants; `a.github.io` and `b.github.io` are two unrelated people. Where
 * the public suffix ends is the whole answer, and getting it wrong hands a
 * credential to a stranger.
 *
 * So this module is deliberately FAIL-CLOSED: when it cannot prove where the
 * suffix ends it returns null, and the caller falls back to the stricter modes
 * (exact origin / same host / subdomain of the entry) which need no list at all.
 *
 * It is not the full Public Suffix List — ~10k rules, almost all of them
 * irrelevant to logins, refreshed weekly, which is not a thing to vendor into a
 * password manager by hand. It is three layers:
 *
 *   1. An explicit list of multi-label public suffixes: ccTLD second levels
 *      (`co.uk`, `com.au`, …) and multi-tenant hosting domains (`github.io`,
 *      `myshopify.com`, …) where sibling subdomains have different owners.
 *   2. A fallback treating a single trailing label as the suffix. That is
 *      correct for `.com` and for effectively every new gTLD.
 *   3. Guards that refuse the fallback whenever its result *looks* like an
 *      unlisted suffix: a registry-generic base label (`a.co.ug` → `co.ug`) or a
 *      two-letter base label under a two-letter ccTLD (`a.mi.it` → `mi.it`).
 *
 * Known limitation, stated rather than hidden: a few rarely-used namespaces are
 * neither listed nor caught by the guards — Italian city domains such as
 * `roma.it` are the clearest example. Two hosts there resolve as same-site. That
 * is why `domain` matching is opt-in per call site, and why the UI labels these
 * matches as *similar* rather than presenting them as the site itself.
 */

/** Longest listed suffix, in labels. Bounds the lookup loop. */
const MAX_SUFFIX_LABELS = 3;

/**
 * Namespaces that are never "the same site" — reserved, internal, or otherwise
 * not a registry where a shared parent implies a shared owner.
 */
const RESERVED_TLDS = new Set([
  'arpa',
  'corp',
  'example',
  'home',
  'internal',
  'intranet',
  'invalid',
  'lan',
  'local',
  'localdomain',
  'localhost',
  'onion',
  'private',
  'test',
]);

/**
 * Public suffixes of two or more labels.
 *
 * Over-listing is safe (it only makes matching stricter, costing a suggestion);
 * under-listing is what layer 3's guards are there to catch.
 */
const MULTI_LABEL_SUFFIXES: readonly string[] = [
  // --- ICANN: ccTLD second levels -----------------------------------------
  // United Kingdom
  'co.uk', 'org.uk', 'me.uk', 'ltd.uk', 'plc.uk', 'net.uk', 'sch.uk', 'ac.uk', 'gov.uk',
  'mod.uk', 'nic.uk',
  // Ireland, Europe
  'gov.ie', 'ac.at', 'co.at', 'gv.at', 'or.at', 'asso.fr', 'com.fr', 'gouv.fr', 'nom.fr',
  'prd.fr', 'tm.fr', 'com.es', 'nom.es', 'org.es', 'gob.es', 'edu.es', 'gov.pl', 'com.pl',
  'net.pl', 'org.pl', 'edu.pl', 'gov.pt', 'com.pt', 'edu.pt', 'org.pt', 'gov.gr', 'com.gr',
  'edu.gr', 'net.gr', 'org.gr', 'gov.it', 'edu.it', 'gov.ua', 'com.ua', 'net.ua', 'org.ua',
  'in.ua', 'kiev.ua', 'gov.ru', 'com.ru', 'net.ru', 'org.ru', 'edu.ru', 'ac.ru', 'msk.ru',
  'spb.ru', 'gov.by', 'com.by', 'com.hr', 'com.cy', 'ac.cy', 'gov.cy', 'net.cy', 'org.cy',
  'gov.se', 'com.se',
  // Asia-Pacific
  'co.jp', 'ne.jp', 'or.jp', 'ac.jp', 'ad.jp', 'ed.jp', 'go.jp', 'gr.jp', 'lg.jp',
  'co.kr', 'ne.kr', 'or.kr', 're.kr', 'pe.kr', 'go.kr', 'ac.kr', 'hs.kr', 'ms.kr', 'es.kr',
  'sc.kr', 'kg.kr', 'mil.kr',
  'com.cn', 'net.cn', 'org.cn', 'gov.cn', 'edu.cn', 'ac.cn', 'mil.cn',
  'com.hk', 'net.hk', 'org.hk', 'edu.hk', 'gov.hk', 'idv.hk',
  'com.tw', 'net.tw', 'org.tw', 'edu.tw', 'gov.tw', 'idv.tw',
  'com.sg', 'net.sg', 'org.sg', 'edu.sg', 'gov.sg', 'per.sg',
  'com.my', 'net.my', 'org.my', 'edu.my', 'gov.my', 'mil.my', 'name.my',
  'co.id', 'or.id', 'ac.id', 'web.id', 'my.id', 'biz.id', 'net.id', 'sch.id', 'go.id', 'desa.id',
  'com.ph', 'net.ph', 'org.ph', 'edu.ph', 'gov.ph',
  'com.vn', 'net.vn', 'org.vn', 'edu.vn', 'gov.vn',
  'co.th', 'in.th', 'ac.th', 'go.th', 'or.th', 'net.th', 'mi.th',
  'co.in', 'net.in', 'org.in', 'firm.in', 'gen.in', 'ind.in', 'ac.in', 'edu.in', 'gov.in',
  'mil.in', 'res.in', 'nic.in',
  'com.pk', 'net.pk', 'org.pk', 'edu.pk', 'gov.pk',
  'com.bd', 'net.bd', 'org.bd', 'edu.bd', 'gov.bd',
  'com.lk', 'net.lk', 'org.lk', 'edu.lk', 'gov.lk', 'ac.lk',
  'com.np', 'org.np', 'edu.np', 'gov.np',
  'com.au', 'net.au', 'org.au', 'edu.au', 'gov.au', 'asn.au', 'id.au', 'csiro.au',
  'co.nz', 'net.nz', 'org.nz', 'ac.nz', 'geek.nz', 'gen.nz', 'kiwi.nz', 'school.nz',
  'govt.nz', 'health.nz', 'iwi.nz', 'maori.nz', 'mil.nz', 'parliament.nz',
  // Middle East, Africa
  'co.il', 'org.il', 'net.il', 'ac.il', 'gov.il', 'muni.il', 'k12.il', 'idf.il',
  'com.tr', 'net.tr', 'org.tr', 'gen.tr', 'gov.tr', 'edu.tr', 'k12.tr', 'av.tr', 'bel.tr',
  'biz.tr', 'info.tr', 'web.tr', 'tv.tr',
  'com.sa', 'net.sa', 'org.sa', 'edu.sa', 'gov.sa', 'med.sa', 'sch.sa',
  'com.ae', 'net.ae', 'org.ae', 'ac.ae', 'gov.ae', 'sch.ae',
  'com.eg', 'net.eg', 'org.eg', 'edu.eg', 'gov.eg', 'sci.eg',
  'co.za', 'org.za', 'net.za', 'web.za', 'ac.za', 'gov.za', 'edu.za', 'mil.za', 'nom.za',
  'school.za',
  'co.ke', 'or.ke', 'ac.ke', 'go.ke', 'ne.ke', 'sc.ke',
  'com.ng', 'net.ng', 'org.ng', 'edu.ng', 'gov.ng',
  'com.gh', 'org.gh', 'edu.gh', 'gov.gh',
  'co.tz', 'ac.tz', 'go.tz', 'or.tz',
  'co.ug', 'or.ug', 'ac.ug', 'go.ug', 'ne.ug', 'sc.ug',
  'co.zw', 'org.zw', 'ac.zw', 'gov.zw',
  'com.ma', 'net.ma', 'org.ma', 'ac.ma', 'gov.ma',
  // Americas
  'com.br', 'net.br', 'org.br', 'gov.br', 'edu.br', 'art.br', 'blog.br', 'dev.br', 'eco.br',
  'emp.br', 'eng.br', 'esp.br', 'ind.br', 'inf.br', 'jus.br', 'leg.br', 'mil.br', 'mp.br',
  'mus.br', 'rec.br', 'srv.br', 'tur.br', 'tv.br', 'wiki.br',
  'com.mx', 'org.mx', 'net.mx', 'edu.mx', 'gob.mx',
  'com.ar', 'net.ar', 'org.ar', 'gob.ar', 'edu.ar', 'int.ar', 'mil.ar', 'tur.ar',
  'com.co', 'net.co', 'org.co', 'nom.co', 'edu.co', 'gov.co', 'mil.co', 'arts.co', 'firm.co',
  'info.co', 'int.co', 'rec.co', 'web.co',
  'com.pe', 'net.pe', 'org.pe', 'edu.pe', 'gob.pe', 'nom.pe', 'mil.pe', 'sld.pe',
  'com.ve', 'net.ve', 'org.ve', 'edu.ve', 'gob.ve', 'info.ve', 'web.ve',
  'com.uy', 'net.uy', 'org.uy', 'edu.uy', 'gub.uy', 'mil.uy',
  'com.ec', 'net.ec', 'org.ec', 'edu.ec', 'gob.ec', 'fin.ec', 'med.ec', 'pro.ec', 'info.ec',
  'k12.ec', 'mil.ec',
  'co.cl', 'gob.cl', 'gov.cl', 'mil.cl',
  'com.bo', 'net.bo', 'org.bo', 'edu.bo', 'gob.bo', 'gov.bo',
  'com.py', 'net.py', 'org.py', 'edu.py', 'gov.py',
  'com.do', 'net.do', 'org.do', 'edu.do', 'gob.do', 'gov.do',
  'com.gt', 'net.gt', 'org.gt', 'edu.gt', 'gob.gt',
  'com.cu', 'net.cu', 'org.cu', 'edu.cu', 'gov.cu',
  'com.pa', 'net.pa', 'org.pa', 'edu.pa', 'gob.pa', 'ac.pa',
  'com.pr', 'net.pr', 'org.pr', 'edu.pr', 'gov.pr',
  // Flat-ish registries that still carve out a second level
  'com.io', 'com.ai', 'net.ai', 'org.ai', 'off.ai', 'co.me', 'net.me', 'org.me', 'edu.me',
  'ac.me', 'gov.me', 'its.me', 'priv.me', 'co.gg', 'net.gg', 'org.gg', 'co.je', 'net.je',
  'org.je', 'co.im', 'net.im', 'org.im', 'ac.im', 'gov.im', 'com.fm', 'net.fm', 'org.fm',
  'edu.fm',

  // --- Private: multi-tenant hosts, where siblings are separate owners ------
  // Code hosting / static sites
  'github.io', 'githubusercontent.com', 'github.dev', 'gitlab.io', 'pages.dev', 'workers.dev',
  'r2.dev', 'netlify.app', 'vercel.app', 'now.sh', 'surge.sh', 'js.org', 'readthedocs.io',
  'sourceforge.io', 'codeberg.page', 'neocities.org',
  // PaaS / app hosting
  'herokuapp.com', 'appspot.com', 'run.app', 'web.app', 'firebaseapp.com', 'fly.dev',
  'onrender.com', 'railway.app', 'up.railway.app', 'koyeb.app', 'deta.app',
  'pythonanywhere.com', 'glitch.me', 'repl.co', 'replit.dev', 'stackblitz.io', 'csb.app',
  'azurewebsites.net', 'azurestaticapps.net', 'cloudapp.azure.com', 'cloudapp.net',
  'elasticbeanstalk.com', 'amazonaws.com', 's3.amazonaws.com', 'compute.amazonaws.com',
  'compute-1.amazonaws.com', 'elb.amazonaws.com', 'cloudfront.net',
  // Tunnels and previews — an attacker can trivially get a sibling here
  'ngrok.io', 'ngrok.app', 'ngrok-free.app', 'trycloudflare.com', 'loca.lt', 'serveo.net',
  // Site builders and SaaS tenants
  'blogspot.com', 'wordpress.com', 'wpcomstaging.com', 'wixsite.com', 'editorx.io',
  'webflow.io', 'myshopify.com', 'shopifypreview.com', 'notion.site', 'atlassian.net',
  'force.com', 'my.salesforce.com', 'translate.goog',
];

const PUBLIC_SUFFIXES = new Set(MULTI_LABEL_SUFFIXES);

/**
 * Registry-generic labels. If the single-label fallback lands on one of these as
 * the *base* label, we almost certainly hit a second-level suffix we failed to
 * list — `a.co.ug` would otherwise resolve to `co.ug` and pool every Ugandan
 * commercial site into one "site". Refuse instead.
 *
 * Cost of a false positive: a site literally named `store.com` loses similar-site
 * suggestions. Cost of a false negative: a credential leak. Easy trade.
 */
const GENERIC_REGISTRY_LABELS = new Set([
  'ac', 'ad', 'asn', 'asso', 'av', 'bel', 'biz', 'co', 'com', 'desa', 'ed', 'edu', 'eng',
  'ens', 'firm', 'gen', 'geek', 'go', 'gob', 'gouv', 'gov', 'govt', 'gr', 'gub', 'gv', 'hs',
  'id', 'idv', 'in', 'ind', 'inf', 'info', 'int', 'jus', 'k12', 'kg', 'leg', 'lg', 'ltd',
  'med', 'mi', 'mil', 'ms', 'muni', 'name', 'ne', 'net', 'nic', 'nom', 'of', 'off', 'or',
  'org', 'pe', 'per', 'plc', 'pol', 'pp', 'prd', 'pri', 'priv', 'pro', 'pub', 're', 'rec',
  'res', 'sc', 'sch', 'school', 'sci', 'sld', 'srv', 'store', 'tm', 'tur', 'tv', 'web', 'www',
]);

/** IPv4/IPv6 literals have no registrable domain — same-host matching covers them. */
function isIpLiteral(host: string): boolean {
  if (host.includes(':')) return true; // bracketed IPv6 arrives as [::1]
  return /^\d+(?:\.\d+){3}$/.test(host);
}

/**
 * The registrable domain (public suffix + one label) of `hostname`, or null when
 * that cannot be established safely.
 *
 * Null is not an error — it means "do not treat any two hosts here as the same
 * site". Callers must fall back to a stricter rule, never to a looser one.
 */
export function registrableDomain(hostname: string): string | null {
  const host = hostname.trim().toLowerCase().replace(/\.$/, '');
  if (host.length === 0) return null;
  if (isIpLiteral(host)) return null;

  const labels = host.split('.');
  if (labels.length < 2) return null; // bare host: `localhost`, an intranet name
  if (labels.some((label) => label.length === 0)) return null;

  const tld = labels[labels.length - 1] ?? '';
  if (RESERVED_TLDS.has(tld)) return null;
  // A real TLD is alphabetic (or an `xn--` A-label, which also starts alphabetic).
  if (!/^[a-z][a-z0-9-]{1,}$/.test(tld)) return null;

  // Longest listed suffix wins, so `www.github.io` resolves against `github.io`
  // rather than `io`.
  const firstStart = Math.max(0, labels.length - MAX_SUFFIX_LABELS);
  for (let start = firstStart; start < labels.length - 1; start += 1) {
    if (!PUBLIC_SUFFIXES.has(labels.slice(start).join('.'))) continue;
    // The host *is* a public suffix (`co.uk`, `github.io`) — nothing to register.
    if (start === 0) return null;
    return labels.slice(start - 1).join('.');
  }

  // Fallback: the TLD alone is the suffix. Guard against having missed one.
  const base = labels[labels.length - 2] ?? '';
  if (GENERIC_REGISTRY_LABELS.has(base)) return null;
  // Every Italian province suffix (`mi.it`, `rm.it`) and most unlisted ccTLD
  // second levels are two letters. Under a two-letter ccTLD, refuse them.
  if (tld.length === 2 && base.length <= 2) return null;
  return `${base}.${tld}`;
}

/**
 * True when two hostnames belong to the same registrable domain.
 *
 * False whenever either side is unresolvable, so an unknown namespace can never
 * widen a match.
 */
export function isSameSite(hostA: string, hostB: string): boolean {
  const a = registrableDomain(hostA);
  if (a === null) return false;
  return a === registrableDomain(hostB);
}
