#!/usr/bin/env python3
"""intel: unified OSINT toolkit.

One command that detects the target type and runs the right keyless modules:

    intel <email>        -> Gravatar profile + breach/stealer exposure + holehe
    intel <@username>    -> maigret/sherlock account finder (+ metadata, recursion)
    intel <domain.com>   -> RDAP whois + crt.sh subdomains
    intel "Acme Ltd"     -> GLEIF entity + ownership (company)
    intel "a person + clues"  -> hint to use the /intel akinator resolver (Exa loop)

Pivots (keyless):
    intel news "<name or company>"        recent global press mentions (GDELT, country-tagged)
    intel localnews "<name>" <locale>     native local press (hr/rs/ba/si/de/fr/it/us/gb/...)
    intel court "<name>"                  US federal court dockets + opinions (CourtListener)
    intel emailguess "First Last" dom.com email-pattern permutations, Gravatar-verified
    intel handles "First Last"            username permutations, GitHub-existence checked
    intel archive <url>                   Wayback change-history + live-vs-archive tamper check
    intel media <profile-or-article-url>  headshot/preview image + title for the brief

Deep (paid, Apify) LinkedIn on demand:
    intel linkedin <profile-or-company-url>     harvestapi (cookieless, ~$0.004)
    intel linkedin-search "title location ..."  people search ($0.10/page)

Flags: --json  --deep (enable paid Apify enrichment of found LinkedIn URLs).
Keyless by default; Apify token read from ~/.config/intel/apify_token or $INTEL_APIFY_TOKEN.
Self / authorized / brand / consenting subjects only.
"""
import base64
import difflib
import glob
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET

UA = {"User-Agent": "intel/1.0 (personal osint)"}
EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
DOMAIN_RE = re.compile(r"^(?=.{1,253}$)([a-z0-9-]{1,63}\.)+[a-z]{2,}$", re.I)
_CO_SUFFIX = re.compile(r"\b(inc|ltd|llc|gmbh|corp|co|ag|plc|sarl|s\.?a\.?|d\.?o\.?o\.?|bv|ab|oy|as)\b", re.I)


def _get(url, headers=None, timeout=15):
    h = dict(UA)
    if headers:
        h.update(headers)
    with urllib.request.urlopen(urllib.request.Request(url, headers=h), timeout=timeout) as r:
        return r.read()


def _json(url, headers=None, timeout=15):
    return json.loads(_get(url, headers, timeout))


# ---------------- detection ----------------

def detect(q):
    q = q.strip()
    if q.startswith("@"):
        return "username"
    if EMAIL_RE.match(q):
        return "email"
    if " " not in q and DOMAIN_RE.match(q):
        return "domain"
    if " " in q or '"' in q:
        return "company" if _CO_SUFFIX.search(q) else "person"
    return "username"


# ---------------- keyless modules ----------------

def mod_username(q, top_sites=300, timeout=8):
    username = q.lstrip("@")
    tmp = tempfile.mkdtemp(prefix="intel_")
    try:
        subprocess.run(["maigret", username, "--top-sites", str(top_sites), "--timeout",
                        str(timeout), "--no-progressbar", "--no-color", "-J", "simple", "-fo", tmp],
                       capture_output=True, text=True, timeout=240)
        accounts, ids, tags = [], set(), set()
        for f in glob.glob(os.path.join(tmp, "report_*_simple.json")):
            uid = os.path.basename(f)[len("report_"):-len("_simple.json")]
            ids.add(uid)
            try:
                data = json.load(open(f))
            except Exception:  # noqa: BLE001
                continue
            for site, info in data.items():
                if isinstance(info, dict) and info.get("url_user"):
                    for kw in (info.get("keywords") or []):
                        tags.add(kw)
                    accounts.append({"platform": site, "url": info["url_user"],
                                     "username": info.get("username", uid), "rank": info.get("rank")})
        seen, uniq = set(), []
        for a in sorted(accounts, key=lambda a: a["rank"] if a["rank"] is not None else 9e9):
            if a["url"] not in seen:
                seen.add(a["url"])
                uniq.append(a)
        return {"module": "username", "seed": username, "accounts": uniq,
                "other_ids": sorted(ids - {username}), "tags": sorted(tags),
                "stealer": _hudsonrock("username", username)}
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def _hudsonrock(kind, value):
    """Hudson Rock Cavalier: is this email/username in infostealer-malware logs? Keyless GET."""
    try:
        d = _json(f"https://cavalier.hudsonrock.com/api/json/v2/osint-tools/search-by-{kind}?"
                  f"{kind}=" + urllib.parse.quote(value), timeout=12)
        return {"message": d.get("message"),
                "user_services": d.get("total_user_services"),
                "corporate_services": d.get("total_corporate_services"),
                "stealer_families": sorted({s.get("stealer_family") for s in d.get("stealers", [])
                                            if isinstance(s, dict) and s.get("stealer_family")})}
    except Exception:  # noqa: BLE001
        return None


def mod_email(q):
    out = {"module": "email", "seed": q, "gravatar": None, "breaches": None,
           "stealer": None, "accounts": []}
    h = hashlib.md5(q.strip().lower().encode()).hexdigest()
    try:
        d = _json(f"https://en.gravatar.com/{h}.json", timeout=10)
        e = (d.get("entry") or [{}])[0] if isinstance(d, dict) else {}
        if e:
            out["gravatar"] = {"name": e.get("displayName"), "username": e.get("preferredUsername"),
                               "about": e.get("aboutMe"), "location": e.get("currentLocation"),
                               "avatar": e.get("thumbnailUrl"),  # headshot for the brief
                               "accounts": [{"service": a.get("shortname"), "url": a.get("url")}
                                            for a in e.get("accounts", [])]}
    except Exception:  # noqa: BLE001 (404 = no gravatar)
        pass
    try:
        d = _json(f"https://leakcheck.io/api/public?check={urllib.parse.quote(q)}", timeout=12)
        if d.get("success"):
            out["breaches"] = {"count": d.get("found"),
                               "sources": [{"name": s.get("name"), "date": s.get("date")}
                                           for s in d.get("sources", [])[:25]],
                               "fields": d.get("fields", [])}
    except Exception:  # noqa: BLE001
        pass
    out["stealer"] = _hudsonrock("email", q)
    try:
        p = subprocess.run(["holehe", q, "--only-used", "--no-color"],
                           capture_output=True, text=True, timeout=180)
        out["accounts"] = [m.group(1) for line in p.stdout.splitlines()
                           if (m := re.match(r"\[\+\]\s+(\S+)", line.strip()))]
    except Exception:  # noqa: BLE001
        pass
    return out


def mod_domain(q):
    out = {"module": "domain", "seed": q, "whois": None, "subdomains": []}
    try:
        d = _json(f"https://rdap.org/domain/{q}", timeout=12)
        if isinstance(d, dict):
            events = {e.get("eventAction"): e.get("eventDate") for e in d.get("events", [])
                      if isinstance(e, dict)}
            registrar = ""
            for ent in d.get("entities", []):
                if "registrar" in (ent.get("roles") or []):
                    v = ent.get("vcardArray", [None, []])[1]
                    for item in v:
                        if item and item[0] == "fn":
                            registrar = item[3]
            out["whois"] = {"domain": d.get("ldhName"), "status": d.get("status"),
                            "registrar": registrar, "registered": events.get("registration"),
                            "expires": events.get("expiration"),
                            "nameservers": [ns.get("ldhName") for ns in d.get("nameservers", [])]}
    except Exception:  # noqa: BLE001
        pass
    try:
        d = _json(f"https://crt.sh/?q={urllib.parse.quote(q)}&output=json", timeout=25)
        subs = set()
        for c in d:
            for name in (c.get("name_value", "").split("\n")):
                name = name.strip().lstrip("*.")
                if name.endswith(q) and name != q:
                    subs.add(name)
        out["subdomains"] = sorted(subs)[:60]
    except Exception:  # noqa: BLE001
        pass
    try:  # Wayback: oldest archived snapshot ~ how long the site has existed publicly
        d = _json("http://web.archive.org/cdx/search/cdx?url=" + urllib.parse.quote(q)
                  + "&output=json&fl=timestamp&limit=1", timeout=15)
        if isinstance(d, list) and len(d) > 1:
            out["first_snapshot"] = d[1][0]
    except Exception:  # noqa: BLE001
        pass
    return out


def mod_company(q):
    out = {"module": "company", "seed": q, "entities": []}
    try:
        d = _json("https://api.gleif.org/api/v1/lei-records?filter%5Bfulltext%5D="
                  + urllib.parse.quote(q) + "&page%5Bsize%5D=5", timeout=12)
        for r in d.get("data", []):
            ent = r["attributes"]["entity"]
            out["entities"].append({"name": ent["legalName"]["name"],
                                    "country": (ent.get("legalAddress") or {}).get("country"),
                                    "status": ent.get("status"), "lei": r["id"]})
    except Exception:  # noqa: BLE001
        pass
    out["hint"] = ("GLEIF only covers LEI-registered (mostly regulated/financial) entities. "
                   "For full company intel use the /intel skill: Exa company search, Wikidata, "
                   "national registers (Croatia sudreg, France recherche-entreprises, GLEIF), "
                   "domain module on their site, and LinkedIn via `intel linkedin`.")
    return out


def news(query, maxrecords=20):
    """GDELT DOC 2.0: recent news mentioning the query, worldwide + local, keyless.
    Each article carries its source country (local/regional press surfaces too) and a
    social image Claude can view for the brief. GDELT rate-limits bursts, so retry once."""
    q = urllib.parse.quote(f'"{query}"' if " " in query else query)
    url = ("https://api.gdeltproject.org/api/v2/doc/doc?query=" + q +
           f"&mode=artlist&maxrecords={maxrecords}&format=json&sort=datedesc")
    d = None
    for attempt in range(2):
        try:
            d = _json(url, timeout=15)
            break
        except Exception:  # noqa: BLE001 (rate-limit returns non-JSON text)
            if attempt == 0:
                time.sleep(6)  # GDELT allows ~1 req / 5s per IP; wait past the window
    if not d:
        return []
    return [{"country": a.get("sourcecountry"), "domain": a.get("domain"),
             "title": a.get("title"), "url": a.get("url"), "date": a.get("seendate"),
             "image": a.get("socialimage")}
            for a in d.get("articles", [])]


def _registrable(dom_or_url):
    dom = dom_or_url
    if "/" in (dom_or_url or ""):
        dom = urllib.parse.urlparse(dom_or_url).netloc
    parts = (dom or "").lower().lstrip("www.").split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else (dom or "")


def corroboration(articles):
    """The 'truth factor', deterministic layer. Public info can be planted, and 20 outlets
    syndicating ONE wire story looks like corroboration but is a single source (circular
    reporting). This scores how INDEPENDENT a set of items really is: distinct publishers +
    near-duplicate headline clusters (copy-paste/syndication)."""
    def norm(t):
        return re.sub(r"[^a-z0-9 ]", "", (t or "").lower()).strip()
    domains = {}
    for a in articles:
        domains.setdefault(_registrable(a.get("domain") or a.get("url", "")), []).append(a)
    titles = [(norm(a.get("title")), a) for a in articles if a.get("title")]
    dups, used = [], set()
    for i, (ti, ai) in enumerate(titles):
        if i in used or not ti:
            continue
        cluster = [ai.get("domain")]
        for j in range(i + 1, len(titles)):
            tj, aj = titles[j]
            if j not in used and tj and difflib.SequenceMatcher(None, ti, tj).ratio() > 0.85:
                cluster.append(aj.get("domain"))
                used.add(j)
        if len(cluster) > 1:
            dups.append(cluster)
    indep = len(domains)
    weak = indep <= 2 or bool(dups)
    return {"items": len(articles), "independent_domains": indep,
            "top_domains": sorted(domains, key=lambda d: -len(domains[d]))[:8],
            "syndication_clusters": dups,
            "caution": ("LOW independence: few distinct publishers or heavy syndication; "
                        "treat as ~1-2 real sources, find the primary." if weak else
                        "Broader independence across publishers; still trace to the primary source.")}


def mod_news(query):
    arts = news(query)
    return {"module": "news", "seed": query, "articles": arts,
            "corroboration": corroboration(arts)}


_LOCALES = {  # locale -> (hl, gl, ceid) for Google News RSS
    "us": ("en-US", "US", "US:en"), "gb": ("en-GB", "GB", "GB:en"),
    "hr": ("hr", "HR", "HR:hr"), "rs": ("sr", "RS", "RS:sr"),
    "ba": ("bs", "BA", "BA:bs"), "si": ("sl", "SI", "SI:sl"),
    "de": ("de", "DE", "DE:de"), "fr": ("fr", "FR", "FR:fr"), "it": ("it", "IT", "IT:it"),
}


def google_news(query, locale="us", limit=15):
    """Google News RSS for one locale — surfaces native local-language press GDELT under-indexes.
    e.g. locale='hr' pulls Croatian outlets by name. Keyless."""
    hl, gl, ceid = _LOCALES.get(locale, _LOCALES["us"])
    url = (f"https://news.google.com/rss/search?q={urllib.parse.quote(query)}"
           f"&hl={hl}&gl={gl}&ceid={ceid}")
    try:
        root = ET.fromstring(_get(url, timeout=12))
    except Exception:  # noqa: BLE001
        return []
    out = []
    for item in root.iter("item"):
        src = item.find("source")
        out.append({"title": (item.findtext("title") or "").strip(), "url": item.findtext("link"),
                    "date": item.findtext("pubDate"), "locale": locale,
                    "source": src.text if src is not None else None})
        if len(out) >= limit:
            break
    return out


def mod_localnews(query, locale):
    return {"module": "localnews", "seed": query, "locale": locale,
            "articles": google_news(query, locale)}


def court(query, limit=10):
    """CourtListener v4 RECAP: US federal dockets + opinions mentioning the query. Keyless."""
    url = ("https://www.courtlistener.com/api/rest/v4/search/?type=r&order_by=score%20desc&q="
           + urllib.parse.quote(f'"{query}"' if " " in query else query))
    try:
        d = _json(url, timeout=20)
    except Exception:  # noqa: BLE001
        return []
    return [{"case": r.get("caseName"), "court": r.get("court"), "date": r.get("dateFiled"),
             "docket": r.get("docketNumber"),
             "url": "https://www.courtlistener.com" + (r.get("absolute_url") or "")}
            for r in d.get("results", [])[:limit]]


def mod_court(query):
    return {"module": "court", "seed": query, "cases": court(query)}


# ---------------- media (headshots / previews, keyless) ----------------

def _meta(html, prop):
    m = re.search(r'<meta[^>]+(?:property|name)=["\']' + re.escape(prop)
                  + r'["\'][^>]*content=["\']([^"\']+)', html, re.I)
    if not m:  # some pages put content= before property=
        m = re.search(r'<meta[^>]+content=["\']([^"\']+)["\'][^>]*(?:property|name)=["\']'
                      + re.escape(prop) + r'["\']', html, re.I)
    return m.group(1) if m else None


def page_media(url):
    """Pull the preview image + title + description a public page advertises about itself
    (og:/twitter: cards). For a profile/article URL this is usually the headshot or hero
    image, so Claude can view and analyse it for the brief. No scraping of private content."""
    try:
        html = _get(url, timeout=12).decode("utf-8", "replace")
    except Exception:  # noqa: BLE001
        return {"url": url}
    title = _meta(html, "og:title") or _meta(html, "twitter:title")
    if not title:
        t = re.search(r"<title[^>]*>(.*?)</title>", html, re.I | re.S)
        title = t.group(1).strip() if t else None
    img = _meta(html, "og:image") or _meta(html, "twitter:image") or _meta(html, "twitter:image:src")
    if img and img.startswith("//"):
        img = "https:" + img
    return {"url": url, "image": img, "title": title,
            "description": _meta(html, "og:description") or _meta(html, "description")}


def mod_media(url):
    return {"module": "media", **page_media(url)}


def embed(url):
    """Fetch an image -> self-contained data: URI, so a headshot embeds in a standalone brief PDF."""
    raw = _get(url, timeout=20)
    low = url.lower().split("?")[0]
    ct = ("image/png" if low.endswith(".png") else "image/webp" if low.endswith(".webp")
          else "image/gif" if low.endswith(".gif") else "image/jpeg")
    return "data:" + ct + ";base64," + base64.b64encode(raw).decode()


# ---------------- permutation + verify (the 'approximations' idea) ----------------

def permute_emails(first, last, domain):
    f, l = re.sub(r"[^a-z]", "", first.lower()), re.sub(r"[^a-z]", "", last.lower())
    fi, li = (f[:1] or "x"), (l[:1] or "x")
    pats = [f"{f}.{l}", f"{f}{l}", f"{fi}{l}", f"{f}{li}", f"{fi}.{l}", f"{l}.{f}",
            f"{l}{f}", f"{f}", f"{f}_{l}", f"{f}-{l}", f"{l}{fi}", f"{fi}{li}", f"{l}.{fi}"]
    return list(dict.fromkeys(f"{p}@{domain}" for p in pats if p and "@" not in p))


def _gravatar_hit(email):
    """Gravatar as a fast, keyless 'is this a real person's email' verifier (+ their name)."""
    h = hashlib.md5(email.strip().lower().encode()).hexdigest()
    try:
        d = _json(f"https://en.gravatar.com/{h}.json", timeout=8)
        e = (d.get("entry") or [{}])[0]
        return e.get("displayName") or e.get("preferredUsername") or "(profile exists)"
    except Exception:  # noqa: BLE001 (404 = no gravatar)
        return None


def mod_emailguess(name, domain):
    parts = name.split()
    cands = permute_emails(parts[0], parts[-1], domain) if len(parts) >= 2 else []
    hits = [{"email": e, "gravatar": g} for e in cands if (g := _gravatar_hit(e))]
    return {"module": "emailguess", "seed": f"{name} @ {domain}", "candidates": cands,
            "gravatar_hits": hits,
            "hint": "Confirm a candidate with `intel <email>` (holehe + breach + Gravatar)."}


def permute_usernames(name):
    parts = re.sub(r"[^a-z ]", "", name.lower()).split()
    if len(parts) < 2:
        b = parts[0] if parts else re.sub(r"[^a-z0-9]", "", name.lower())
        return list(dict.fromkeys([b, f"{b}1", f"{b}_", f"the{b}"]))
    f, l = parts[0], parts[-1]
    fi, li = f[0], l[0]
    return list(dict.fromkeys([f"{f}{l}", f"{f}.{l}", f"{f}_{l}", f"{fi}{l}", f"{f}{li}",
                               f"{l}{f}", f"{l}.{f}", f"{l}{fi}", f"{f}", f"{fi}.{l}", f"{f}-{l}"]))


def _github_user(u):
    """GitHub's public user API as a cheap keyless 'does this handle exist' anchor."""
    try:
        d = _json(f"https://api.github.com/users/{urllib.parse.quote(u)}", timeout=8)
        if isinstance(d, dict) and d.get("login"):
            return {"login": d["login"], "name": d.get("name"), "bio": d.get("bio"),
                    "url": d.get("html_url"), "followers": d.get("followers")}
    except Exception:  # noqa: BLE001 (404 = no such user)
        pass
    return None


def mod_handles(name):
    cands = permute_usernames(name)
    gh = [r for u in cands if (r := _github_user(u))]
    return {"module": "handles", "seed": name, "candidates": cands, "github_hits": gh,
            "hint": "Run `intel <@candidate>` (maigret, 3000+ sites) on the promising handles."}


# ---------------- archive / tamper detection ----------------

def _visible_text(html):
    html = re.sub(r"(?is)<(script|style|noscript)[^>]*>.*?</\1>", " ", html)
    return re.sub(r"\s+", " ", re.sub(r"(?s)<[^>]+>", " ", html)).strip()


def wayback_timeline(url):
    # Oldest capture via a bounded CDX query (first-seen / age); latest capture via the
    # dedicated `available` endpoint (one fast reliable call, unlike a negative-limit CDX scan).
    first = last = None
    try:
        d = _json("http://web.archive.org/cdx/search/cdx?url=" + urllib.parse.quote(url)
                  + "&output=json&fl=timestamp&limit=1", timeout=15)
        if isinstance(d, list) and len(d) > 1:
            first = d[1][0]
    except Exception:  # noqa: BLE001
        pass
    try:
        d = _json("http://archive.org/wayback/available?timestamp=29990101&url="
                  + urllib.parse.quote(url), timeout=12)
        last = (((d or {}).get("archived_snapshots") or {}).get("closest") or {}).get("timestamp")
    except Exception:  # noqa: BLE001
        pass
    out = {}
    if first:
        out["first"] = first
    if last:
        out["last"] = last
    return out


def mod_archive(url):
    """Wayback change-history + a live-vs-last-archive diff: catches a claim quietly inserted
    into an old page, or a story edited after the fact (a deception/tamper tripwire)."""
    out = {"module": "archive", "seed": url, "timeline": wayback_timeline(url)}
    last = (out["timeline"] or {}).get("last")
    if last:
        try:
            live = _visible_text(_get(url, timeout=15).decode("utf-8", "replace"))[:8000]
            arch = _visible_text(_get(f"http://web.archive.org/web/{last}id_/{url}",
                                      timeout=25).decode("utf-8", "replace"))[:8000]
            r = difflib.SequenceMatcher(None, live, arch).ratio()
            # A genuine stealth edit leaves most of a page intact (0.3-0.8). A near-zero score
            # is almost always a render mismatch (JS-rendered live page vs a rendered archive),
            # not a real edit, so treat it as inconclusive rather than crying tamper.
            if r < 0.15:
                note = ("inconclusive: raw live HTML barely overlaps the archive (likely a "
                        "JS-rendered page); render it with browse/reach before diffing")
            elif r < 0.8:
                note = "live page differs from last archive: possible edit/tamper, inspect"
            else:
                note = "live page matches last archive"
            out["live_vs_last_archive"] = {"similarity": round(r, 2), "archived": last, "note": note}
        except Exception:  # noqa: BLE001
            pass
    return out


# ---------------- Apify (deep, paid) ----------------

def _apify_token():
    t = os.environ.get("INTEL_APIFY_TOKEN") or os.environ.get("SIGNAL_APIFY_TOKEN")
    if t:
        return t
    p = os.path.expanduser("~/.config/intel/apify_token")
    return open(p).read().strip() if os.path.exists(p) else None


def run_actor(actor, run_input, timeout=300):
    tok = _apify_token()
    if not tok:
        return {"error": "no Apify token (~/.config/intel/apify_token or $INTEL_APIFY_TOKEN)"}
    aid = actor.replace("/", "~")
    url = f"https://api.apify.com/v2/acts/{aid}/run-sync-get-dataset-items?token={tok}&timeout={timeout}"
    req = urllib.request.Request(url, data=json.dumps(run_input).encode(),
                                 headers={**UA, "Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=timeout + 15) as r:
        return json.loads(r.read())


def linkedin(url):
    if "/company/" in url:
        return {"module": "linkedin-company",
                "data": run_actor("harvestapi/linkedin-company", {"companies": [url]})}
    return {"module": "linkedin-profile",
            "data": run_actor("harvestapi/linkedin-profile-scraper", {"profileUrls": [url]})}


def linkedin_search(query, limit=10):
    return {"module": "linkedin-search",
            "data": run_actor("harvestapi/linkedin-profile-search",
                              {"searchQuery": query, "maxItems": limit})}


# ---------------- assemble + CLI ----------------

def assemble(query, deep=False):
    t = detect(query)
    res = {"query": query, "detected": t, "modules": []}
    if t == "username":
        res["modules"].append(mod_username(query))
    elif t == "email":
        res["modules"].append(mod_email(query))
    elif t == "domain":
        res["modules"].append(mod_domain(query))
    elif t == "company":
        res["modules"].append(mod_company(query))
        res["modules"].append(mod_news(query))
    else:  # person
        res["modules"].append(mod_news(query))  # local + global news mentions (GDELT)
        res["note"] = ("Person-name detected. Deterministic tools can't resolve a fuzzy name; "
                       "use the /intel skill's akinator loop (Exa neural search + Wikidata + "
                       "Claude reasoning) to converge on candidates, then run `intel <@handle>` "
                       "on any handle it surfaces. The news mentions below are a starting pivot.")
    if deep:
        for m in res["modules"]:
            if not m:
                continue
            for a in m.get("accounts", []) if isinstance(m.get("accounts"), list) else []:
                if isinstance(a, dict) and "linkedin.com/in/" in a.get("url", ""):
                    a["linkedin"] = linkedin(a["url"]).get("data")
    res["modules"] = [m for m in res["modules"] if m]
    return res


def _print(res):
    print(f"\nINTEL: {res['query']}   (detected: {res['detected']})")
    if res.get("note"):
        print("  " + res["note"])
    for m in res["modules"]:
        mod = m["module"]
        print(f"\n[{mod}]")
        if mod == "username":
            if m["other_ids"]:
                print("  also seen as:", ", ".join(m["other_ids"]))
            if m["tags"]:
                print("  interests:", ", ".join(m["tags"]))
            s = m.get("stealer")
            if s and s.get("user_services"):
                print(f"  stealer: {s.get('message')} (user svcs {s.get('user_services')})")
            for a in m["accounts"]:
                print(f"    {a['platform']:20} {a['url']}")
        elif mod == "email":
            g = m.get("gravatar")
            if g:
                print(f"  gravatar: {g.get('name')} (@{g.get('username')}) {g.get('location') or ''}")
                if g.get("avatar"):
                    print(f"    headshot: {g['avatar']}")
                for a in g.get("accounts", []):
                    print(f"    {a['service']:14} {a['url']}")
            b = m.get("breaches")
            if b:
                print(f"  breaches: {b['count']} · fields: {', '.join(b.get('fields', [])[:6])}")
                for s in b["sources"][:10]:
                    print(f"    {s['name']:28} {s.get('date') or ''}")
            s = m.get("stealer")
            if s:
                print(f"  stealer: {s.get('message')} (user svcs {s.get('user_services')}, corp {s.get('corporate_services')})")
            if m.get("accounts"):
                print("  registered on:", ", ".join(m["accounts"]))
        elif mod == "domain":
            w = m.get("whois") or {}
            print(f"  whois: registrar={w.get('registrar')} registered={w.get('registered')} expires={w.get('expires')}")
            print(f"  status: {w.get('status')}  ns: {', '.join(w.get('nameservers') or [])}")
            if m.get("first_snapshot"):
                print(f"  first web-archive snapshot: {m['first_snapshot']}")
            print(f"  subdomains ({len(m['subdomains'])}): {', '.join(m['subdomains'][:20])}")
        elif mod == "company":
            for e in m["entities"]:
                print(f"    {e['name']}  [{e.get('country')}]  LEI {e['lei']}")
            print("  " + m["hint"])
        elif mod == "news":
            c = m.get("corroboration") or {}
            if c:
                print(f"  independence: {c.get('independent_domains')} distinct publishers "
                      f"of {c.get('items')} items · {c.get('caution')}")
            for a in m["articles"][:15]:
                print(f"    [{a.get('country', '?')}] {a.get('domain', '')}: {a.get('title', '')[:60]}")


def main(argv=None):
    argv = argv if argv is not None else sys.argv[1:]
    as_json = "--json" in argv
    deep = "--deep" in argv
    a = [x for x in argv if not x.startswith("--")]
    if not a:
        print(__doc__)
        return
    if a[0] == "embed" and len(a) > 1:
        print(embed(a[1]))
        return
    if a[0] == "linkedin" and len(a) > 1:
        out = linkedin(a[1])
    elif a[0] == "linkedin-search" and len(a) > 1:
        out = linkedin_search(" ".join(a[1:]))
    elif a[0] == "news" and len(a) > 1:
        out = mod_news(" ".join(a[1:]))
    elif a[0] == "media" and len(a) > 1:
        out = mod_media(a[1])
    elif a[0] == "localnews" and len(a) > 1:
        loc = a[-1] if a[-1] in _LOCALES else "us"
        q = " ".join(a[1:-1] if a[-1] in _LOCALES else a[1:])
        out = mod_localnews(q, loc)
    elif a[0] == "court" and len(a) > 1:
        out = mod_court(" ".join(a[1:]))
    elif a[0] == "emailguess" and len(a) > 2:
        out = mod_emailguess(" ".join(a[1:-1]), a[-1])  # last arg = domain
    elif a[0] == "handles" and len(a) > 1:
        out = mod_handles(" ".join(a[1:]))
    elif a[0] == "archive" and len(a) > 1:
        out = mod_archive(a[1])
    else:
        out = assemble(" ".join(a), deep=deep)
    if as_json:
        print(json.dumps(out, indent=2, ensure_ascii=False))
    elif "module" in out:
        print(json.dumps(out.get("data", out), indent=2, ensure_ascii=False)[:4000])
    else:
        _print(out)


if __name__ == "__main__":
    main()
