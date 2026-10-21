#!/usr/bin/env python3
"""intel: unified OSINT toolkit.

One command that detects the target type and runs the right keyless modules:

    intel <email>        -> Gravatar profile + breach/stealer exposure + holehe
    intel <@username>    -> maigret/sherlock account finder (+ metadata, recursion)
    intel <domain.com>   -> RDAP whois + crt.sh subdomains
    intel <+43...>       -> line/carrier/type + official block allocation + spam reports
    intel "Acme Ltd"     -> GLEIF entity + ownership (company)
    intel "a person + clues"  -> hint to use the /intel akinator resolver (Exa loop)

Pivots (keyless):
    intel news "<name or company>"        recent global press mentions (GDELT, country-tagged)
    intel localnews "<name>" <locale>     native local press (hr/rs/ba/si/de/fr/it/us/gb/...)
    intel court "<name>"                  US federal court dockets + opinions (CourtListener)
    intel emailguess "First Last" dom.com email-pattern permutations, Gravatar-verified
    intel handles "First Last"            username permutations, GitHub-existence checked
    intel archive <url>                   Wayback change-history + live-vs-archive tamper check
    intel phone <number> [--region=AT]    force phone mode (skips type detection)
                       [--accounts]       + silent Microsoft/Amazon/Zoho existence (phonsint)
    intel media <profile-or-article-url>  headshot/preview image + title for the brief

Deep (paid, Apify) LinkedIn on demand:
    intel linkedin <profile-or-company-url>     harvestapi (cookieless, ~$0.004)
    intel linkedin-search "title location ..."  people search ($0.10/page)

Flags: --json  --deep (paid Apify enrichment of found LinkedIn URLs)  --region=XX (phone).
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
import urllib.error
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET
from html import unescape as html_unescape

UA = {"User-Agent": "intel/1.0 (personal osint)"}
EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
DOMAIN_RE = re.compile(r"^(?=.{1,253}$)([a-z0-9-]{1,63}\.)+[a-z]{2,}$", re.I)
_CO_SUFFIX = re.compile(r"\b(inc|ltd|llc|gmbh|corp|co|ag|plc|sarl|s\.?a\.?|d\.?o\.?o\.?|bv|ab|oy|as)\b", re.I)


def _get(url, headers=None, timeout=15, max_bytes=8 * 1024 * 1024):
    # Only http/https: urllib.urlopen would otherwise open file:// and ftp://, so a
    # user-supplied URL (intel media/embed/archive) could read local files.
    if not str(url).lower().startswith(("http://", "https://")):
        raise ValueError("only http/https URLs are allowed")
    h = dict(UA)
    if headers:
        h.update(headers)
    with urllib.request.urlopen(urllib.request.Request(url, headers=h), timeout=timeout) as r:
        return r.read(max_bytes)  # cap: crt.sh / big pages can be huge


def _json(url, headers=None, timeout=15):
    return json.loads(_get(url, headers, timeout))


# ---------------- detection ----------------

def detect(q):
    q = q.strip()
    if q.startswith("@"):
        return "username"
    if EMAIL_RE.match(q):
        return "email"
    if PHONE_RE.match(q) and 7 <= len(re.sub(r"\D", "", q)) <= 15:
        return "phone"  # E.164 allows 15 digits; <7 is a username, not a number
    if " " not in q and DOMAIN_RE.match(q):
        return "domain"
    if " " in q or '"' in q:
        return "company" if _CO_SUFFIX.search(q) else "person"
    return "username"


# ---------------- keyless modules ----------------

def mod_username(q, top_sites=300, timeout=8):
    username = q.lstrip("@")
    # Must start alphanumeric so it can't be read as a flag by maigret (argument injection),
    # and stay within a sane handle charset.
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}", username):
        return {"module": "username", "seed": username, "accounts": [], "other_ids": [],
                "tags": [], "stealer": None,
                "error": "invalid username: start alphanumeric, <=64 chars of letters/digits/._-"}
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
                with open(f) as fh:
                    data = json.load(fh)
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


def _whois_cli(domain):
    """Fallback to the system `whois` for TLDs RDAP does not cover (many ccTLDs, e.g. .hr)."""
    try:
        out = subprocess.run(["whois", domain], capture_output=True, text=True, timeout=20).stdout
    except Exception:  # noqa: BLE001 (whois missing or timed out)
        return None

    def grab(*keys):
        for k in keys:
            m = re.search(rf"(?im)^\s*{re.escape(k)}\s*:\s*(.+)$", out)
            if m and m.group(1).strip():
                return m.group(1).strip()
        return None

    ns = re.findall(r"(?im)^\s*(?:name ?server|nserver)\s*:\s*([^\s,]+)", out)
    reg = grab("Registrar", "Sponsoring Registrar", "Registrar Name")
    created = grab("Creation Date", "Created On", "Created", "Registration Date", "Registered On")
    if not (reg or ns or created):  # nothing parseable -> treat as no data
        return None
    return {"domain": domain, "registrar": reg, "registered": created,
            "expires": grab("Registrar Registration Expiration Date", "Registry Expiry Date",
                            "Expiration Date", "Expiry Date", "paid-till"),
            "status": grab("Domain Status", "Status"),
            "nameservers": sorted({n.lower() for n in ns}) or None}


def _wayback_first(domain):
    """Oldest Wayback snapshot for `domain` -> (timestamp_or_None, status).

    Returns a (value, status) pair so callers can tell the three states apart:
        ("19961231235847", "found")  - archived since then; age is known
        (None, "none")               - checked, nothing EVER archived. A real signal:
                                       brand-new or deliberately unarchived domain.
        (None, "unknown")            - the lookup failed/timed out. NOT a signal.
                                       The brief must never infer "new domain" from this.

    Deliberately NOT retried: a retry loop (like the GDELT one) would collapse "unknown"
    back into a guess, which is the whole bug this function exists to prevent.
    """
    try:
        d = _json("http://web.archive.org/cdx/search/cdx?url=" + urllib.parse.quote(domain)
                  + "&output=json&fl=timestamp&limit=1", timeout=30)
    except Exception:  # noqa: BLE001 (timeout / rate-limit / junk response)
        return None, "unknown"  # could not check: the brief must infer NOTHING from this
    # CDX gives [['timestamp'], ['19961231235847']] when found; [] or a header-only row
    # when the domain has genuinely never been captured.
    if isinstance(d, list) and len(d) > 1 and d[1]:
        return d[1][0], "found"
    return None, "none"  # checked, nothing ever archived: a real red flag


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
    if not out["whois"]:  # RDAP miss (common for ccTLDs like .hr) -> system whois fallback
        out["whois"] = _whois_cli(q)
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
    # Wayback: oldest archived snapshot ~ how long the site has existed publicly. Age is a
    # deception tripwire (fresh domain + clean narrative = red flag), so the THREE states
    # must stay distinct, same as archive()'s "inconclusive" and the ghost-account check:
    #   found        -> timestamp, age known
    #   no archive   -> REAL signal: nothing ever archived (brand-new / hidden)
    #   lookup failed-> NO signal: unknown, never infer "new" from it
    # 30s, not 15: CDX is slow on huge archives (nasa.gov timed out at 15 and the age signal
    # silently vanished into the same None as "brand-new domain").
    #
    # TODO(Simon): set the semantics below — how should mod_domain report these three?
    out["first_snapshot"], out["first_snapshot_status"] = _wayback_first(q)
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


# ---------------- phone (keyless) ----------------

# These sites 403 the intel/1.0 UA. A normal browser UA is not evasion here, it is the
# difference between "no data" and "data"; we are still just GETting a public page.
_BROWSER_UA = {
    "User-Agent": ("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 "
                   "(KHTML, like Gecko) Chrome/124.0 Safari/537.36"),
    "Accept-Language": "de-AT,de;q=0.9,en;q=0.8",
}

# A phone number once the separators humans type are stripped. Deliberately tighter than
# "any run of digits": detect() sees a bare token, and a 5-digit string is far likelier a
# username than something dialable. Explicit `intel phone <n>` bypasses the guess.
PHONE_RE = re.compile(r"^\+?[0-9][0-9 ().\-/]{5,20}$")

# phonenumbers' PhoneNumberType -> a label. VOIP/UAN matter for spam triage: they are the
# cheap, instantly-recyclable, easily-spoofed ranges a call centre actually dials from.
_LINE_TYPES = {0: "fixed_line", 1: "mobile", 2: "fixed_line_or_mobile", 3: "toll_free",
               4: "premium_rate", 5: "shared_cost", 6: "voip", 7: "personal_number",
               8: "pager", 9: "uan", 10: "voicemail", -1: "unknown"}

# Fallback only, for when libphonenumber is absent: enough to name the country so the
# report is not blank. Never used to claim carrier or validity.
_CC = {"1": "US/CA", "7": "RU/KZ", "20": "EG", "27": "ZA", "30": "GR", "31": "NL",
       "32": "BE", "33": "FR", "34": "ES", "36": "HU", "39": "IT", "40": "RO",
       "41": "CH", "43": "AT", "44": "GB", "45": "DK", "46": "SE", "47": "NO",
       "48": "PL", "49": "DE", "90": "TR", "91": "IN", "212": "MA", "234": "NG",
       "351": "PT", "352": "LU", "353": "IE", "358": "FI", "359": "BG", "370": "LT",
       "371": "LV", "372": "EE", "380": "UA", "381": "RS", "382": "ME", "383": "XK",
       "385": "HR", "386": "SI", "387": "BA", "389": "MK", "420": "CZ", "421": "SK",
       "423": "LI"}

_PN_VENV = "~/.local/share/intel/venv/lib/python*/site-packages"


def _load_phonenumbers():
    """Google's libphonenumber metadata: region, carrier, line type, timezone - all
    OFFLINE. Optional on purpose so `intel` stays stdlib-only; if it is missing we say
    so and degrade, rather than reporting "unknown carrier" as if we had checked."""
    try:
        import phonenumbers  # noqa: PLC0415
        return phonenumbers
    except ImportError:
        pass
    for sp in sorted(glob.glob(os.path.expanduser(_PN_VENV))):
        if sp not in sys.path:
            sys.path.append(sp)
    try:
        import phonenumbers  # noqa: PLC0415
        return phonenumbers
    except ImportError:
        return None


def _phone_digits(q):
    """'+43 664 / 123-45 67' -> '+436641234567'. 00 is the other way to write +."""
    s = re.sub(r"[^\d+]", "", q.strip())
    if s.startswith("00"):
        s = "+" + s[2:]
    return s


def _title(body):
    m = re.search(r"<title[^>]*>(.*?)</title>", body, re.S | re.I)
    return re.sub(r"\s+", " ", html_unescape(m.group(1))).strip() if m else None


def _fetch_final(url, timeout=20, data=None):
    """GET/POST that reports the FINAL url after redirects and never raises on 4xx.
    Both halves matter: spamcalls answers an unlisted number with a redirect to a
    DIFFERENT number's page (see _spamcalls), and a 410 there is real information."""
    req = urllib.request.Request(url, data=data, headers=dict(_BROWSER_UA))
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, r.geturl(), r.read(4 * 1024 * 1024).decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, e.geturl(), e.read(512 * 1024).decode("utf-8", "replace")


def _html_rows(body):
    """Every <tr> in the document as a list of non-empty cell strings."""
    rows = []
    for table in re.findall(r"<table.*?</table>", body, re.S | re.I):
        for tr in re.findall(r"<tr.*?</tr>", table, re.S | re.I):
            cells = [html_unescape(re.sub(r"<[^>]+>", "", c)).strip()
                     for c in re.findall(r"<t[dh].*?</t[dh]>", tr, re.S | re.I)]
            cells = [c for c in cells if c]
            if cells:
                rows.append(cells)
    return rows


def _phone_parse(q, region=None):
    """The offline identity of the number. This is the only part of the phone module
    that cannot be rate-limited, blocked, or handed a lie by a website, so it anchors
    everything else."""
    raw = _phone_digits(q)
    out = {"input": q, "e164": None, "national": None, "valid": None, "possible": None,
           "country": None, "region": None, "carrier": None, "line_type": None,
           "timezones": [], "source": None, "region_assumed": False}
    pn = _load_phonenumbers()
    if pn is None:
        out["source"] = "fallback-table"
        out["note"] = ("libphonenumber is not installed, so validity / carrier / line "
                       "type are UNKNOWN (not negative). Install: python3 -m venv "
                       "~/.local/share/intel/venv && ~/.local/share/intel/venv/bin/pip "
                       "install phonenumbers")
        if raw.startswith("+"):
            for n in (3, 2, 1):
                if raw[1:1 + n] in _CC:
                    out["country"], out["e164"] = _CC[raw[1:1 + n]], raw
                    break
        return out
    from phonenumbers import carrier as _carrier  # noqa: PLC0415
    from phonenumbers import geocoder as _geocoder  # noqa: PLC0415
    from phonenumbers import timezone as _pntz  # noqa: PLC0415
    # A national-format number ("0664 ...") is meaningless without a country. Guessing
    # one is fine; hiding that we guessed is not, because every downstream lookup
    # (RTR, the dorks, the whole report) inherits the guess.
    if not raw.startswith("+") and region is None:
        region, out["region_assumed"] = "AT", True
    elif region:
        region = region.upper()
    try:
        n = pn.parse(raw, region)
    except Exception:  # noqa: BLE001 (NumberParseException -> unparseable input)
        out["error"] = "unparseable"
        return out
    out["source"] = "libphonenumber"
    out["valid"] = pn.is_valid_number(n)
    out["possible"] = pn.is_possible_number(n)
    out["e164"] = pn.format_number(n, pn.PhoneNumberFormat.E164)
    out["national"] = pn.format_number(n, pn.PhoneNumberFormat.NATIONAL)
    out["international"] = pn.format_number(n, pn.PhoneNumberFormat.INTERNATIONAL)
    out["country"] = pn.region_code_for_number(n)
    out["region"] = _geocoder.description_for_number(n, "en") or None
    out["carrier"] = _carrier.name_for_number(n, "en") or None
    out["line_type"] = _LINE_TYPES.get(pn.number_type(n), "unknown")
    out["timezones"] = list(_pntz.time_zones_for_number(n))
    return out


def _rtr_allocation(e164):
    """RTR, the Austrian telecom regulator, publishes which operator holds each number
    BLOCK - and for premium ranges ((0)900/901/810/820/930/931/939) the service
    provider's actual NAME AND ADDRESS. That second case is the only keyless source
    that names the entity behind a number outright, which makes it the hard anchor for
    an Austrian nuisance call. Ordinary end subscribers are NOT public, by law.

    Four distinct states, and they must not be collapsed:
      allocated -> block holder known (and maybe the premium service provider)
      foreign   -> RTR says this is not an Austrian number; ask that country's regulator
      none      -> checked, and the range is not allocated to anyone (real signal:
                   an unallocated range on caller ID means a SPOOFED number)
      unknown   -> the lookup itself failed; infer nothing at all
    """
    out = {"source": "RTR (rtr.at)", "status": "unknown", "blocks": [],
           "service_provider": None,
           "url": "https://www2.rtr.at/de/tk/Rufnummernsuche"}
    body_data = urllib.parse.urlencode({"rufnummern_rufnummer": e164, "art": "",
                                        "rufnummern_rufnummer_hidden": ""}).encode()
    try:
        status, _, body = _fetch_final(out["url"], timeout=25, data=body_data)
    except Exception:  # noqa: BLE001
        return out
    if status != 200:
        return out
    rows = _html_rows(body)
    if any("internationale Rufnummer" in c for row in rows for c in row):
        out["status"] = "foreign"
        return out
    out["blocks"] = [{"range": r[0], "holder": r[1]} for r in rows
                     if len(r) >= 2 and r[0].startswith("(0)")]
    # Premium ranges add a second table; the row after the "Diensteanbieter" header
    # carries "Name\nAddress" for whoever actually operates the number.
    header_seen = False
    for r in rows:
        if any("Diensteanbieter" in c for c in r):
            header_seen = True
            continue
        if header_seen and len(r) >= 2 and r[1] not in ("-", ""):
            name, _, addr = r[1].partition("\n")
            out["service_provider"] = {"name": name.strip(),
                                       "address": re.sub(r"\s*\n\s*", ", ", addr).strip(),
                                       "state": r[0]}
            break
    out["status"] = "allocated" if (out["blocks"] or out["service_provider"]) else "none"
    return out


def _spamcalls(e164):
    """spamcalls.net crowd reports.

    THE TRAP, verified 2026-09-18: an unlisted number does not 404. The site 302s to a
    DIFFERENT, numerically adjacent number's page, which then returns 200 with a scary
    "Scam Call (508 User Reports)" title. Every tool that reads `status == 200` as
    "spammer" (PhoneInfoga-era scripts, Phunter's spam.py) therefore manufactures
    reports for clean numbers. Only a final URL whose digits EQUAL the queried digits
    counts as a hit.
    """
    digits = re.sub(r"\D", "", e164 or "")
    url = f"https://spamcalls.net/en/num/{digits}"
    out = {"source": "spamcalls.net", "status": "unknown", "url": url}
    if not digits:
        return out
    try:
        status, final, body = _fetch_final(url)
    except Exception:  # noqa: BLE001
        return out
    final_digits = re.sub(r"\D", "", final.rsplit("/", 1)[-1])
    if final_digits != digits:
        out["status"] = "not_listed"
        out["note"] = (f"site redirected to a different number ({final_digits}); that is "
                       "its fuzzy fallback page, NOT a report on the queried number")
        return out
    if status in (404, 410):
        out["status"] = "not_listed"
        return out
    if status == 200:
        out["status"] = "listed"
        # The count lives in the body, not the title: a lightly reported number gets a
        # generic "Who owns ...?" title. Anchor on "Spam-Risk", because the sidebar
        # lists OTHER numbers' "(1,363 User Reports)" on the same page.
        text = _page_text(body)
        m = re.search(r"Spam-Risk \w+ \(([\d,]+) User Reports?\)", text)
        out["reports"] = int(m.group(1).replace(",", "")) if m else None
        m = re.search(r"Most frequently reported \([\d,]+ User Reports?\) ([A-Za-z /-]+?) "
                      r"How would", text)
        out["verdict"] = m.group(1).strip() if m else None
    return out


def _page_text(body):
    """Visible text of an HTML page, whitespace-collapsed, for anchoring regexes."""
    body = re.sub(r"(?s)<(script|style)[^>]*>.*?</\1>", " ", body)
    return re.sub(r"\s+", " ", html_unescape(re.sub(r"<[^>]+>", " ", body)))


# Croatian crowd-report sites. Verified 2026-10-13 against a heavily reported HT
# telemarketing line and an unreported number: tko-me-zvao and ciji-broj 404 an
# unreported number (a clean "not_listed"), telefonbroj answers 200 with "još nema
# recenzija". tko-me-zvao silently prefixes 385 to ANY number, so a foreign number
# would come back as a different Croatian one - HR only, never call it for others.
# The comments are the payload here: they are where "the IVR says Hrvatski Telekom"
# style identification lives, so the latest few are returned verbatim.

def _tkomezvao(parsed):
    e164 = parsed.get("e164") or ""
    url = "https://tko-me-zvao.com.hr/broj.php?number=" + urllib.parse.quote(e164)
    out = {"source": "tko-me-zvao.com.hr", "status": "unknown", "url": url}
    try:
        status, _, body = _fetch_final(url)
    except Exception:  # noqa: BLE001
        return out
    if status == 404:
        out["status"] = "not_listed"
        return out
    if status != 200:
        return out
    text = _page_text(body)
    m = re.search(r"dala (\d+) SPAM i (\d+) OK", text)
    c = re.search(r"Komentari korisnika \( ?(\d+) ?\)", text)
    if not (m or c):
        return out  # page shape changed: unknown, not "clean"
    out["status"] = "listed"
    if m:
        out["spam_votes"], out["ok_votes"] = int(m.group(1)), int(m.group(2))
    out["comments"] = int(c.group(1)) if c else 0
    out["latest"] = [
        f"{d[8:10]}.{d[5:7]}.{d[:4]}: {html_unescape(re.sub(r'<[^>]+>', '', t)).strip()[:160]}"
        for d, t in re.findall(r'<time class="comment-date" datetime="([^"]+)".*?'
                               r'<p class="comment-text-large">(.*?)</p>', body, re.S)][:5]
    return out


def _cijibroj(parsed):
    bare = (parsed.get("e164") or "").lstrip("+")
    url = f"https://www.ciji-broj.hr/tel/{bare}"
    out = {"source": "ciji-broj.hr", "status": "unknown", "url": url}
    try:
        status, _, body = _fetch_final(url)
    except Exception:  # noqa: BLE001
        return out
    if status == 404:
        out["status"] = "not_listed"
        return out
    if status != 200:
        return out
    text = _page_text(body)
    ev = re.search(r"Broj evaluacija x (\d+)", text)
    if not ev:
        return out
    co = re.search(r"Broj komentara x (\d+)", text)
    pr = re.search(r"Procjena (\w+)", text)
    out["ratings"] = int(ev.group(1))
    out["comments"] = int(co.group(1)) if co else 0
    out["verdict"] = pr.group(1) if pr else None
    out["status"] = "listed" if out["ratings"] or out["comments"] else "not_listed"
    i = text.find("Komentari [")
    out["latest"] = [f"{d} [{r}] {t.strip()[:160]}" for r, d, t in re.findall(
        r"\[(\w+)\] \[(\d{2}\.\d{2}\.\d{4})\] : (.*?)(?= \[\w+\] \[\d{2}\.|Zadnji pregledani|$)",
        text[i:i + 4000])][:5] if i >= 0 else []
    return out


def _telefonbroj(parsed):
    bare = (parsed.get("e164") or "").lstrip("+")
    url = f"https://telefonbroj.com/hr/pretraga-telefona/{bare}/"
    out = {"source": "telefonbroj.com", "status": "unknown", "url": url}
    try:
        status, _, body = _fetch_final(url)
    except Exception:  # noqa: BLE001
        return out
    if status != 200:
        return out
    text = _page_text(body)
    if "još nema recenzija" in text:
        out["status"] = "not_listed"
        return out
    m = re.search(r"Sve \((\d+)\) Sigurno \((\d+)\) Neutralno \((\d+)\) Opasnost \((\d+)\)", text)
    if not m:
        return out
    out["status"] = "listed"
    out["reports"], out["safe"], out["neutral"], out["dangerous"] = map(int, m.groups())
    return out


def _hakom(parsed):
    """HAKOM, the Croatian regulator. Both public lookups that matter sit behind an image
    CAPTCHA (verified 2026-10-13), so they are handed over as links, never automated:
    e-Prenosivost names the network a number is on NOW (098 is only the ORIGINAL HT
    range; numbers port), and the "Ne zovi" register says whether telemarketing to it
    is illegal. Neither ever reveals the subscriber."""
    return {"status": "manual", "source": "HAKOM (hakom.hr)",
            "note": ("CAPTCHA-gated, open by hand. Current network after porting: "
                     "https://www.hakom.hr/hr/e-prenosivost/216 · on the 'Ne zovi' "
                     "register: https://www.hakom.hr/hr/e-registar-ne-zovi/224")}


# Silent account-existence checks via phonsint (github.com/kaifcodec/phonsint),
# installed in its own venv, pinned to f1f37480d088. Source-reviewed 2026-10-13 at that
# commit: it only contacts the target services, and anything it marks loud needs
# --allow-loud, which is never passed. Only three modules are allowed. Excluded on
# purpose: `instagram` (solves Instagram's anti-automation proof-of-work to get in) and `facebook` (walks
# account recovery and returns the holder's real NAME and PHOTO - a reverse lookup on
# a private person, the same line as Truecaller). Opt-in: `intel phone <n> --accounts`.
_PHONSINT = "~/.local/share/intel/phonsint-venv/bin/phonsint"
_PHONSINT_MODULES = "microsoft,amazon,zoho"


def _accounts(e164):
    exe = os.path.expanduser(_PHONSINT)
    out = {"source": "phonsint", "modules": _PHONSINT_MODULES, "status": "unknown"}
    if not os.path.exists(exe):
        out["status"] = "not_installed"
        out["note"] = ("python3 -m venv ~/.local/share/intel/phonsint-venv && "
                       "~/.local/share/intel/phonsint-venv/bin/pip install "
                       "git+https://github.com/kaifcodec/phonsint@f1f37480d088")
        return out
    with tempfile.TemporaryDirectory() as d:
        dest = os.path.join(d, "r.json")
        try:
            subprocess.run([exe, "-p", e164, "-m", _PHONSINT_MODULES, "--all",
                            "-f", "json", "-o", dest], capture_output=True,
                           timeout=120, check=False)
            with open(dest, encoding="utf-8") as f:
                data = json.load(f)
        except Exception as e:  # noqa: BLE001
            out["error"] = str(e)[:200]
            return out
    out["status"] = "checked"
    out["results"] = data
    return out


def _werruft(parsed):
    """werruft.info, German-language crowd reports. It answers 200 for EVERY number,
    including ones nobody has ever reported, so the rating counts in the title are the
    signal and the status code is worthless."""
    nat = re.sub(r"\D", "", parsed.get("national") or "")
    out = {"source": "werruft.info", "status": "unknown", "url": None}
    if not nat or parsed.get("country") not in ("DE", "AT", "CH"):
        out["status"] = "unsupported"
        out["note"] = "German-language site; only meaningful for DE/AT/CH numbers"
        return out
    out["url"] = url = f"https://www.werruft.info/telefonnummer/{nat}"
    try:
        status, _, body = _fetch_final(url)
    except Exception:  # noqa: BLE001
        return out
    if status != 200:
        return out
    m = re.search(r"Bewertungen:\s*(\d+)\s*\(Negativ:\s*(\d+)\)", _title(body) or "")
    if not m:
        return out
    out["ratings"], out["negative"] = int(m.group(1)), int(m.group(2))
    out["status"] = "listed" if out["ratings"] else "not_listed"
    return out


def _tellows(parsed):
    """tellows is the big DE/AT crowd-score database and would be the best single
    reputation source here - but it now sits behind a Cloudflare interstitial that a
    plain GET cannot pass (verified 403 "Just a moment..."). Rather than silently drop
    it, hand the caller the exact URL to open in the headless browser. A source we
    could not read must look different from a source that said "nothing"."""
    e164 = (parsed.get("e164") or "").lstrip("+")
    cc = {"AT": "at", "DE": "de", "CH": "ch", "FR": "fr", "GB": "co.uk",
          "US": "us", "IT": "it", "ES": "es"}.get(parsed.get("country"))
    if cc is None:  # there is no tellows.hr etc. (NXDOMAIN); .de would be a non-answer
        return {"source": "tellows", "status": "unsupported",
                "note": "no tellows site for this country"}
    return {"source": f"tellows.{cc}", "status": "blocked",
            "url": f"https://www.tellows.{cc}/num/%2B{e164}" if e164 else None,
            "note": "Cloudflare-gated: open with `browse goto <url>` to read the score"}


def phone_dorks(parsed):
    """The number as a human actually typed it wherever it leaked - a classified ad, a
    company imprint, a group-chat export, a dumped CRM. Search engines index the
    FORMAT, not the E.164, so a single query on '+436641234567' misses the page that
    wrote '0664 123 45 67'. Feed these to `ddgs` / Serper / `reach`."""
    e164 = parsed.get("e164") or ""
    bare = e164.lstrip("+")
    nat = parsed.get("national") or ""
    nat_bare = re.sub(r"\D", "", nat)
    intl = parsed.get("international") or ""
    variants = {v for v in [e164, bare, "00" + bare, nat, nat_bare, intl,
                            intl.replace(" ", "-"), nat.replace(" ", ""),
                            nat.replace(" ", "-"), nat.replace("/", " ")] if v}
    # Group the national number the way people write it, e.g. 0664 123 45 67.
    if len(nat_bare) >= 9:
        variants.add(f"{nat_bare[:4]} {nat_bare[4:7]} {nat_bare[7:]}")
        variants.add(f"{nat_bare[:4]}/{nat_bare[4:]}")
    quoted = sorted(f'"{v}"' for v in variants)
    return {"variants": sorted(variants),
            "queries": [" OR ".join(quoted)] + [
                f'{quoted[0]} (impressum OR kontakt OR contact)',
                f'{quoted[0]} (spam OR betrug OR scam OR "wer ruft")',
                f'site:willhaben.at OR site:kleinanzeigen.de {quoted[0]}',
                f'site:facebook.com OR site:linkedin.com OR site:x.com {quoted[0]}',
                f'filetype:pdf OR filetype:xlsx {quoted[0]}']}


def mod_phone(q, region=None, accounts=False):
    p = _phone_parse(q, region)
    e164 = p.get("e164") or _phone_digits(q)
    out = {"module": "phone", "seed": q, "parsed": p}
    hr = p.get("country") == "HR"
    if p.get("country") == "AT":
        out["allocation"] = _rtr_allocation(e164)
    elif hr:
        out["allocation"] = _hakom(p)
    else:
        out["allocation"] = {"status": "unsupported", "source": None,
                             "note": ("Official block-allocation lookup is wired for AT "
                                      "(RTR) only. Equivalents to check by hand: DE "
                                      "bundesnetzagentur.de, CH bakom.admin.ch, most EU "
                                      "regulators publish one.")}
    out["reputation"] = [_spamcalls(e164), _werruft(p), _tellows(p), _telefonbroj(p)]
    if hr:
        out["reputation"] += [_tkomezvao(p), _cijibroj(p)]
    if accounts:
        out["accounts"] = _accounts(e164)
    out["dorks"] = phone_dorks(p)
    # Deliberately NOT automated. Each of these is either an account Simon owns (the
    # WhatsApp bridge), a ToS question, or a judgement call about how far to push a
    # lookup on a private individual - so the CLI names the pivot and a human decides.
    out["next_pivots"] = [
        "messaging apps: does the number have a WhatsApp/Telegram/Viber/Signal account? "
        "A business account leaks a verified NAME, and the profile photo reverse-images. "
        "Use the whatsapp MCP `lookup_identity` / `get_profile_picture` on your own bridge.",
        "search the dork variants above with `ddgs` / `reach` - a leaked number usually "
        "surfaces in an imprint, a classified ad or a scraped directory, not a people-search",
        "if it is AT/DE and listed, read the Cloudflare-gated score: `browse goto "
        "<tellows url>`; Austrian white pages: `browse goto https://www.herold.at/"
        "telefonbuch/was_wer/<national>/` (JS app, no API)",
        "once a NAME surfaces, pivot back into intel: `intel handles \"First Last\"`, "
        "`intel emailguess \"First Last\" <domain>`, `intel \"<Company>\"`, `intel news`",
        "Truecaller / Viber caller ID: look it up in the app on your phone and paste what "
        "it shows (spam count, carrier label). Reputation only - a NAME there usually "
        "comes from strangers' address books and is not evidence.",
        "report it: AT -> RTR Rufnummernmissbrauch, DE -> Bundesnetzagentur, HR -> "
        "operator + nezeljeni.sms@hakom.hr. Regulators act on volume and can unmask the "
        "subscriber; you cannot.",
    ]
    if hr:
        out["next_pivots"].append(
            "HR telemarketing from a real company stops at the source: put YOUR number on "
            "the 'Ne zovi' register via your own operator (form + OIB, 7 days); after "
            "that the call is illegal and the State Inspectorate enforces it.")
    return out


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
    """GitHub public user API. Surfaces the fields you actually verify identity with (avatar,
    blog, location, twitter, repos, created) - NOT just follower count. `identifying_signal`
    is False for a ghost account (no name/bio/blog/location/twitter/repos): a ghost can't be
    confirmed OR denied from OSINT, so callers must mark it UNVERIFIED, never 'not them'."""
    try:
        d = _json(f"https://api.github.com/users/{urllib.parse.quote(u)}", timeout=8)
        if isinstance(d, dict) and d.get("login"):
            sig = any([d.get("name"), d.get("bio"), d.get("blog"), d.get("location"),
                       d.get("twitter_username"), d.get("public_repos")])
            return {"login": d["login"], "name": d.get("name"), "bio": d.get("bio"),
                    "url": d.get("html_url"), "followers": d.get("followers"),
                    "repos": d.get("public_repos"), "blog": d.get("blog") or None,
                    "location": d.get("location"), "twitter": d.get("twitter_username"),
                    "avatar": d.get("avatar_url"), "created": (d.get("created_at") or "")[:10],
                    "identifying_signal": sig}
    except Exception:  # noqa: BLE001 (404 = no such user)
        pass
    return None


def mod_handles(name):
    cands = permute_usernames(name)
    gh = [r for u in cands if (r := _github_user(u))]
    ghosts = [r["login"] for r in gh if not r["identifying_signal"]]
    return {"module": "handles", "seed": name, "candidates": cands, "github_hits": gh,
            "ghost_accounts": ghosts,
            "hint": ("Verify handles WITH identifying_signal via avatar-match, linked site, or a "
                     "link from a known profile. Ghost accounts " + (str(ghosts) if ghosts else "[]")
                     + " have no name/bio/repos/avatar: OSINT can't confirm or deny them, so mark "
                     "them UNVERIFIED, never 'not them' (that needs contradicting evidence).")}


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
                  + "&output=json&fl=timestamp&limit=1", timeout=30)  # slow on big archives
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
    if os.path.exists(p):
        with open(p) as fh:
            return fh.read().strip()
    return None


def run_actor(actor, run_input, timeout=300):
    tok = _apify_token()
    if not tok:
        return {"error": "no Apify token (~/.config/intel/apify_token or $INTEL_APIFY_TOKEN)"}
    aid = actor.replace("/", "~")
    # Token goes in the Authorization header, never the query string: URLs land in
    # server logs, proxy history and error reports, and a leaked Apify token is
    # billable. Same reason reach moved off ?token= in cafd656.
    url = f"https://api.apify.com/v2/acts/{aid}/run-sync-get-dataset-items?timeout={timeout}"
    req = urllib.request.Request(url, data=json.dumps(run_input).encode(),
                                 headers={**UA, "Content-Type": "application/json",
                                          "Authorization": f"Bearer {tok}"})
    with urllib.request.urlopen(req, timeout=timeout + 15) as r:
        return json.loads(r.read())


def linkedin(url):
    # Input keys come from the actor's own schema
    # (GET /v2/acts/<actor>/builds/default/openapi.json), not from guessing:
    # a wrong key makes the run SUCCEED with an empty dataset rather than error,
    # which is how "profileUrls" silently returned nothing here until 2026-08-05.
    if "/company/" in url:
        return {"module": "linkedin-company",
                "data": run_actor("harvestapi/linkedin-company", {"companies": [url]})}
    return {"module": "linkedin-profile",
            "data": run_actor("harvestapi/linkedin-profile-scraper", {"urls": [url]})}


def linkedin_search(query, limit=10):
    return {"module": "linkedin-search",
            "data": run_actor("harvestapi/linkedin-profile-search",
                              {"searchQuery": query, "maxItems": limit})}


# ---------------- assemble + CLI ----------------

def assemble(query, deep=False, region=None):
    t = detect(query)
    res = {"query": query, "detected": t, "modules": []}
    if t == "username":
        res["modules"].append(mod_username(query))
    elif t == "email":
        res["modules"].append(mod_email(query))
    elif t == "domain":
        res["modules"].append(mod_domain(query))
    elif t == "phone":
        res["modules"].append(mod_phone(query, region=region))
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
            st = m.get("first_snapshot_status")
            if st == "found":
                print(f"  first web-archive snapshot: {m['first_snapshot']}")
            elif st == "none":
                print("  first web-archive snapshot: NEVER ARCHIVED — red flag "
                      "(brand-new or deliberately unarchived domain)")
            elif st == "unknown":
                print("  first web-archive snapshot: unknown (lookup failed; infer nothing)")
            print(f"  subdomains ({len(m['subdomains'])}): {', '.join(m['subdomains'][:20])}")
        elif mod == "phone":
            p = m["parsed"]
            v = {True: "valid", False: "INVALID", None: "validity unknown"}[p.get("valid")]
            print(f"  {p.get('e164') or p['input']}  ({p.get('national') or '?'})  {v}")
            print(f"  country: {p.get('country')} {p.get('region') or ''} · "
                  f"carrier: {p.get('carrier') or '?'} · line: {p.get('line_type') or '?'}"
                  f" · tz: {', '.join(p.get('timezones') or []) or '?'}")
            if p.get("region_assumed"):
                print("  ! no country code given — region ASSUMED AT; re-run with "
                      "--region=XX if that is wrong (every lookup below inherits it)")
            if p.get("note"):
                print("  ! " + p["note"])
            a = m["allocation"]
            if a["status"] == "allocated":
                for b in a["blocks"]:
                    print(f"  block {b['range']:34} -> {b['holder']}")
                sp = a.get("service_provider")
                if sp:
                    print(f"  SERVICE PROVIDER: {sp['name']}")
                    print(f"                    {sp['address']}")
            elif a["status"] == "none":
                print("  allocation: range NOT allocated to any operator — a caller ID in "
                      "an unallocated range is SPOOFED")
            elif a["status"] == "foreign":
                print("  allocation: RTR says this is not an Austrian number")
            elif a["status"] == "manual":
                print(f"  allocation ({a['source']}): {a['note']}")
            elif a["status"] == "unknown":
                print("  allocation: lookup FAILED (no information either way)")
            else:
                print("  allocation: " + (a.get("note") or "not checked"))
            for r in m["reputation"]:
                bits = [f"{k}={r[k]}" for k in ("reports", "verdict", "ratings", "negative",
                                                "spam_votes", "ok_votes", "comments",
                                                "safe", "neutral", "dangerous")
                        if r.get(k) not in (None, "")]
                print(f"  {r['source']:18} {r['status']:12} {' '.join(bits)}")
                if r.get("note"):
                    print(f"    note: {r['note']}")
                for c in r.get("latest") or []:
                    print(f"    > {c}")
            acc = m.get("accounts")
            if acc:
                print(f"  accounts ({acc['modules']}): {acc['status']}")
                if acc.get("note") or acc.get("error"):
                    print(f"    {acc.get('note') or acc.get('error')}")
                for row in acc.get("results") or []:
                    if isinstance(row, dict):
                        print("    " + " ".join(f"{k}={v}" for k, v in row.items()
                                                if v not in (None, "", [], {}))[:200])
            print("  search variants: " + " ".join(m["dorks"]["variants"]))
            print("  next:")
            for n in m["next_pivots"]:
                print(f"    - {n}")
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
    # A national-format number needs a country to mean anything; the default is applied
    # (and flagged) in _phone_parse, never silently here.
    region = next((x.split("=", 1)[1] for x in argv if x.startswith("--region=")), None)
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
    elif a[0] == "phone" and len(a) > 1:
        # Shaped like assemble()'s result, not a bare module, so it reaches _print()
        # instead of the raw-JSON branch (which truncates at 4000 chars).
        q = " ".join(a[1:])
        out = {"query": q, "detected": "phone",
               "modules": [mod_phone(q, region=region, accounts="--accounts" in argv)]}
    else:
        out = assemble(" ".join(a), deep=deep, region=region)
    if as_json:
        print(json.dumps(out, indent=2, ensure_ascii=False))
    elif "module" in out:
        print(json.dumps(out.get("data", out), indent=2, ensure_ascii=False)[:4000])
    else:
        _print(out)


if __name__ == "__main__":
    main()
