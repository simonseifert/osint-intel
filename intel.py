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
    intel capture <url> [--no-wayback]    evidence: raw page + sha256 + UTC + Wayback copy
    intel sun <lat,lon> <YYYY-MM-DD[THH:MM]> [shadow_bearing]
                                          sun/shadow geometry; bearing -> UTC time bands
    intel <github-url | discord-id>       GitHub exposure audit / snowflake account date

Deep (paid) LinkedIn on demand:
    intel linkedin <profile-or-company-url>     corpus ($0) -> HarvestAPI ($0.004)
                   [--fresh]                    -> Apify; prints vendor and cost
    intel linkedin-search "title location ..."  people search ($0.10/page)

Content back-catalogue (passes through to the separate `corpus` tool):
    intel content add <url> --relationship own|client|competitor|influencer
    intel content sync|comments|analyze|brief|find|search|profile|health ...

Working with corpus (optional): person/company/username/domain runs add a "Content
(tracked in corpus)" section when corpus already tracks the subject (read-only, free;
own/client accounts are aggregate-only). Untracked profiles are listed with the command
to track them; nothing is auto-tracked. `intel socials <target> --json` lists the
profiles the keyless modules found: [{platform, handle, url, source}].
Flags: --json  --no-corpus  --verbose  --deep (paid enrichment of found LinkedIn URLs)  --region=XX (phone).
Keyless by default. HARVESTAPI_KEY from the env or ~/.reach/keys.env; Apify token from
~/.config/intel/apify_token, $INTEL_APIFY_TOKEN or APIFY_TOKEN in ~/.reach/keys.env.
corpus via $INTEL_CORPUS_CMD / ~/.config/intel/corpus_cmd.
Self / authorized / brand / consenting subjects only.
"""
import base64
import contextlib
import difflib
import glob
import hashlib
import io
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
# Labels never start or end with "-": a leading hyphen would reach `whois` as a flag
# (e.g. "-hevil.com" == "-h evil.com", query an attacker's whois server).
DOMAIN_RE = re.compile(r"^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+"
                       r"([a-z]{2,63}|xn--[a-z0-9-]{1,59})$", re.I)
_CO_SUFFIX = re.compile(r"\b(inc|ltd|llc|gmbh|corp|co|ag|plc|sarl|s\.?a\.?|j\.?d\.?o\.?o\.?|"
                        r"d\.?o\.?o\.?|d\.?d\.?|s\.?r\.?l\.?|s\.?p\.?a\.?|kft|nv|bv|ab|oy|as|"
                        r"sp\.? z o\.?o\.?|s\.?r\.?o\.?|ug|kg|obrt)(?!\w)", re.I)


class _HttpOnlyRedirects(urllib.request.HTTPRedirectHandler):
    """urllib follows a 30x to ftp:// by default, so a hostile page could bounce any
    fetch (spam sites, capture, media) off the http(s)-only check. Refuse that."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        if not newurl.lower().startswith(("http://", "https://")):
            raise urllib.error.HTTPError(newurl, code, "blocked non-http(s) redirect",
                                         headers, fp)
        return super().redirect_request(req, fp, code, msg, headers, newurl)


urllib.request.install_opener(urllib.request.build_opener(_HttpOnlyRedirects))


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

# Profile URLs people paste instead of a handle: host -> (path regex for the handle).
# The handle is re-validated by mod_username, so a hostile path cannot reach maigret.
_PROFILE_HOSTS = {
    "github.com": r"^/([A-Za-z0-9-]{1,39})/?$",
    "gitlab.com": r"^/([A-Za-z0-9._-]{1,64})/?$",
    "x.com": r"^/([A-Za-z0-9_]{1,15})/?$", "twitter.com": r"^/([A-Za-z0-9_]{1,15})/?$",
    "instagram.com": r"^/([A-Za-z0-9._]{1,30})/?$",
    "tiktok.com": r"^/@([A-Za-z0-9._]{1,24})/?$",
    "youtube.com": r"^/@([A-Za-z0-9._-]{1,30})/?$",
    "reddit.com": r"^/(?:u|user)/([A-Za-z0-9_-]{3,20})/?$",
    "t.me": r"^/([A-Za-z0-9_]{5,32})/?$",
    "medium.com": r"^/@([A-Za-z0-9._-]{1,30})/?$",
    "keybase.io": r"^/([A-Za-z0-9_]{2,16})/?$",
}
# Discord/X user IDs are "snowflakes": 64-bit ints whose top bits are a millisecond
# timestamp, so the ID alone dates the account. Pure arithmetic, no lookup.
_SNOWFLAKE_EPOCHS = {"discord": 1420070400000, "x/twitter": 1288834974657}


def classify(q):
    """(type, normalized value). Strips the wrappers people paste (tel:, mailto:,
    profile URLs) so each module receives the identifier it expects."""
    q = (q or "").strip().strip("<>").strip()
    if not q.strip("@+.-_ "):
        return "invalid", q
    low = q.lower()
    for pre, t in (("tel:", "phone"), ("callto:", "phone"), ("mailto:", "email")):
        if low.startswith(pre):
            return t, q[len(pre):].split("?")[0].strip()
    if re.match(r"^[a-z][a-z0-9+.-]*:", low) and not low.startswith(("http://", "https://")):
        if not PHONE_RE.match(q):  # "file:", "javascript:" ... never fetch these
            return "invalid", q
    if q.startswith("@"):
        return "username", q
    if EMAIL_RE.match(q):
        return "email", q
    q = re.sub(r"(?i)\s*(?:ext\.?|extension|x|#)\s*\d{1,6}$", "", q) \
        if PHONE_RE.match(re.sub(r"(?i)\s*(?:ext\.?|extension|x|#)\s*\d{1,6}$", "", q)) else q
    digits = re.sub(r"\D", "", q)
    if re.fullmatch(r"\d{17,20}", q):
        return "snowflake", q
    if valid_oib(q) and not q.startswith(("0", "385")):  # 385... = a phone missing its +
        return "company", q  # Croatian OIB (checksum-valid); sudreg resolves it
    if PHONE_RE.match(q) and 7 <= len(digits) <= 15:
        return "phone", q  # E.164 allows 15 digits; <7 is a username, not a number
    url = q if low.startswith(("http://", "https://")) else None
    if not url and "/" in q and " " not in q and DOMAIN_RE.match(q.split("/", 1)[0]):
        url = "https://" + q
    if url:
        u = urllib.parse.urlsplit(url)
        host = (u.hostname or "").lower().removeprefix("www.").removeprefix("m.")
        if host in ("discord.com", "discordapp.com"):
            m = re.match(r"^/users/(\d{17,20})/?$", u.path)
            if m:
                return "snowflake", m.group(1)
        pat = _PROFILE_HOSTS.get(host)
        m = re.match(pat, u.path) if pat else None
        if m:
            return ("github" if host == "github.com" else "username"), m.group(1)
        return "url", url
    if " " not in q:
        try:
            ascii_q = q.encode("idna").decode() if not q.isascii() else q
        except UnicodeError:
            ascii_q = None
        if ascii_q and DOMAIN_RE.match(ascii_q):
            return "domain", ascii_q.lower()
    if " " in q or '"' in q:
        return ("company" if _CO_SUFFIX.search(q) else "person"), q
    return "username", q


def detect(q):
    return classify(q)[0]


# ---------------- keyless modules ----------------

def mod_username(q, top_sites=300, timeout=8):
    username = q.lstrip("@")
    # Must start alphanumeric so it can't be read as a flag by maigret (argument injection),
    # and stay within a sane handle charset.
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}", username):
        return {"module": "username", "seed": username, "accounts": [], "other_ids": [],
                "tags": [], "stealer": None,
                "error": "invalid username: start alphanumeric, <=64 chars of letters/digits/._-"}
    if not shutil.which("maigret"):
        # Never crash and never return an empty list that reads as "no accounts".
        return {"module": "username", "seed": username, "status": "unavailable",
                "accounts": [], "other_ids": [], "tags": [],
                "stealer": _hudsonrock("username", username),
                "error": "maigret not installed (pipx install maigret); account search "
                         "NOT run, so the empty list means nothing"}
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
                    u = info["url_user"]
                    sp = urllib.parse.urlsplit(u)
                    # A search page or a bare site root proves nothing about the handle:
                    # maigret reports them as "found" for sites it cannot really check.
                    weak = (sp.path.strip("/") == "" or bool(re.search(
                        r"(?i)search|filter|[?&](q|query|s)=", sp.path + "?" + sp.query)))
                    accounts.append({"platform": site, "url": u, "weak": weak,
                                     "username": info.get("username", uid), "rank": info.get("rank")})
        seen, uniq = set(), []
        for a in sorted(accounts, key=lambda a: a["rank"] if a["rank"] is not None else 9e9):
            if a["url"] not in seen:
                seen.add(a["url"])
                uniq.append(a)
        return {"module": "username", "seed": username, "status": "checked", "accounts": uniq,
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
        if not d.get("success") and str(d.get("error", "")).lower() == "not found":
            out["breaches"] = {"status": "clean", "count": 0, "sources": [], "fields": []}
        elif not d.get("success"):
            out["breaches"] = {"status": "unknown", "error": str(d.get("error"))[:120]}
        if d.get("success"):
            out["breaches"] = {"status": "found", "count": d.get("found"),
                               "sources": [{"name": s.get("name"), "date": s.get("date")}
                                           for s in d.get("sources", [])[:25]],
                               "fields": d.get("fields", [])}
    except Exception:  # noqa: BLE001
        pass
    out["stealer"] = _hudsonrock("email", q)
    # holehe prints [+] used / [-] not used / [x] rate-limited or errored. Keep all three:
    # it was last released 2024-09 and many modules now hit CAPTCHAs or 429s, so "[x]"
    # (and a stale module's "[-]") is NOT evidence the account does not exist.
    out["holehe"] = {"status": "unavailable", "used": [], "not_used": 0, "unknown": []}
    if shutil.which("holehe"):
        try:
            p = subprocess.run(["holehe", q, "--no-color"], capture_output=True, text=True,
                               timeout=180)
            for line in p.stdout.splitlines():
                m = re.match(r"\[([+\-x])\]\s+(\S+\.\S+)\s*$", line.strip())
                if not m:  # also skips holehe's legend lines ("[+] Email used", ...)
                    continue
                if m.group(1) == "+":
                    out["holehe"]["used"].append(m.group(2))
                elif m.group(1) == "-":
                    out["holehe"]["not_used"] += 1
                else:
                    out["holehe"]["unknown"].append(m.group(2))
            out["holehe"]["status"] = "checked"
        except subprocess.TimeoutExpired:
            out["holehe"]["status"] = "timeout"
        except Exception as e:  # noqa: BLE001
            out["holehe"]["status"], out["holehe"]["error"] = "error", str(e)[:200]
    out["accounts"] = out["holehe"]["used"]
    return out


def _whois_cli(domain):
    """Fallback to the system `whois` for TLDs RDAP does not cover (many ccTLDs, e.g. .hr)."""
    try:
        out = subprocess.run(["whois", "--", domain], capture_output=True, text=True, timeout=20).stdout
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
    # Two passive sources, each with its own status, so "crt.sh timed out" (it often
    # does) never reads as "this domain has no subdomains".
    subs, out["subdomain_sources"] = set(), {}
    try:
        d = _json(f"https://crt.sh/?q={urllib.parse.quote(q)}&output=json", timeout=25)
        for c in d:
            for name in (c.get("name_value", "").split("\n")):
                name = name.strip().lstrip("*.").lower()
                if name.endswith("." + q):  # not endswith(q): evilexample.com != example.com
                    subs.add(name)
        out["subdomain_sources"]["crt.sh"] = "ok"
    except Exception:  # noqa: BLE001
        out["subdomain_sources"]["crt.sh"] = "failed"
    if shutil.which("subfinder"):
        try:
            p = subprocess.run(["subfinder", "-d", q, "-silent", "-timeout", "20",
                                "-max-time", "2"], capture_output=True, text=True, timeout=150)
            subs |= {ln.strip().lower() for ln in p.stdout.splitlines()
                     if ln.strip().lower().endswith("." + q)}
            out["subdomain_sources"]["subfinder"] = "ok"
        except Exception:  # noqa: BLE001
            out["subdomain_sources"]["subfinder"] = "failed"
    else:
        out["subdomain_sources"]["subfinder"] = "unavailable"
    out["subdomain_count"] = len(subs)
    out["subdomains"] = sorted(subs)[:100]
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


# ---------------- Croatian court register (sudreg open data) ----------------

_SUDREG = "https://sudreg-data.gov.hr/api/javni/"


def _keys_env(name):
    """Env var, else ~/.reach/keys.env (where Simon keeps API credentials, chmod 600)."""
    if os.environ.get(name):
        return os.environ[name]
    try:
        with open(os.path.expanduser("~/.reach/keys.env")) as fh:
            for line in fh:
                k, _, v = line.strip().partition("=")
                if k == name:
                    return v.strip().strip("'\"")
    except OSError:
        pass
    return None


def _sudreg_token():
    cid, sec = _keys_env("SUDREG_CLIENT_ID"), _keys_env("SUDREG_CLIENT_SECRET")
    if not (cid and sec):
        return None
    auth = base64.b64encode(f"{cid}:{sec}".encode()).decode()
    req = urllib.request.Request("https://sudreg-data.gov.hr/api/oauth/token",
                                 data=b"grant_type=client_credentials",
                                 headers={**UA, "Authorization": "Basic " + auth,
                                          "Content-Type": "application/x-www-form-urlencoded"})
    with urllib.request.urlopen(req, timeout=15) as r:
        return json.loads(r.read()).get("access_token")


def _sudreg_get(tok, path, **params):
    try:
        d = _json(_SUDREG + path + "?" + urllib.parse.urlencode(params),
                  headers={"Authorization": f"Bearer {tok}"}, timeout=20)
    except urllib.error.HTTPError as e:
        # "no rows" arrives as HTTP 400 with {"error_code": 505}; anything else is real
        try:
            d = json.loads(e.read())
        except ValueError:
            raise e from None
        if not (isinstance(d, dict) and d.get("error_code") == 505):
            raise
        return []
    # "no rows" comes back as an error object (code 505), not an empty list
    return [] if isinstance(d, dict) and d.get("error_code") == 505 else d


def valid_oib(s):
    """Croatian OIB: 11 digits, ISO 7064 MOD 11,10 check digit."""
    if not re.fullmatch(r"\d{11}", s or ""):
        return False
    a = 10
    for c in s[:10]:
        a = (a + int(c)) % 10 or 10
        a = (a * 2) % 11
    return (11 - a) % 10 == int(s[10])


def sudreg(q, limit=5):
    """Croatian companies from the court register: name (exact, then %partial%) or OIB.
    Companies only: obrti are a separate register. The open API carries no people
    (directors/members), only the legal entity."""
    out = {"source": "sudreg", "status": "unavailable", "matches": []}
    try:
        tok = _sudreg_token()
    except Exception as e:  # noqa: BLE001
        out.update(status="failed", error=f"token: {str(e)[:120]}")
        return out
    if not tok:
        out["note"] = ("no SUDREG_CLIENT_ID/SECRET (free registration at sudreg-data.gov.hr)")
        return out
    try:
        if valid_oib(q):
            ids = [("oib", q)]
        else:
            name = q.strip()
            rows = _sudreg_get(tok, "subjekti", tvrtka_naziv=name, limit=limit)
            if not rows:
                core = _CO_SUFFIX.sub("", name).strip(" ,.%")
                rows = _sudreg_get(tok, "subjekti", tvrtka_naziv=f"%{core}%", limit=15)
            ids = [("mbs", str(r["mbs"])) for r in rows[:15] if isinstance(r, dict)]
        for kind, ident in ids:
            d = _sudreg_get(tok, "detalji_subjekta", tip_identifikatora=kind,
                            identifikator=ident, expand_relations="true", omit_nulls="true")
            if not isinstance(d, dict) or not d.get("mbs"):
                continue
            sj = d.get("sjediste") or {}
            cap = (d.get("temeljni_kapitali") or [{}])[-1]
            gfi = sorted({g.get("godina_izvjestaja") for g in d.get("gfi") or []
                          if g.get("godina_izvjestaja")})
            out["matches"].append({
                "name": (d.get("tvrtka") or {}).get("ime"),
                "short": (d.get("skracena_tvrtka") or {}).get("ime"),
                "oib": str(d.get("potpuni_oib") or d.get("oib")),
                "mbs": str(d.get("potpuni_mbs") or d.get("mbs")),
                "form": ((d.get("pravni_oblik") or {}).get("vrsta_pravnog_oblika") or {})
                .get("kratica"),
                "active": d.get("status") == 1,
                "bankruptcy": bool(d.get("stecajna_masa")),
                "liquidation": bool(d.get("likvidacijska_masa")),
                "founded": (d.get("datum_osnivanja") or "")[:10],
                "address": " ".join(str(x) for x in (sj.get("ulica"), sj.get("kucni_broj"),
                                                     sj.get("naziv_naselja")) if x),
                "court": (d.get("sud_nadlezan") or {}).get("naziv"),
                "nkd": d.get("glavna_djelatnost"),
                "capital": f"{cap.get('iznos')} {(cap.get('valuta') or {}).get('naziv', '')}"
                if cap.get("iznos") else None,
                "emails": [e.get("adresa") for e in d.get("email_adrese") or [] if e.get("adresa")],
                "financial_statements_years": gfi[-5:],
                "last_change": (d.get("vrijeme_zadnje_izmjene") or "")[:10],
            })
        # %konzum% also matches "konzumnih jaja": whole-word matches first, then the
        # shortest names (closest to what was asked), then cap.
        words = re.findall(r"\w+", _ascii_fold(_CO_SUFFIX.sub("", q)).lower())

        def _rank(c):
            nm = _ascii_fold(f"{c['name']} {c.get('short') or ''}").lower()
            whole = all(re.search(rf"\b{re.escape(w)}\b", nm) for w in words)
            return (not whole, not c["active"], len((c["short"] or c["name"] or "").split()))
        out["matches"] = sorted(out["matches"], key=_rank)[:limit]
        out["status"] = "ok"
    except Exception as e:  # noqa: BLE001
        out.update(status="failed", error=str(e)[:200])
    return out


def mod_company(q):
    out = {"module": "company", "seed": q, "entities": []}
    try:
        d = _json("https://api.gleif.org/api/v1/lei-records?filter%5Bfulltext%5D="
                  + urllib.parse.quote(q) + "&page%5Bsize%5D=5", timeout=12)
        # GLEIF fulltext is fuzzy ("Konzum d.d." -> an unrelated real-estate firm):
        # keep only records whose legal name contains every core word of the query.
        core = [w for w in re.findall(r"\w+", _ascii_fold(_CO_SUFFIX.sub("", q)).lower())
                if len(w) > 1]
        for r in d.get("data", []):
            ent = r["attributes"]["entity"]
            nm = _ascii_fold(ent["legalName"]["name"]).lower()
            if core and not all(w in nm for w in core):
                continue
            out["entities"].append({"name": ent["legalName"]["name"],
                                    "country": (ent.get("legalAddress") or {}).get("country"),
                                    "status": ent.get("status"), "lei": r["id"]})
    except Exception:  # noqa: BLE001
        pass
    out["sudreg"] = sudreg(q)
    out["hint"] = ("GLEIF only covers LEI-registered (mostly regulated/financial) entities. "
                   "For full company intel use the /intel skill: Exa company search, Wikidata, "
                   "national registers (Croatia sudreg, France recherche-entreprises, GLEIF), "
                   "domain module on their site, and LinkedIn via `intel linkedin`.")
    return out


def news(query, maxrecords=20):
    return _gdelt(query, maxrecords)[0]


def _gdelt(query, maxrecords=20):
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
    if not isinstance(d, dict):
        return [], "failed"  # rate-limited / down: NOT the same as "no coverage"
    return [{"country": a.get("sourcecountry"), "domain": a.get("domain"),
             "title": a.get("title"), "url": a.get("url"), "date": a.get("seendate"),
             "image": a.get("socialimage")}
            for a in d.get("articles", [])], "ok"


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
    # Press writes "Hrvatski Telekom", not "Hrvatski Telekom d.d."; an exact-phrase
    # search WITH the legal suffix finds almost nothing.
    query = _CO_SUFFIX.sub("", query).strip(" ,.") or query
    arts, status = _gdelt(query)
    source = "gdelt"
    if status != "ok" or len(arts) < 3:
        # GDELT 429s bursts from one IP and is thin on some names. Top up from Google
        # News RSS rather than report a famous company as having no press.
        seen = {x.get("url") for x in arts}
        rss = [{"country": None, "domain": a.get("source"), "title": a.get("title"),
                "url": a.get("url"), "date": a.get("date"), "image": None}
               for a in google_news(query, "us", limit=20) if a.get("url") not in seen]
        source = ("gdelt + google-news-rss" if arts else
                  "google-news-rss (gdelt " + ("failed" if status != "ok" else "empty") + ")")
        arts = arts + rss
        status = "ok" if arts or status == "ok" else "failed"
    return {"module": "news", "seed": query, "source": source, "status": status,
            "articles": arts, "corroboration": corroboration(arts)}


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
    # A multi-word name must be an exact phrase: unquoted, "Simon Seifert" returns
    # every Seifert obituary and every Simon in sport. Then the namesake gate: drop
    # items whose title lacks any word of the query.
    phrase = f'"{query}"' if " " in query.strip() and '"' not in query else query
    url = (f"https://news.google.com/rss/search?q={urllib.parse.quote(phrase)}"
           f"&hl={hl}&gl={gl}&ceid={ceid}")
    try:
        root = ET.fromstring(_get(url, timeout=12))
    except Exception:  # noqa: BLE001
        return []
    out = []
    for item in root.iter("item"):
        src = item.find("source")
        title = (item.findtext("title") or "").strip()
        words = re.findall(r"\w{3,}", _ascii_fold(query).lower())
        if words and not all(w in _ascii_fold(title).lower() for w in words):
            continue
        out.append({"title": title, "url": item.findtext("link"),
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
PHONE_RE = re.compile(r"^\+?\(?[0-9][0-9 ().\-/]{5,20}$")

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


# Everything scraped is attacker-controlled text: a spam-report comment or a page
# title can carry ANSI escapes (rewrite the terminal, fake output lines) or bidi
# overrides (make "evil.com" render as something else). Strip C0/C1 controls and
# bidi/zero-width formatting chars from every scraped string, and again from the
# whole human-readable report before it reaches the terminal.
_CTRL = re.compile("[\x00-\x08\x0b-\x1f\x7f-\x9f\u200b-\u200f\u202a-\u202e"
                   "\u2066-\u2069\ufeff]")


def _clean(s):
    return _CTRL.sub("", s) if isinstance(s, str) else s


def _title(body):
    m = re.search(r"<title[^>]*>(.*?)</title>", body, re.S | re.I)
    return _clean(re.sub(r"\s+", " ", html_unescape(m.group(1))).strip()) if m else None


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
            cells = [_clean(html_unescape(re.sub(r"<[^>]+>", "", c))).strip()
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
    return re.sub(r"\s+", " ", _clean(html_unescape(re.sub(r"<[^>]+>", " ", body))))


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
        f"{d[8:10]}.{d[5:7]}.{d[:4]}: {_clean(html_unescape(re.sub(r'<[^>]+>', '', t))).strip()[:160]}"
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
        status, final, body = _fetch_final(url)
    except Exception:  # noqa: BLE001
        return out
    if "match=none" in final:  # unknown number -> search page with "no match"
        out["status"] = "not_listed"
        return out
    if status != 200:
        return out
    # Read the machine-readable layer, not the visible text: the 2026-10 redesign
    # moved the counts into JS, but kept a schema.org AggregateRating and one
    # review card per report, classed review-danger / -neutral / -safe.
    agg = None
    for blob in re.findall(r'<script type="application/ld\+json">(.*?)</script>', body, re.S):
        try:
            d = json.loads(blob)
        except ValueError:
            continue
        if isinstance(d, dict) and d.get("@type") == "AggregateRating":
            agg = d
    cards = re.findall(r'review-card review-(danger|neutral|safe|success|warning)[^"]*">\s*'
                       r'<div class="card-body">\s*<div class="review-text">(.*?)</div>',
                       body, re.S)
    # The page ships a hidden JS template card ("__DESC__") even for unknown numbers;
    # counting it would invent a report for every clean number.
    cards = [(k, t) for k, t in cards if "__" not in t]
    if agg and not str(agg.get("ratingCount", "0")).strip("0"):
        agg = None
    if not agg and not cards:
        t = _page_text(body).lower()
        if "još nema prijava" in t or "još nema recenzija" in t:
            out["status"] = "not_listed"
        return out  # layout changed again: unknown, never a silent "clean"
    kinds = [k for k, _ in cards]
    out["status"] = "listed"
    out["reports"] = int(agg["ratingCount"]) if agg and str(agg.get("ratingCount", "")).isdigit() \
        else len(cards)
    if agg and agg.get("ratingValue"):
        out["verdict"] = f"{agg['ratingValue']}/5"
    out["dangerous"] = kinds.count("danger")
    out["neutral"] = kinds.count("neutral") + kinds.count("warning")
    out["safe"] = kinds.count("safe") + kinds.count("success")
    out["latest"] = [f"[{k}] " + re.sub(r"\s+", " ", _clean(html_unescape(
                         re.sub(r"<[^>]+>", " ", t)))).strip()[:160]
                     for k, t in cards[:5]]
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
    f = re.sub(r"[^a-z]", "", _ascii_fold(first).lower())
    l = re.sub(r"[^a-z]", "", _ascii_fold(last).lower())
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


def _ascii_fold(s):
    """Tomić -> tomic, Đurđević -> djurdjevic, Müller -> muller. Handles and email
    local-parts are ASCII; deleting the accented letter instead ("tomi") makes every
    candidate wrong for most Croatian, Serbian and German surnames."""
    import unicodedata
    s = s.replace("đ", "dj").replace("Đ", "Dj").replace("ß", "ss").replace("ł", "l")
    return "".join(c for c in unicodedata.normalize("NFKD", s)
                   if not unicodedata.combining(c))


def permute_usernames(name):
    parts = re.sub(r"[^a-z ]", "", _ascii_fold(name).lower()).split()
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
    # The same token corpus and reach use, so one key funds every LinkedIn route.
    return _keys_env("APIFY_TOKEN")


def run_actor(actor, run_input, timeout=300, max_charge=0.25):
    tok = _apify_token()
    if not tok:
        return {"error": "no Apify token (~/.config/intel/apify_token, $INTEL_APIFY_TOKEN "
                         "or APIFY_TOKEN in ~/.reach/keys.env)"}
    aid = actor.replace("/", "~")
    # Token goes in the Authorization header, never the query string: URLs land in
    # server logs, proxy history and error reports, and a leaked Apify token is
    # billable. Same reason reach moved off ?token= in cafd656.
    # maxTotalChargeUsd is enforced by Apify itself, so a wrong input or a runaway
    # pay-per-result actor stops at the cap instead of at the monthly limit.
    url = (f"https://api.apify.com/v2/acts/{aid}/run-sync-get-dataset-items"
           f"?timeout={timeout}&maxTotalChargeUsd={max_charge}")
    req = urllib.request.Request(url, data=json.dumps(run_input).encode(),
                                 headers={**UA, "Content-Type": "application/json",
                                          "Authorization": f"Bearer {tok}"})
    try:
        with urllib.request.urlopen(req, timeout=timeout + 15) as r:
            return json.loads(r.read())
    except urllib.error.HTTPError as e:
        # 402 = out of credit/cap, 403 = token or plan: say which, never "no results".
        return {"error": f"apify {e.code} on {actor}: {e.read()[:200].decode(errors='replace')}"}
    except (urllib.error.URLError, TimeoutError, ValueError) as e:
        return {"error": f"apify unreachable for {actor}: {e}"}


# ---------------- corpus (the content back-catalogue) ----------------
#
# corpus is a separate private tool: it downloads an account's whole LinkedIn/IG
# back-catalogue into SQLite and audits it. intel is the front door to it:
#   `intel content <corpus args>`  runs corpus (locally, or over ssh where it lives)
#   `intel linkedin <url>`         reads the profile corpus already paid for, first.
# The command comes from $INTEL_CORPUS_CMD or ~/.config/intel/corpus_cmd, e.g.
# "ssh mac /Users/me/corpus/.venv/bin/corpus", else `corpus` on PATH.

CORPUS_MAX_AGE_DAYS = 90


def _corpus_cmd():
    import shlex
    c = os.environ.get("INTEL_CORPUS_CMD")
    p = os.path.expanduser("~/.config/intel/corpus_cmd")
    if not c and os.path.exists(p):
        with open(p) as fh:
            c = fh.read().strip()
    if c:
        return shlex.split(c)
    w = shutil.which("corpus")
    return [w] if w else None


def _corpus_argv(args):
    """ssh hands its trailing words to a remote SHELL, so each argument is quoted
    there; locally they go straight to exec and must not be."""
    import shlex
    cmd = _corpus_cmd()
    if not cmd:
        return None
    if os.path.basename(cmd[0]) == "ssh":
        return cmd + [shlex.quote(x) for x in args]
    return cmd + list(args)


def corpus_profile(target):
    """found / not_tracked / unavailable. Never raises: a missing corpus only means
    intel pays for the lookup, it must not stop the lookup."""
    argv = _corpus_argv(["profile", target, "--json"])
    if not argv:
        return {"status": "unavailable", "why": "corpus not configured"}
    try:
        r = subprocess.run(argv, capture_output=True, text=True, timeout=45)
        d = json.loads(r.stdout.strip().splitlines()[-1])
    except (OSError, subprocess.TimeoutExpired, ValueError, IndexError) as e:
        return {"status": "unavailable", "why": f"{type(e).__name__}"}
    return d if isinstance(d, dict) and d.get("status") else {"status": "unavailable"}


def corpus_passthrough(args):
    argv = _corpus_argv(args)
    if not argv:
        print("corpus is not configured: set $INTEL_CORPUS_CMD or ~/.config/intel/"
              "corpus_cmd, or put `corpus` on PATH", file=sys.stderr)
        return 2
    if argv[0].endswith("ssh") and "-t" not in argv and sys.stdin.isatty():
        argv.insert(1, "-t")      # corpus colours and prompts want a terminal
    return subprocess.call(argv)


# ---------------- corpus <-> intel: tracked content, and social profiles ----------------
#
# Two directions, both cheap and both optional:
#   corpus_lookup()  asks `corpus lookup ... --json` (read-only, free) whether the
#                    handles / domain / name a run found are already tracked, and adds
#                    a "Content (tracked in corpus)" section to the result.
#   socials()        lists the social profiles the existing modules found, so corpus's
#                    `find --via-intel` can offer them for tracking.
# A missing, unreachable or slow corpus is skipped with one line under --verbose (or
# INTEL_DEBUG=1) and never fails the run. Nothing here ever tracks anything: that
# spends money, so it is only ever printed as a command for the user to run.
#
# PRIVACY. corpus marks own/client accounts "private": true and then returns only
# aggregates. intel never asks for private detail (no --include-private) and,
# belt and braces, rebuilds every private entry from an allow-list of aggregate
# fields, so a corpus that ignored the rule still cannot push client text into a
# brief. intel runs no LLM itself; the brief is read by whatever model drives it, so
# that rebuilt entry is the most any such model ever gets.

CORPUS_LOOKUP_TIMEOUT = 10
MAX_LOOKUP_CANDIDATES = 12
_VERBOSE = False

# The platforms corpus can track (corpus/discover.py PLATFORM_PATTERNS).
CORPUS_PLATFORMS = ("linkedin", "instagram", "youtube", "tiktok", "facebook")
_PUBLIC_RELATIONSHIPS = ("competitor", "influencer")
_PRIVATE_KEEP = ("private", "platform", "handle", "url", "relationship", "followers",
                 "posts_stored", "first_post", "last_post", "last_synced",
                 "cadence_median_days", "engagement_median", "brief_cmd")
_PUBLIC_KEEP = _PRIVATE_KEEP + ("display_name", "top_posts", "recent_outliers",
                                "top_formats", "top_topics", "summary")

_SOCIAL_HOSTS = (
    ("linkedin.com", "linkedin", r"/(?:in|company|school)/([^/?#]+)"),
    ("instagram.com", "instagram", r"/(?!p/|reel/|reels/|stories/|explore/)([^/?#]+)"),
    ("youtube.com", "youtube", r"/@([^/?#]+)"),
    ("tiktok.com", "tiktok", r"/@([^/?#]+)"),
    ("facebook.com", "facebook", r"/(?!profile\.php|groups/|share|watch|reel|events/|pages/|people/)([^/?#]{2,})"),
    ("twitter.com", "x", r"/([^/?#]+)"),
    ("x.com", "x", r"/([^/?#]+)"),
    ("github.com", "github", r"/([^/?#]+)"),
    ("threads.net", "threads", r"/@([^/?#]+)"),
    ("t.me", "telegram", r"/([^/?#]+)"),
    ("mastodon.social", "mastodon", r"/@([^/?#]+)"),
)
_SOCIAL_RESERVED = {"about", "legal", "privacy", "accounts", "explore", "login", "help",
                    "share", "intent", "home", "i", "settings", "company", "p", "reel"}


def _debug(msg):
    if _VERBOSE or os.environ.get("INTEL_DEBUG"):
        print(f"# {msg}", file=sys.stderr)


def social_from_url(url):
    """(platform, handle) for a profile URL on a known social host, else None."""
    try:
        u = urllib.parse.urlsplit(url if "//" in url else "https://" + url)
    except ValueError:
        return None
    host = (u.hostname or "").lower().removeprefix("www.").removeprefix("m.")
    for dom, platform, pat in _SOCIAL_HOSTS:
        if host == dom or host.endswith("." + dom):
            m = re.match(pat, u.path or "")
            if not m:
                return None
            h = urllib.parse.unquote(m.group(1)).rstrip("/")
            if not h or h.lower() in _SOCIAL_RESERVED:
                return None
            return platform, h.lower()
    return None


def corpus_lookup(queries, timeout=CORPUS_LOOKUP_TIMEOUT):
    """{"status": "ok", "matches": [...]} or {"status": "unavailable", "why": ...}.
    Never raises, never prompts, never asks for private detail."""
    queries = [q for q in dict.fromkeys(str(q).strip() for q in queries) if q][:MAX_LOOKUP_CANDIDATES]
    if not queries:
        return {"status": "skipped", "why": "no candidates"}
    if os.environ.get("INTEL_NO_CORPUS"):
        return {"status": "skipped", "why": "INTEL_NO_CORPUS set"}
    # "--" so a candidate that starts with "-" is data, not a corpus flag.
    argv = _corpus_argv(["lookup", "--json", "--"] + queries)
    if not argv:
        return {"status": "unavailable", "why": "corpus not configured"}
    try:
        r = subprocess.run(argv, capture_output=True, text=True, timeout=timeout,
                           stdin=subprocess.DEVNULL)
        d = json.loads(r.stdout.strip().splitlines()[-1])
    except subprocess.TimeoutExpired:
        return {"status": "unavailable", "why": f"timed out after {timeout}s"}
    except (OSError, ValueError, IndexError) as e:
        return {"status": "unavailable", "why": type(e).__name__}
    if not isinstance(d, dict) or not isinstance(d.get("matches"), list):
        return {"status": "unavailable", "why": d.get("error", "unexpected reply")
                if isinstance(d, dict) else "unexpected reply"}
    return {"status": "ok", "matches": d["matches"]}


def _is_private(m):
    """Fail closed: public only when corpus says so AND the relationship agrees."""
    return not (m.get("private") is False and m.get("relationship") in _PUBLIC_RELATIONSHIPS)


def sanitize_corpus_match(m):
    """The entry as intel is willing to carry it. Private ones are rebuilt from
    aggregate fields only; nothing textual survives."""
    if not isinstance(m, dict):
        return None
    priv = _is_private(m)
    out = {k: m[k] for k in (_PRIVATE_KEEP if priv else _PUBLIC_KEEP) if k in m}
    out["private"] = priv
    if priv:
        out["top_posts"] = [{"date": p.get("date"), "engagement": p.get("engagement")}
                            for p in m.get("top_posts") or [] if isinstance(p, dict)]
        out["recent_outliers"] = [{k: p.get(k) for k in ("date", "engagement", "usual", "x")}
                                  for p in m.get("recent_outliers") or [] if isinstance(p, dict)]
        out["top_formats"] = [{k: f.get(k) for k in ("kind", "posts", "median_engagement")}
                              for f in m.get("top_formats") or [] if isinstance(f, dict)]
        out["handling"] = ("private own/client data: aggregate numbers only. Do not send "
                           "it to any cloud LLM or external service")
    for k, v in list(out.items()):
        if isinstance(v, str):
            out[k] = _clean(v)
    return out


def corpus_candidates(kind, value, modules):
    """What to ask corpus about for this run: the handle, domain or name itself, plus
    the profile URLs of socials the modules found (corpus matches URLs exactly)."""
    c = []
    if kind == "username":
        c.append(value.lstrip("@"))
    elif kind == "domain":
        c.append(value)
    elif kind in ("company", "person"):
        c.append(value)
        for m in modules:
            for e in (m or {}).get("entities") or []:
                if isinstance(e, dict) and e.get("name"):
                    c.append(e["name"])
            for h in ((m or {}).get("sudreg") or {}).get("matches") or []:
                if isinstance(h, dict) and h.get("name"):
                    c.append(h["name"])
    for s in collect_socials(modules):
        if s["platform"] in CORPUS_PLATFORMS:
            c.append(s["url"])
    return list(dict.fromkeys(x for x in c if x))[:MAX_LOOKUP_CANDIDATES]


def collect_socials(modules):
    """[{platform, handle, url, source}] from what the existing modules already found.
    No lookups of its own. Weak maigret hits (search pages, site roots) are dropped."""
    out, seen = [], set()

    def add(url, source):
        sh = social_from_url(url or "")
        if not sh or sh in seen:
            return
        seen.add(sh)
        out.append({"platform": sh[0], "handle": sh[1], "url": _clean(url), "source": source})

    for m in modules:
        if not isinstance(m, dict):
            continue
        mod = m.get("module")
        if mod == "username":
            for a in m.get("accounts") or []:
                if isinstance(a, dict) and not a.get("weak"):
                    add(a.get("url"), "maigret")
        elif mod == "github":
            for x in m.get("socials") or []:
                add(x.get("url"), "github profile")
            prof = m.get("profile") or {}
            if prof.get("login"):
                add(f"https://github.com/{prof['login']}", "github profile")
            if prof.get("twitter_username"):
                add(f"https://x.com/{prof['twitter_username']}", "github profile")
            if prof.get("blog"):
                add(prof["blog"], "github profile")
        elif mod == "email":
            for a in (m.get("gravatar") or {}).get("accounts") or []:
                add(a.get("url"), "gravatar")
    return out


def corpus_section(kind, value, modules):
    """The result's `content` block, or None when there is nothing to say."""
    cands = corpus_candidates(kind, value, modules)
    if not cands:
        return None
    got = corpus_lookup(cands)
    if got["status"] != "ok":
        _debug(f"corpus lookup skipped: {got.get('why')}")
        return None
    matches = [x for x in (sanitize_corpus_match(m) for m in got["matches"]) if x]
    tracked = {(m.get("platform"), (m.get("handle") or "").lower()) for m in matches}
    suggestions = []
    for s in collect_socials(modules):
        if s["platform"] in CORPUS_PLATFORMS and (s["platform"], s["handle"]) not in tracked:
            suggestions.append({**s, "command": f"intel content add {s['url']} "
                                f"--relationship <own|client|competitor|influencer>"})
    if not matches and not suggestions:
        return None
    return {"source": "corpus lookup (read-only, free)", "candidates": cands,
            "matches": matches, "suggestions": suggestions,
            "note": "Matches by name or domain are leads, not identity: confirm the account "
                    "is the same subject. Tracking costs money, so nothing is auto-added."}


def socials(target):
    """`intel socials <target> --json`: the social profiles the existing keyless
    modules find for a handle / email / GitHub user / domain / company. A bare list of
    {platform, handle, url, source}. Adds no lookup of its own and never pays."""
    res = assemble(target, corpus=False)
    return collect_socials(res["modules"])


# ---------------- HarvestAPI (direct, paid per request) ----------------
#
# The company behind the harvestapi/* Apify actors also sells the same scrapers as a
# plain REST API. Same payload, $0.004 per profile (main=true) or company lookup
# (measured 2026-10-23), no Apify plan needed, and every response states its own
# price in `cost`. So it goes first and Apify is the fallback.

_HARVESTAPI = "https://api.harvestapi.io"


def harvestapi(path, params, timeout=60):
    """GET one HarvestAPI endpoint. Returns the parsed body, or {"error", "fallback"}:
    fallback=False means the vendor answered and the TARGET is the problem (not found,
    private), so paying a second vendor for the same miss is pointless."""
    key = _keys_env("HARVESTAPI_KEY")
    if not key:
        return {"error": "no HARVESTAPI_KEY (env or ~/.reach/keys.env)", "fallback": True}
    url = f"{_HARVESTAPI}{path}?{urllib.parse.urlencode(params)}"
    req = urllib.request.Request(url, headers={**UA, "X-API-Key": key})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            d = json.loads(r.read())
    except urllib.error.HTTPError as e:
        body = e.read()[:300].decode(errors="replace")
        return {"error": f"harvestapi {e.code}: {body[:160]}", "fallback": e.code not in (404,)}
    except (urllib.error.URLError, TimeoutError, ValueError) as e:
        return {"error": f"harvestapi unreachable: {e}", "fallback": True}
    if not isinstance(d, dict):
        return {"error": "harvestapi: unexpected response", "fallback": True}
    if d.get("error"):
        return {"error": f"harvestapi: {str(d['error'])[:160]}", "fallback": False,
                "cost": d.get("cost")}
    if not d.get("element"):
        return {"error": "harvestapi: empty result", "fallback": False, "cost": d.get("cost")}
    return d


def linkedin(url, fresh=False, max_age_days=CORPUS_MAX_AGE_DAYS):
    """corpus ($0, if it already holds a full fresh profile) -> HarvestAPI direct
    ($0.004) -> Apify actor. Every result says which vendor answered (`vendor`,
    `source`) and what it cost (`cost_usd`; None when the vendor does not say)."""
    module = "linkedin-company" if "/company/" in url else "linkedin-profile"
    today = time.strftime("%Y-%m-%d", time.gmtime())
    # corpus runs the SAME harvestapi scrapers and keeps the raw payload, so a stored
    # profile is byte-compatible with a fresh one. Only a full profile counts (the
    # posts feed leaves a name/headline stub), and only within max_age_days.
    cached = {"status": "skipped (--fresh)"} if fresh else corpus_profile(url)
    if cached.get("status") == "found":
        age = (time.time() - (cached.get("last_scraped_at") or 0)) / 86400
        if cached.get("complete") and age <= max_age_days:
            return {"module": module, "source": "corpus (stored, $0)", "vendor": "corpus",
                    "cost_usd": 0.0,
                    "as_of": time.strftime("%Y-%m-%d", time.gmtime(cached["last_scraped_at"])),
                    "relationship": cached.get("relationship"),
                    "data": [cached["profile"]]}
        cached = {"status": "stale" if cached.get("complete") else "stub only",
                  "age_days": round(age)}
    if module == "linkedin-company":
        hv = harvestapi("/linkedin/company", {"query": url})
    else:
        # main=true: the short profile ("linkedinProfileShort"), the cheap tier.
        hv = harvestapi("/linkedin/profile", {"query": url, "main": "true"})
    if not hv.get("error"):
        cost = hv.get("cost")
        return {"module": module, "vendor": "harvestapi", "cost_usd": cost,
                "source": f"harvestapi (paid, ${cost if cost is not None else '?'})",
                "as_of": today, "corpus": cached.get("status"), "data": [hv["element"]]}
    if not hv.get("fallback"):
        return {"module": module, "vendor": "harvestapi", "cost_usd": hv.get("cost"),
                "source": "harvestapi (target not found, no fallback)", "as_of": today,
                "corpus": cached.get("status"), "data": {"error": hv["error"]}}
    # Input keys come from the actor's own schema
    # (GET /v2/acts/<actor>/builds/default/openapi.json), not from guessing:
    # a wrong key makes the run SUCCEED with an empty dataset rather than error,
    # which is how "profileUrls" silently returned nothing here until 2026-08-05.
    if module == "linkedin-company":
        data = run_actor("harvestapi/linkedin-company", {"companies": [url]}, max_charge=0.05)
    else:
        data = run_actor("harvestapi/linkedin-profile-scraper", {"urls": [url]},
                         max_charge=0.05)
    return {"module": module, "vendor": "apify", "cost_usd": None,
            "source": "apify (paid, ~$0.004, capped at $0.05)",
            "as_of": today, "corpus": cached.get("status"),
            "harvestapi": hv["error"], "data": data}


def linkedin_search(query, limit=10):
    return {"module": "linkedin-search",
            "data": run_actor("harvestapi/linkedin-profile-search",
                              {"searchQuery": query, "maxItems": limit},
                              max_charge=0.5)}


# ---------------- evidence capture ----------------

_EVIDENCE_DIR = os.path.expanduser("~/.local/share/intel/evidence")


def capture(url, wayback=True):
    """Preserve a page as evidence: raw bytes + sha256 + UTC time + response headers,
    and ask the Wayback Machine for an independent third-party copy. Appends one line
    to evidence/log.jsonl (append-only: dead ends get logged too, not just hits)."""
    if not url.lower().startswith(("http://", "https://")):
        return {"module": "capture", "url": url, "error": "http(s) URLs only"}
    ts = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
    host = re.sub(r"[^A-Za-z0-9.-]", "_", urllib.parse.urlsplit(url).hostname or "x")[:60]
    d = os.path.join(_EVIDENCE_DIR, f"{ts}_{host}")
    os.makedirs(d, exist_ok=True)
    out = {"module": "capture", "url": url, "retrieved_at": ts, "dir": d}
    try:
        req = urllib.request.Request(url, headers=dict(_BROWSER_UA))
        with urllib.request.urlopen(req, timeout=30) as r:
            body = r.read(16 * 1024 * 1024)
            out.update(status=r.status, final_url=r.geturl(),
                       content_type=r.headers.get("Content-Type"))
            headers = dict(r.headers.items())
        with open(os.path.join(d, "page.bin"), "wb") as fh:
            fh.write(body)
        with open(os.path.join(d, "headers.json"), "w") as fh:
            json.dump(headers, fh, indent=1)
        out["sha256"] = hashlib.sha256(body).hexdigest()
        out["bytes"] = len(body)
        out["title"] = _title(body.decode("utf-8", "replace"))
    except Exception as e:  # noqa: BLE001
        out["error"] = f"fetch failed: {str(e)[:200]}"
    if wayback:
        # Save Page Now, anonymous tier: slow and rate-limited, but the copy is held by a
        # party with no stake in the investigation, which is what makes it citable.
        try:
            req = urllib.request.Request("https://web.archive.org/save/" + url,
                                         headers=dict(_BROWSER_UA))
            with urllib.request.urlopen(req, timeout=90) as r:
                loc = r.headers.get("Content-Location") or r.geturl()
            out["archive_url"] = (loc if loc.startswith("http")
                                  else "https://web.archive.org" + loc)
        except Exception as e:  # noqa: BLE001
            out["archive_url"] = None
            out["archive_error"] = str(e)[:160]
    with open(os.path.join(_EVIDENCE_DIR, "log.jsonl"), "a") as fh:
        fh.write(json.dumps({k: v for k, v in out.items() if k != "module"}) + "\n")
    return out


# ---------------- sun position (chronolocation) ----------------

def _sun_position(lat, lon, t):
    """Solar azimuth (deg from north, clockwise) and elevation for a UTC epoch t.
    NOAA's simplified algorithm; ~0.5 deg, plenty for shadow work, no dependencies."""
    import math
    jd = t / 86400.0 + 2440587.5
    jc = (jd - 2451545.0) / 36525.0
    l0 = (280.46646 + jc * (36000.76983 + jc * 0.0003032)) % 360
    m = 357.52911 + jc * (35999.05029 - 0.0001537 * jc)
    e = 0.016708634 - jc * (0.000042037 + 0.0000001267 * jc)
    rm = math.radians(m)
    c = (math.sin(rm) * (1.914602 - jc * (0.004817 + 0.000014 * jc))
         + math.sin(2 * rm) * (0.019993 - 0.000101 * jc) + math.sin(3 * rm) * 0.000289)
    lam = l0 + c - 0.00569 - 0.00478 * math.sin(math.radians(125.04 - 1934.136 * jc))
    eps0 = 23 + (26 + (21.448 - jc * (46.815 + jc * (0.00059 - jc * 0.001813))) / 60) / 60
    eps = eps0 + 0.00256 * math.cos(math.radians(125.04 - 1934.136 * jc))
    decl = math.asin(math.sin(math.radians(eps)) * math.sin(math.radians(lam)))
    y = math.tan(math.radians(eps / 2)) ** 2
    l0r = math.radians(l0)
    eqt = 4 * math.degrees(y * math.sin(2 * l0r) - 2 * e * math.sin(rm)
                           + 4 * e * y * math.sin(rm) * math.cos(2 * l0r)
                           - 0.5 * y * y * math.sin(4 * l0r) - 1.25 * e * e * math.sin(2 * rm))
    minutes = (t % 86400) / 60.0
    tst = (minutes + eqt + 4 * lon) % 1440
    ha = math.radians(tst / 4 - 180)
    la = math.radians(lat)
    cz = math.sin(la) * math.sin(decl) + math.cos(la) * math.cos(decl) * math.cos(ha)
    zen = math.acos(max(-1.0, min(1.0, cz)))
    elev = 90 - math.degrees(zen)
    az = math.degrees(math.atan2(math.sin(ha),
                                 math.cos(ha) * math.sin(la) - math.tan(decl) * math.cos(la)))
    return (az + 180) % 360, elev


def mod_sun(latlon, when, shadow_az=None):
    """`intel sun 45.33,14.44 2026-07-01T10:30` -> sun azimuth/elevation and the shadow
    it casts. With a measured shadow bearing: `intel sun 45.33,14.44 2026-07-01 312`
    -> the UTC time bands that day when shadows pointed that way."""
    import math
    try:
        lat, lon = (float(x) for x in latlon.split(","))
        assert -90 <= lat <= 90 and -180 <= lon <= 180
    except Exception:  # noqa: BLE001
        return {"module": "sun", "error": "location must be 'lat,lon' in decimal degrees"}
    import calendar
    try:
        fmt = "%Y-%m-%dT%H:%M" if "T" in when else "%Y-%m-%d"
        t0 = calendar.timegm(time.strptime(when, fmt))
    except ValueError:
        return {"module": "sun", "error": "time must be YYYY-MM-DD or YYYY-MM-DDTHH:MM (UTC)"}
    out = {"module": "sun", "lat": lat, "lon": lon, "when_utc": when}
    if "T" in when:
        az, el = _sun_position(lat, lon, t0)
        out.update(sun_azimuth=round(az, 1), sun_elevation=round(el, 1),
                   shadow_azimuth=round((az + 180) % 360, 1),
                   shadow_length_per_unit_height=round(1 / math.tan(math.radians(el)), 2)
                   if el > 0.5 else None)
    if shadow_az is not None:
        target = float(shadow_az) % 360
        hits = []
        for minute in range(0, 1440):
            az, el = _sun_position(lat, lon, t0 + minute * 60)
            diff = abs(((az + 180) % 360 - target + 180) % 360 - 180)
            if el > 0 and diff <= 3:
                hits.append(minute)
        bands, start = [], None
        for i, mnt in enumerate(hits):
            if start is None:
                start = mnt
            if i == len(hits) - 1 or hits[i + 1] != mnt + 1:
                bands.append(f"{start // 60:02d}:{start % 60:02d}-{mnt // 60:02d}:{mnt % 60:02d}")
                start = None
        out["shadow_azimuth_measured"] = target
        out["utc_time_bands"] = bands
    out["note"] = ("UTC times. +-3 deg bearing tolerance. Measure the shadow bearing on a map "
                   "(Google Earth ruler) against a straight edge; near solar noon shadows "
                   "change slowly, so bands widen there. A band is an inference, not a fact: "
                   "cross-check weather, vegetation and posters.")
    return out


# ---------------- snowflake IDs (Discord / X) ----------------

def mod_snowflake(q):
    """Decode a 64-bit snowflake ID into its creation time. No network: the timestamp is
    in the ID itself, which is why a bare Discord user ID already dates the account."""
    n = int(q)
    now = time.time() * 1000
    out = {"module": "snowflake", "seed": q, "readings": []}
    for platform, epoch in _SNOWFLAKE_EPOCHS.items():
        ms = (n >> 22) + epoch
        plausible = epoch <= ms <= now
        out["readings"].append({
            "platform": platform, "plausible": plausible,
            "created_utc": time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime(ms / 1000))
            if plausible else None})
    out["note"] = ("The ID dates an account/message/server; it names no one. Discord has no "
                   "keyless profile lookup: the username, avatar and banner need a bot "
                   "token (GET /users/{id}) or a client you are logged into. Both readings "
                   "are shown when both are plausible; context decides which platform it is.")
    return out


# ---------------- GitHub (public profile exposure) ----------------

def _gh_headers():
    tok = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")
    if not tok and shutil.which("gh"):
        try:
            tok = subprocess.run(["gh", "auth", "token"], capture_output=True, text=True,
                                 timeout=5).stdout.strip()
        except Exception:  # noqa: BLE001
            tok = None
    h = {"Accept": "application/vnd.github+json"}
    if tok:
        h["Authorization"] = f"Bearer {tok}"
    return h


def mod_github(user, max_repos=5):
    """What a GitHub account publicly exposes: profile fields, linked socials, orgs,
    and the author identities in its own commits (the classic self-audit finding: a
    real email in commit metadata long after the profile email was hidden)."""
    out = {"module": "github", "seed": user, "profile": None, "socials": [], "orgs": [],
           "commit_identities": [], "ssh_keys": 0, "gpg_emails": []}
    if not re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})", user):
        out["error"] = "invalid GitHub username"
        return out
    h = _gh_headers()
    base = "https://api.github.com/users/" + user
    try:
        p = _json(base, headers=h, timeout=12)
    except urllib.error.HTTPError as e:
        out["status"] = "not_found" if e.code == 404 else "unknown"
        out["error"] = f"HTTP {e.code}"
        return out
    except Exception as e:  # noqa: BLE001
        out["status"], out["error"] = "unknown", str(e)[:200]
        return out
    out["status"] = "found"
    out["profile"] = {k: _clean(p.get(k)) for k in (
        "login", "id", "type", "name", "company", "blog", "location", "email", "bio",
        "twitter_username", "hireable", "public_repos", "public_gists", "followers",
        "following", "created_at", "updated_at")}
    out["profile"]["avatar"] = p.get("avatar_url")

    def _try(url, default):
        try:
            return _json(url, headers=h, timeout=12)
        except Exception:  # noqa: BLE001 (one failed facet must not sink the module)
            return default
    out["socials"] = [{"provider": x.get("provider"), "url": _clean(x.get("url"))}
                      for x in _try(base + "/social_accounts", []) if isinstance(x, dict)]
    out["orgs"] = [o.get("login") for o in _try(base + "/orgs", []) if isinstance(o, dict)]
    out["gpg_emails"] = sorted({e.get("email") for k in _try(base + "/gpg_keys", [])
                                if isinstance(k, dict) for e in k.get("emails") or []
                                if e.get("email")})
    try:
        out["ssh_keys"] = len([ln for ln in _get(f"https://github.com/{user}.keys",
                                                 timeout=10).splitlines() if ln.strip()])
    except Exception:  # noqa: BLE001
        out["ssh_keys"] = None
    # Commit identities: own (non-fork) repos, most recently pushed first. The events
    # API stopped carrying commit lists in 2025, so read commits per repo instead.
    repos = _try(base + "/repos?type=owner&sort=pushed&per_page=30", [])
    seen = {}
    for r in [r for r in repos if isinstance(r, dict) and not r.get("fork")][:max_repos]:
        commits = _try(f"https://api.github.com/repos/{r['full_name']}/commits"
                       f"?author={user}&per_page=30", [])
        for c in commits if isinstance(commits, list) else []:
            a = (c.get("commit") or {}).get("author") or {}
            key = (a.get("name"), a.get("email"))
            if a.get("email") and key not in seen:
                seen[key] = {"name": _clean(a.get("name")), "email": _clean(a.get("email")),
                             "noreply": a["email"].endswith("users.noreply.github.com"),
                             "first_seen_in": r["full_name"], "date": a.get("date")}
    out["commit_identities"] = list(seen.values())
    out["note"] = ("Commit names/emails are self-asserted by whoever ran `git commit` and "
                   "can be anything; treat them as leads, grade C. A real address here "
                   "is the self-audit fix: set a noreply email and rewrite nothing public.")
    return out


# ---------------- assemble + CLI ----------------

def assemble(query, deep=False, region=None, corpus=True):
    t, value = classify(query)
    res = {"query": query, "detected": t, "modules": []}
    if value != query.strip():
        res["normalized"] = value
    query = value
    if t == "invalid":
        res["error"] = ("not a usable identifier (empty, or a non-web URI scheme); give an "
                        "email, @handle, phone, domain, profile URL, company or name")
    elif t == "github":
        res["modules"].append(mod_github(query))
        res["modules"].append(mod_username(query))
    elif t == "snowflake":
        res["modules"].append(mod_snowflake(query))
    elif t == "url":
        host = urllib.parse.urlsplit(query).hostname or ""
        res["modules"].append(mod_media(query))
        res["modules"].append(mod_domain(host.lower().removeprefix("www.")))
        res["note"] = ("URL: showing the page's preview card and its domain. For change "
                       "history / stealth edits run `intel archive <url>`.")
    elif t == "username":
        res["modules"].append(mod_username(query))
    elif t == "email":
        res["modules"].append(mod_email(query))
    elif t == "domain":
        res["modules"].append(mod_domain(query))
    elif t == "phone":
        res["modules"].append(mod_phone(query, region=region))
    elif t == "company":
        comp = mod_company(query)
        res["modules"].append(comp)
        # an OIB is not a press term: search news for the name the register resolved
        hits = (comp.get("sudreg") or {}).get("matches") or []
        name = hits[0]["name"] if valid_oib(query) and hits else query
        if not valid_oib(name):
            res["modules"].append(mod_news(name))
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
    if corpus and t in ("username", "domain", "company", "person"):
        content = corpus_section(t, query, res["modules"])
        if content:
            res["content"] = content
    # Evidence hygiene: every result says WHEN it was observed. Pages change and vanish;
    # a finding without a retrieval time cannot be re-checked or defended later.
    res["retrieved_at"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    for m in res["modules"]:
        if isinstance(m, dict):
            m.setdefault("retrieved_at", res["retrieved_at"])
    return res


def _print_content(c):
    print("\n[Content (tracked in corpus)]")
    for m in c["matches"]:
        tag = "  PRIVATE: aggregate only" if m["private"] else ""
        print(f"  {m.get('platform')}:{m.get('handle')}  {m.get('relationship')}{tag}")
        print(f"    {m.get('followers')} followers, {m.get('posts_stored')} posts stored "
              f"({m.get('first_post')} .. {m.get('last_post')}), synced {m.get('last_synced')}; "
              f"posts every {m.get('cadence_median_days')} days, median engagement "
              f"{m.get('engagement_median')}")
        if m.get("top_formats"):
            print("    formats: " + ", ".join(f"{f.get('kind')} x{f.get('posts')}"
                                              for f in m["top_formats"]))
        for p in m.get("top_posts") or []:
            print(f"    top: {p.get('date')} engagement {p.get('engagement')}"
                  + (f"  {p['url']}  {p.get('opening') or ''}" if p.get("url") else ""))
        for o in m.get("recent_outliers") or []:
            print(f"    outlier: {o.get('date')} engagement {o.get('engagement')} "
                  f"({o.get('x')}x usual)"
                  + (f"  {o['url']}  {o.get('opening') or ''}" if o.get("url") else ""))
        if m.get("top_topics"):
            print("    topics: " + ", ".join(t["topic"] for t in m["top_topics"]))
        if m.get("summary"):
            print("    summary: " + m["summary"].strip().splitlines()[0][:200])
        if m.get("handling"):
            print("    ! " + m["handling"])
        print(f"    more: intel content brief {m.get('platform')}:{m.get('handle')}")
    if c["suggestions"]:
        print("  Found by intel but NOT tracked yet (tracking costs money; run it yourself,"
              " pick the relationship):")
        for s_ in c["suggestions"]:
            print(f"    {s_['platform']:10} {s_['url']}   [{s_['source']}]")
            print(f"      {s_['command']}")
    print("  " + c["note"])


def _print(res):
    print(f"\nINTEL: {res['query']}   (detected: {res['detected']})")
    if res.get("normalized"):
        print(f"  normalized to: {res['normalized']}")
    if res.get("error"):
        print("  ! " + res["error"])
    if res.get("note"):
        print("  " + res["note"])
    for m in res["modules"]:
        mod = m["module"]
        print(f"\n[{mod}]")
        if mod == "username":
            if m.get("error"):
                print("  ! " + m["error"])
            elif m.get("status") == "checked" and not m["accounts"]:
                print("  maigret found no accounts (absence is not proof: sites block, "
                      "rename, or hide profiles)")
            if m["other_ids"]:
                print("  also seen as:", ", ".join(m["other_ids"]))
            if m["tags"]:
                print("  interests:", ", ".join(m["tags"]))
            s = m.get("stealer")
            if s and s.get("user_services"):
                print(f"  stealer: {s.get('user_services')} stealer-log credentials use this "
                      f"HANDLE string. Username-only match: common handles collide, so "
                      f"this is a lead about the string, not proof about the person.")
            strong = [a for a in m["accounts"] if not a.get("weak")]
            weak = [a for a in m["accounts"] if a.get("weak")]
            if m["accounts"]:
                print(f"  {len(strong)} profile hits (handle EXISTS there; same person is "
                      f"unverified) + {len(weak)} search/root pages (no evidence):")
            for a in strong:
                print(f"    {a['platform']:20} {a['url']}")
            if weak:
                print("    weak: " + ", ".join(a["platform"] for a in weak))
        elif mod == "email":
            g = m.get("gravatar")
            if g:
                print(f"  gravatar: {g.get('name')} (@{g.get('username')}) {g.get('location') or ''}")
                if g.get("avatar"):
                    print(f"    headshot: {g['avatar']}")
                for a in g.get("accounts", []):
                    print(f"    {a['service']:14} {a['url']}")
            b = m.get("breaches")
            if not b or b.get("status") == "unknown":
                print("  breaches: lookup FAILED (no information either way)")
            elif b.get("status") == "clean":
                print("  breaches: none in LeakCheck's public index (not proof of none anywhere)")
            if b and b.get("status") == "found":
                print(f"  breaches: {b['count']} · fields: {', '.join(b.get('fields', [])[:6])}")
                for s in b["sources"][:10]:
                    print(f"    {s['name']:28} {s.get('date') or ''}")
            s = m.get("stealer")
            if s:
                print(f"  stealer: {s.get('message')} (user svcs {s.get('user_services')}, corp {s.get('corporate_services')})")
            hh = m.get("holehe") or {}
            if hh.get("status") == "checked":
                print(f"  holehe: used on {len(hh['used'])}, not used on {hh['not_used']}, "
                      f"COULD NOT CHECK {len(hh['unknown'])} (rate-limit/CAPTCHA; stale "
                      f"tool, so 'not used' is weak evidence)")
            elif hh:
                print(f"  holehe: {hh.get('status')} (registration check NOT run; "
                      f"no inference)")
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
            src = " ".join(f"{k}:{v}" for k, v in (m.get("subdomain_sources") or {}).items())
            print(f"  subdomains ({m.get('subdomain_count', len(m['subdomains']))}; {src}): "
                  f"{', '.join(m['subdomains'][:20])}")
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
            sr = m.get("sudreg") or {}
            if sr.get("status") == "ok" and not sr["matches"]:
                print("  sudreg (HR court register): no company by that name")
            elif sr.get("status") != "ok":
                print(f"  sudreg: {sr.get('status')} {sr.get('error') or sr.get('note') or ''}")
            for c in sr.get("matches") or []:
                flags = ", ".join(f for f, on in (("ACTIVE", c["active"]),
                                                  ("INACTIVE", not c["active"]),
                                                  ("BANKRUPTCY", c["bankruptcy"]),
                                                  ("LIQUIDATION", c["liquidation"])) if on)
                print(f"  sudreg: {c['name']} ({c.get('short') or '-'})  OIB {c['oib']} "
                      f"MBS {c['mbs']}  [{flags}]")
                print(f"    {c.get('form')} · founded {c['founded']} · {c['address']} · "
                      f"NKD {c.get('nkd')} · capital {c.get('capital')}")
                print(f"    {c.get('court')} · statements filed: "
                      f"{c['financial_statements_years']} · last change {c['last_change']}"
                      + (f" · email {', '.join(c['emails'])}" if c["emails"] else ""))
            print("  " + m["hint"])
        elif mod == "github":
            if m.get("status") != "found":
                print(f"  {m.get('status')}: {m.get('error')}")
                continue
            p = m["profile"]
            print(f"  {p['login']} (id {p['id']}, {p['type']})  created {p['created_at']}  "
                  f"updated {p['updated_at']}")
            for k in ("name", "company", "blog", "location", "email", "bio",
                      "twitter_username"):
                if p.get(k):
                    print(f"  {k:16} {str(p[k])[:120]}")
            print(f"  repos {p['public_repos']} · gists {p['public_gists']} · followers "
                  f"{p['followers']} · following {p['following']} · ssh keys {m['ssh_keys']}")
            for x in m["socials"]:
                print(f"  social: {x['provider']} {x['url']}")
            if m["orgs"]:
                print("  orgs: " + ", ".join(m["orgs"]))
            if m["gpg_emails"]:
                print("  gpg key emails: " + ", ".join(m["gpg_emails"]))
            for c in m["commit_identities"]:
                tag = "noreply" if c["noreply"] else "REAL ADDRESS"
                print(f"  commit identity: {c['name']} <{c['email']}>  [{tag}] "
                      f"in {c['first_seen_in']}")
            print("  " + m["note"])
        elif mod == "snowflake":
            for r in m["readings"]:
                print(f"  as {r['platform']:10} " + (f"created {r['created_utc']} UTC"
                      if r["plausible"] else "implausible (date outside platform life)"))
            print("  " + m["note"])
        elif mod == "media":
            for k in ("title", "image", "url", "error"):
                if m.get(k):
                    print(f"  {k:6} {str(m[k])[:150]}")
        elif mod == "news":
            if m.get("status") == "failed":
                print("  news lookup FAILED (rate-limited/down): no information either "
                      "way, retry later")
                continue
            print(f"  source: {m.get('source', 'gdelt')}")
            c = m.get("corroboration") or {}
            if c:
                print(f"  independence: {c.get('independent_domains')} distinct publishers "
                      f"of {c.get('items')} items · {c.get('caution')}")
            for a in m["articles"][:15]:
                print(f"    [{a.get('country', '?')}] {a.get('domain', '')}: {a.get('title', '')[:60]}")
    if res.get("content"):
        _print_content(res["content"])


def main(argv=None):
    argv = argv if argv is not None else sys.argv[1:]
    as_json = "--json" in argv
    deep = "--deep" in argv
    # A national-format number needs a country to mean anything; the default is applied
    # (and flagged) in _phone_parse, never silently here.
    region = next((x.split("=", 1)[1] for x in argv if x.startswith("--region=")), None)
    global _VERBOSE
    _VERBOSE = "--verbose" in argv
    no_corpus = "--no-corpus" in argv
    a = [x for x in argv if not x.startswith("--")]
    if not a:
        print(__doc__)
        return
    if argv and argv[0] == "content":
        # Raw argv: corpus owns its own flags (--dry-run, --relationship, ...).
        sys.exit(corpus_passthrough(argv[1:]))
    if a[0] == "embed" and len(a) > 1:
        print(embed(a[1]))
        return
    if a[0] == "socials" and len(a) > 1:
        # A bare JSON list, whatever the flags: it is the machine contract corpus reads.
        print(_clean(json.dumps(socials(" ".join(a[1:])), indent=2, ensure_ascii=False)))
        return
    if a[0] == "linkedin" and len(a) > 1:
        out = linkedin(a[1], fresh="--fresh" in argv)
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
    elif a[0] == "capture" and len(a) > 1:
        out = capture(a[1], wayback="--no-wayback" not in argv)
    elif a[0] == "sun" and len(a) > 2:
        out = mod_sun(a[1], a[2], a[3] if len(a) > 3 else None)
    elif a[0] == "archive" and len(a) > 1:
        out = mod_archive(a[1])
    elif a[0] == "phone" and len(a) > 1:
        # Shaped like assemble()'s result, not a bare module, so it reaches _print()
        # instead of the raw-JSON branch (which truncates at 4000 chars).
        q = " ".join(a[1:])
        out = {"query": q, "detected": "phone",
               "modules": [mod_phone(q, region=region, accounts="--accounts" in argv)]}
    else:
        out = assemble(" ".join(a), deep=deep, region=region, corpus=not no_corpus)
    if as_json:
        # json escapes C0 controls itself, but not C1 or bidi overrides
        print(_clean(json.dumps(out, indent=2, ensure_ascii=False)))
    elif "module" in out:
        if out.get("source"):
            print(f"# source: {out['source']}, as of {out.get('as_of')}"
                  + (f", corpus: {out['corpus']}" if out.get("corpus") else "")
                  + (f", harvestapi: {out['harvestapi']}" if out.get("harvestapi") else ""))
        print(_clean(json.dumps(out.get("data", out), indent=2, ensure_ascii=False)[:4000]))
    else:
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            _print(out)
        sys.stdout.write(_clean(buf.getvalue()).replace("\r", ""))


if __name__ == "__main__":
    main()
