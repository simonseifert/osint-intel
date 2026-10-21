#!/usr/bin/env python3
"""Live canary: known-answer checks against the REAL sources intel.py scrapes.

The offline tests pin the parsing logic; this catches the other failure mode: a site
redesign, an endpoint moving, a tool vanishing, or a key running out of credit, all of
which otherwise surface as a silent "not found" in the middle of an investigation.

    python3 tests/canary.py            # print a report, exit 1 if anything broke
    python3 tests/canary.py --notify   # also send the report when something broke

Notification settings are private, in ~/.config/intel/canary.json (never in the repo):
    {"rest_url": "http://127.0.0.1:8083/api/send",
     "rest_env": "~/.local/share/whatsapp-friday/.env",   # file with API_KEY=...
     "recipient": "<number>@s.whatsapp.net"}
"""
import importlib.util
import json
import os
import re
import shutil
import subprocess
import sys
import time
import urllib.request
from typing import Any

_HERE = os.path.dirname(os.path.abspath(__file__))
_spec = importlib.util.spec_from_file_location("intel", os.path.join(_HERE, "..", "intel.py"))
assert _spec and _spec.loader
intel: Any = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(intel)

# Known answers. The HT line is a heavily reported public telemarketing number; the
# second HR number had no reports anywhere when this was written (2026-10-21).
HT = intel._phone_parse("+38598155221")
CLEAN_HR = intel._phone_parse("+385981234987")


def check(name, fn, expect, tries=2):
    """One retry after a pause: rate limits and archive.org timeouts are routine, and
    an alert should mean "this source is broken", not "it blinked once"."""
    t = time.time()
    for attempt in range(tries):
        try:
            got = fn()
            ok = expect(got)
        except Exception as e:  # noqa: BLE001
            got, ok = f"{type(e).__name__}: {str(e)[:120]}", False
        if ok:
            break
        if attempt < tries - 1:
            time.sleep(8)
    return {"name": name, "ok": bool(ok), "got": got if not ok else None,
            "secs": round(time.time() - t, 1)}


def checks():
    yield check("tools on PATH", lambda: [t for t in (
        "maigret", "holehe", "sherlock", "ddgs", "exiftool", "whois", "theHarvester",
        "subfinder", "c2patool", "yt-dlp") if not shutil.which(t)], lambda miss: not miss)
    yield check("spamcalls: HT line listed",
                lambda: intel._spamcalls(HT["e164"]),
                lambda r: r["status"] == "listed" and (r.get("reports") or 0) >= 1)
    yield check("spamcalls: redirect guard",
                lambda: intel._spamcalls(CLEAN_HR["e164"])["status"],
                lambda s: s == "not_listed")
    yield check("telefonbroj: HT line listed", lambda: intel._telefonbroj(HT),
                lambda r: r["status"] == "listed" and r.get("reports", 0) >= 1)
    yield check("telefonbroj: clean number", lambda: intel._telefonbroj(CLEAN_HR)["status"],
                lambda s: s == "not_listed")
    yield check("tko-me-zvao: HT line listed", lambda: intel._tkomezvao(HT),
                lambda r: r["status"] == "listed" and r.get("spam_votes", 0) > 100)
    yield check("ciji-broj: HT line listed", lambda: intel._cijibroj(HT),
                lambda r: r["status"] == "listed" and r.get("ratings", 0) > 50)
    yield check("ciji-broj / tko-me-zvao: clean number",
                lambda: (intel._cijibroj(CLEAN_HR)["status"],
                         intel._tkomezvao(CLEAN_HR)["status"]),
                lambda s: s == ("not_listed", "not_listed"))
    yield check("RTR (AT): 0900 123456 -> ARBOE",
                lambda: json.dumps(intel.mod_phone("0900 123456", region="AT")["allocation"],
                                   ensure_ascii=False),
                lambda s: "ARB" in s)
    yield check("sudreg: OIB -> Hrvatski Telekom",
                lambda: intel.sudreg("81793146560"),
                lambda r: r["status"] == "ok" and r["matches"]
                and "Telekom" in r["matches"][0]["name"])
    yield check("GLEIF: Hrvatski Telekom LEI",
                lambda: intel.mod_company("Hrvatski Telekom d.d.")["entities"],
                lambda e: any(x["lei"] == "097900BFHJ0000029454" for x in e))
    yield check("news (GDELT or RSS fallback)",
                lambda: intel.mod_news("Hrvatski Telekom"),
                lambda r: r["status"] == "ok" and len(r["articles"]) >= 3)
    yield check("domain: example.com whois + wayback",
                lambda: intel.mod_domain("example.com"),
                lambda r: r["first_snapshot_status"] == "found" and r.get("whois"))
    yield check("GitHub API: torvalds",
                lambda: intel.mod_github("torvalds", max_repos=1)["status"],
                lambda s: s == "found")
    yield check("LeakCheck public: test@example.com has breaches",
                lambda: intel._json("https://leakcheck.io/api/public?check=test@example.com",
                                    timeout=15),
                lambda d: isinstance(d, dict) and d.get("success") and d.get("found", 0) > 0)
    yield check("Hudson Rock: keyless endpoint answers",
                lambda: intel._hudsonrock("email", "test@example.com"),
                lambda r: r is not None and r.get("user_services") is not None)
    # A real paid run (~$0.004/week). The doctor line below only reads the monthly
    # cap, and passed on 2026-10-22 while every actor run was refused with 403
    # "Too many outstanding invoices". This also catches the actor's input schema
    # drifting, which shows up as an empty dataset rather than an error.
    yield check("Apify: LinkedIn profile actor actually runs",
                lambda: intel.linkedin("https://www.linkedin.com/in/williamhgates/",
                                       fresh=True)["data"],
                lambda d: isinstance(d, list) and d and d[0].get("lastName") == "Gates")
    yield check("reach doctor: no paid backend out of credit",
                lambda: [re.sub(r"\x1b\[[0-9;]*m", "", ln).strip() for ln in subprocess.run(
                    ["reach", "doctor"], capture_output=True, text=True, timeout=120
                ).stdout.splitlines() if "✗" in ln and any(
                    k in ln for k in ("exa", "apify", "jina (", "web (jina)"))],
                lambda bad: not bad)


def notify(text):
    try:
        with open(os.path.expanduser("~/.config/intel/canary.json")) as fh:
            cfg = json.load(fh)
        env = open(os.path.expanduser(cfg["rest_env"])).read().splitlines()
        key = next(ln.split("=", 1)[1].strip() for ln in env if ln.startswith("API_KEY="))
        req = urllib.request.Request(
            cfg["rest_url"], method="POST",
            data=json.dumps({"recipient": cfg["recipient"], "message": text}).encode(),
            headers={"X-API-Key": key, "Content-Type": "application/json"})
        return bool(json.loads(urllib.request.urlopen(req, timeout=20).read() or b"{}")
                    .get("success"))
    except Exception as e:  # noqa: BLE001
        print(f"notify failed: {e}", file=sys.stderr)
        return False


def main():
    results = list(checks())
    bad = [r for r in results if not r["ok"]]
    for r in results:
        print(f"{'ok  ' if r['ok'] else 'FAIL'} {r['name']:48} {r['secs']:>5}s"
              + (f"  -> {str(r['got'])[:160]}" if not r["ok"] else ""))
    print(f"\n{len(results) - len(bad)}/{len(results)} ok")
    if bad and "--notify" in sys.argv:
        msg = (f"intel canary: {len(bad)}/{len(results)} checks FAILED\n"
               + "\n".join(f"- {r['name']}: {str(r['got'])[:120]}" for r in bad)
               + "\nRun: python3 ~/Code/personal/intel/tests/canary.py")
        notify(msg)
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
