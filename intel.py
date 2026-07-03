#!/usr/bin/env python3
"""intel: person/entity OSINT finder.

`intel find <username|email>` returns a normalized list of candidate accounts
across the web, by running the right keyless finder:
  - username -> maigret (3000+ sites, profile metadata, auto-recursion on found IDs)
  - email    -> holehe  (which sites the email is registered on)

The output (JSON with --json) is the hand-off to the fetch->analyze pipeline:
route each account to a content fetcher you already have (reach / agent-reach /
instaloader / firecrawl), normalize, then let Claude analyze. See the `footprint`
skill for the full pipeline.
"""
import glob
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile

_EMAIL = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


def is_email(s):
    return bool(_EMAIL.match(s.strip()))


def find_username(username, top_sites=300, timeout=8):
    tmp = tempfile.mkdtemp(prefix="intel_")
    try:
        subprocess.run(
            ["maigret", username, "--top-sites", str(top_sites), "--timeout", str(timeout),
             "--no-progressbar", "--no-color", "-J", "simple", "-fo", tmp],
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
                if not isinstance(info, dict):
                    continue
                url = info.get("url_user", "")
                if not url:
                    continue
                for kw in (info.get("keywords") or []):
                    tags.add(kw)
                accounts.append({"platform": site, "url": url,
                                 "username": info.get("username", uid),
                                 "source": "maigret", "rank": info.get("rank")})
        seen, uniq = set(), []
        for a in sorted(accounts, key=lambda a: a["rank"] if a["rank"] is not None else 9e9):
            if a["url"] not in seen:
                seen.add(a["url"])
                uniq.append(a)
        return {"seed": username, "type": "username", "accounts": uniq,
                "other_ids": sorted(ids - {username}), "tags": sorted(tags)}
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def find_email(email):
    p = subprocess.run(["holehe", email, "--only-used", "--no-color"],
                       capture_output=True, text=True, timeout=200)
    found = []
    for line in p.stdout.splitlines():
        m = re.match(r"\[\+\]\s+(\S+)", line.strip())
        if m:
            found.append({"platform": m.group(1), "source": "holehe"})
    return {"seed": email, "type": "email", "accounts": found}


def find(seed, top_sites=300, timeout=8):
    return find_email(seed) if is_email(seed) else find_username(seed, top_sites, timeout)


def _arg(argv, flag, default, cast=str):
    return cast(argv[argv.index(flag) + 1]) if flag in argv else default


def main(argv=None):
    argv = argv if argv is not None else sys.argv[1:]
    if not argv or argv[0] in ("-h", "--help") or argv[0] != "find" or len(argv) < 2:
        print("usage: intel find <username|email> [--top-sites N] [--timeout T] [--json]")
        return
    seed = argv[1]
    res = find(seed, _arg(argv, "--top-sites", 300, int), _arg(argv, "--timeout", 8, int))
    if "--json" in argv:
        print(json.dumps(res, indent=2))
        return
    print(f"\nFOOTPRINT: {res['seed']}  ({res['type']})")
    if res.get("other_ids"):
        print("  also seen as:", ", ".join(res["other_ids"]))
    if res.get("tags"):
        print("  interests:", ", ".join(res["tags"]))
    print(f"  {len(res['accounts'])} accounts found:")
    for a in res["accounts"]:
        print(f"    {a['platform']:22} {a.get('url', '')}")


if __name__ == "__main__":
    main()
