<div align="center">

# 🛰️ osint-intel

**One command. Point it at anything. Get a graded intelligence brief.**

Auto-detects whether your target is an email, a username, a phone number, a domain, a company, or a
person-from-clues, runs the right keyless recon, verifies findings against planted
disinformation, and assembles a printable dossier.

[![License: MIT](https://img.shields.io/badge/License-MIT-2f6f4f.svg)](LICENSE)
[![Python 3.9+](https://img.shields.io/badge/python-3.9%2B-blue.svg)](https://www.python.org)
[![Keyless by default](https://img.shields.io/badge/keys-none%20required-2f6f4f.svg)](#-install)
[![Authorized use only](https://img.shields.io/badge/use-authorized%20only-b23b3b.svg)](#%EF%B8%8F-ethics--legal)

</div>

---

```console
$ intel john.doe@example.com
$ intel @johndoe
$ intel example.com
$ intel "Acme Ltd"
$ intel handles "John Doe"      # -> jdoe, john.doe, doej ... which exist?
```

One entry point. It figures out the target type and dispatches:

| You type | It runs |
|---|---|
| `intel <email>` | Gravatar profile + LeakCheck breach sources + Hudson Rock stealer exposure + holehe |
| `intel <@username>` | maigret across 3000+ sites + Hudson Rock username exposure |
| `intel <+43...>` / `intel phone <n>` | libphonenumber identity (validity, carrier, line type, tz) + official number-block allocation (AT/RTR, incl. premium-range service provider name+address) + crowd spam reports (exact-match guarded; spamcalls + telefonbroj everywhere, tko-me-zvao.com.hr + ciji-broj.hr for HR, with latest comments) + HAKOM links for HR (CAPTCHA-gated, manual) + search-format variants. `--accounts` adds silent Microsoft/Amazon/Zoho existence checks via phonsint |
| `intel <domain.com>` | RDAP whois (with system-`whois` ccTLD fallback) + crt.sh + subfinder subdomains (per-source status) + oldest Wayback snapshot. IDN domains are punycoded |
| `intel <github-url>` | GitHub exposure audit: profile, linked socials, orgs, GPG-key emails, SSH key count, and the author identities in its own commits (real address vs noreply) + maigret on the handle |
| `intel <discord-id>` | snowflake decode: account/message creation time (Discord and X epochs), offline |
| `intel <url>` | the page's preview card + its domain. Profile URLs (x.com, instagram, tiktok, reddit, t.me...) resolve to the handle; `tel:`/`mailto:` unwrap |
| `intel "Acme Ltd"` | GLEIF legal entity + LEI + recent news |
| `intel "Name + clues"` | news pivot + the akinator-style resolver loop |

## 🧭 Pivots (keyless, `--json` for machine output)

```console
intel news "<name/company>"          # global press, country-tagged (GDELT)
intel localnews "<name>" hr           # native local-language press (hr/rs/ba/si/de/fr/it/us/gb)
intel court "<name>"                  # US federal dockets + opinions (CourtListener)
intel emailguess "First Last" x.com   # email-pattern permutations, Gravatar-verified
intel handles "First Last"            # username permutations, GitHub-existence checked
intel phone "+43 664 123 4567"        # phone: line identity + allocation + spam reports
intel phone "0664 1234567" --region=AT # national format needs a country (assumed + flagged)
intel archive <url>                   # Wayback first-seen + latest + live-vs-archive diff (tamper)
intel capture <url>                   # evidence: raw page + sha256 + UTC time + Wayback copy, logged
intel sun 45.81,15.98 2026-06-21 334  # shadow bearing -> UTC time bands that day (chronolocation)
intel media <url>                     # the headshot/preview image a page advertises
intel embed <image-url>               # image -> self-contained data: URI (for the brief)
```

## 🛡️ The truth factor

Public information can be **planted**. Fake profiles, seeded stories, sockpuppets, and
30 outlets syndicating one wire story all look like corroboration but are a single source.
osint-intel treats every finding as a *claim to be graded*, not a fact:

- **Independence scoring** — `intel news` counts distinct publishers (not raw articles) and
  flags near-duplicate/syndicated headlines, so circular reporting can't fake a consensus.
- **Tamper detection** — `intel archive` diffs a live page against its last archived copy to
  catch a claim quietly edited into an old source.
- **Grade, never launder** — the intended workflow labels everything
  `FACT` / `INFERENCE` / `UNVERIFIED` / `DISPUTED`. A username match is a lead, not an identity.

> Real-world catch: two different people can share a handle. The verifier is what stops a
> stranger's accounts from being merged into your subject's profile.

## 📄 The brief

`brief_template.html` is a print-ready dossier: headshot, a graded highlights box, an
identity table with a confidence chip per row, media, timeline, sources, and a reliability
section. Fill the `{{...}}` slots, embed a headshot with `intel embed`, and export to PDF
with any headless browser's print-to-PDF.

## 🤖 Use it as a Claude Code skill (optional)

The CLI is the tool; the **skill** is the agent that knows how to drive it well — open-minded
pivoting, the akinator resolver, the verification pass, and writing the brief. It lives in
[`skill/`](skill/).

```bash
mkdir -p ~/.claude/skills/intel
cp skill/SKILL.md skill/brief_template.html ~/.claude/skills/intel/
# make sure `intel` is on PATH (see Install below)
```

Then in Claude Code: `/intel osint <target>` or "build a brief on <X>". Without the skill you
still have the full CLI; with it, Claude runs the whole find → verify → grade → brief loop.

## 🔧 Install

Core is Python 3.9+ **stdlib only**. The finder modules shell out to a few well-known tools:

```bash
pipx install maigret holehe          # username + email finders
# optional: passive subdomains (projectdiscovery/subfinder release binary), exiftool, whois
# optional, for phone: offline carrier/line-type metadata (Google's libphonenumber)
python3 -m venv ~/.local/share/intel/venv && ~/.local/share/intel/venv/bin/pip install phonenumbers
# optional, for `intel phone --accounts` (pinned to the source-reviewed commit)
python3 -m venv ~/.local/share/intel/phonsint-venv && ~/.local/share/intel/phonsint-venv/bin/pip install "git+https://github.com/kaifcodec/phonsint@f1f37480d088"
brew install exiftool whois          # image metadata + ccTLD whois (optional)
# optional pivots: gallery-dl, yt-dlp, theHarvester, phoneinfoga

git clone https://github.com/simonseifert/osint-intel
ln -s "$PWD/osint-intel/intel.py" ~/.local/bin/intel   # put it on PATH
```

**Optional paid tier** (cookieless LinkedIn): set `HARVESTAPI_KEY` ([harvestapi.io](https://harvestapi.io),
$0.004 per profile or company lookup, the price comes back with every response). Apify is the
fallback: set `INTEL_APIFY_TOKEN`, or drop the token in `~/.config/intel/apify_token` (chmod
600); every Apify run carries an Apify-enforced spend cap. Each result names the vendor that
answered and its cost. Everything else is free and keyless.

**Optional content mode**: if you also run a `corpus`-style back-catalogue tool (a CLI that
stores an account's posts and answers `corpus profile <url> --json`), point
`INTEL_CORPUS_CMD` (or `~/.config/intel/corpus_cmd`) at it, e.g.
`ssh mac /path/to/corpus/.venv/bin/corpus`. Then `intel content ...` passes through to it, and
`intel linkedin <url>` returns a stored full profile for $0 before paying for a fresh one
(`--fresh` skips that).

## 🤝 Working together with corpus (optional)

If you run a `corpus`-style back-catalogue CLI (one that answers
`corpus lookup <query> --json` and `corpus profile <url> --json`) and point
`INTEL_CORPUS_CMD` / `~/.config/intel/corpus_cmd` at it, the two cooperate:

- **corpus into intel.** Person, company, username and domain runs ask corpus (read-only,
  free, ~10s timeout) whether the handle, domain or name is already tracked. Matches appear
  as a "Content (tracked in corpus)" section in the brief and under `content` in `--json`:
  followers, cadence, formats, top posts, outliers. Profiles intel found that corpus does
  not track are listed with the exact `intel content add <url> --relationship ...` command.
  Nothing is ever tracked automatically, since tracking costs money. If corpus is missing,
  unreachable or slow, the step is skipped (`--verbose` prints one line saying why) and the
  run carries on. `--no-corpus` turns it off.
- **Privacy.** Accounts the corpus marks `"private": true` (your own and your clients')
  are carried as aggregate numbers only. intel never requests private detail and rebuilds
  such entries from an allow-list, so no post text reaches a brief that a cloud model may
  read. Anything not clearly public is treated as private.
- **intel into corpus.** `intel socials <target> --json` prints
  `[{"platform", "handle", "url", "source"}]` from the modules intel already has (handle
  search, GitHub profile links, Gravatar), with no extra or paid lookups. A corpus can use it
  to suggest other profiles of an entity.

## ⚖️ Ethics & legal

> [!WARNING]
> **Authorized use only.** Use this on **yourself, consenting subjects, targets you are
> explicitly authorized to assess, or public companies/brands.** Do not stalk, harass, dox,
> or surveil private individuals. Breach and register lookups are legal but sensitive, and
> finder hits are leads to verify, never facts. You are responsible for the terms of every
> service it touches and the laws of your jurisdiction (GDPR and equivalents included).
> **No facial-recognition people-search is included, by design** — the line is "where else is
> this *image*" (fine), never "where else is this *person's face*" (surveillance).

## 📜 License

[MIT](LICENSE) © Simon Seifert

## Tests

```bash
python3 -m unittest discover -s tests -v   # offline: detection, OIB, sanitizer, sun, every phone parser (synthetic pages)
python3 tests/canary.py                    # live known-answer checks against the real sources (needs network)
```

The offline suite pins the parsing logic (mutation-checked: removing the spamcalls redirect guard or the
telefonbroj template-card filter fails it). The canary catches the other failure mode, a site redesign or an
exhausted API key, which otherwise shows up as a silent "not found". Run it on a timer; with `--notify` it
messages you only when something broke (settings in `~/.config/intel/canary.json`, outside the repo).
