<div align="center">

# 🛰️ osint-intel

**One command. Point it at anything. Get a graded intelligence brief.**

Auto-detects whether your target is an email, a username, a domain, a company, or a
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
| `intel <domain.com>` | RDAP whois (with system-`whois` ccTLD fallback) + crt.sh subdomains + oldest Wayback snapshot |
| `intel "Acme Ltd"` | GLEIF legal entity + LEI + recent news |
| `intel "Name + clues"` | news pivot + the akinator-style resolver loop |

## 🧭 Pivots (keyless, `--json` for machine output)

```console
intel news "<name/company>"          # global press, country-tagged (GDELT)
intel localnews "<name>" hr           # native local-language press (hr/rs/ba/si/de/fr/it/us/gb)
intel court "<name>"                  # US federal dockets + opinions (CourtListener)
intel emailguess "First Last" x.com   # email-pattern permutations, Gravatar-verified
intel handles "First Last"            # username permutations, GitHub-existence checked
intel archive <url>                   # Wayback first-seen + latest + live-vs-archive diff (tamper)
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

## 🔧 Install

Core is Python 3.9+ **stdlib only**. The finder modules shell out to a few well-known tools:

```bash
pipx install maigret holehe          # username + email finders
brew install exiftool whois          # image metadata + ccTLD whois (optional)
# optional pivots: gallery-dl, yt-dlp, theHarvester, phoneinfoga

git clone https://github.com/simonseifert/osint-intel
ln -s "$PWD/osint-intel/intel.py" ~/.local/bin/intel   # put it on PATH
```

**Optional paid tier** (cookieless LinkedIn via Apify): set `INTEL_APIFY_TOKEN`, or drop the
token in `~/.config/intel/apify_token` (chmod 600). Everything else is free and keyless.

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
