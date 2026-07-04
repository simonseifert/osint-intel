# osint-intel

One CLI that auto-detects an OSINT target (email, username, domain, company, or a
person described by clues) and runs the right keyless modules, then helps you fetch,
verify, and assemble a graded intelligence brief.

It is a thin, stdlib-first orchestrator over well-known public tools and keyless APIs.
The CLI does deterministic recon; the harder reasoning (verification, media analysis,
brief writing) is meant to be driven by an agent or by you.

> [!WARNING]
> **Authorized use only.** This tool queries public data sources. Use it on **yourself,
> on subjects who have consented, on targets you are explicitly authorized to assess, or
> on public companies/brands.** Do not use it to stalk, harass, dox, or surveil private
> individuals. Breach and register lookups are legal but sensitive; treat results as
> leads to verify, never as facts. You are responsible for complying with the terms of
> every service it touches and with the laws of your jurisdiction (GDPR and equivalents
> included). No facial-recognition people-search is included, by design.

## What it does

```
intel <email>        Gravatar + LeakCheck breach sources + Hudson Rock stealer + holehe
intel <@username>    maigret account finder (3000+ sites) + Hudson Rock username exposure
intel <domain.com>   RDAP whois + crt.sh subdomains + oldest Wayback snapshot
intel "Acme Ltd"     GLEIF entity/LEI + recent news
intel "Name + clues" news pivot + a hint to run the resolver loop
```

Keyless pivots (each a subcommand, `--json` for machine output):

```
intel news "<name/company>"          global press mentions, country-tagged (GDELT)
intel localnews "<name>" <locale>     native local-language press (hr/rs/ba/si/de/fr/it/us/gb)
intel court "<name>"                  US federal dockets + opinions (CourtListener)
intel emailguess "First Last" dom.com email-pattern permutations, Gravatar-verified
intel handles "First Last"            username permutations, GitHub-existence checked
intel archive <url>                   Wayback first-seen + latest + live-vs-archive diff (tamper)
intel media <url>                     the preview/headshot image a page advertises
intel embed <image-url>               fetch an image as a self-contained data: URI
```

Optional paid tier (Apify, cookieless LinkedIn):

```
intel linkedin <profile-or-company-url>       ~$0.004/lookup
intel linkedin-search "title location ..."    people search
```

## The "truth factor"

Public info can be planted. `intel news` reports source **independence** (distinct
publishers, not raw article count) and flags near-duplicate/syndicated headlines, so
circular reporting can't masquerade as corroboration. `intel archive` diffs a live page
against its last archived copy to catch stealth edits. The intended workflow grades every
finding (fact / inference / unverified / disputed) before it reaches a brief.

## Install

Python 3.9+ (stdlib only for the core). The finder modules shell out to these tools:

```
pipx install maigret holehe          # username + email finders
brew install exiftool                 # image metadata (optional, for media authenticity)
# optional: gallery-dl, yt-dlp, theHarvester, phoneinfoga for media/correlation pivots
```

Then put `intel.py` on your PATH (e.g. symlink it to `~/.local/bin/intel`).

For the paid LinkedIn tier, set an Apify token via `INTEL_APIFY_TOKEN` or
`~/.config/intel/apify_token`.

## The brief

`brief_template.html` is a print-ready dossier template (headshot + graded highlights +
identity/media/analysis/timeline/sources + a reliability section). Fill the `{{...}}`
slots, embed a headshot with `intel embed`, and export to PDF with a headless browser's
print-to-PDF.

## License

MIT. See [LICENSE](LICENSE).
