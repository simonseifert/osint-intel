---
name: intel
description: Unified OSINT and intelligence. Auto-detects the target (email, username/handle, domain, company, or a person described by clues) and runs the right modules, then fetches, ANALYZES (text, images, video), and assembles a visual BRIEF (with optional PDF export). Use for "osint X", "check my/this footprint", "who is this username/email", "look up this company/domain", "find the person who <clues>" (akinator), "analyze this brand's socials", "is this email breached", "dig into <company>", "build a brief/dossier on X". Covers people, businesses, brands, domains, breaches, LinkedIn, local news, photos and video. Self / authorized / brand / consenting subjects only.
---

# intel

One toolkit for person + business + brand OSINT. The `intel` CLI does the keyless
deterministic recon; this skill orchestrates the deeper, reasoning-driven parts:
open-minded investigation, media analysis, and a visual brief.

## Mindset: build the puzzle, do not just run tools

The goal is not a list of hits. It is a **picture of the subject** assembled from
scattered public pieces. Work like an investigator, not a scanner:

- **Every finding is a pivot, not an endpoint.** A handle implies an email pattern; an
  avatar reverse-searches to other profiles; a bio phrase becomes a dork; a follower is a
  connection; a company implies colleagues; a reused username threads across platforms; an
  EXIF/city hint narrows location. Chase the thread.
- **Think in similarities and approximations, not exact match.** Name variants and
  transliterations (Ivan/Ian, Đ/Dj, ć/c), nicknames, handle mutations (jsmith, j.smith,
  smithj, john_smith), old vs new employers, maiden names, adjacent time windows. The
  target rarely uses one clean identifier everywhere.
- **Hypothesize, then verify.** Form a candidate identity, then actively try to *break* it.
  Coincidence is the enemy: shared name != same person. Corroborate on at least two
  independent signals (avatar match + linked handle, bio + location + timeline) before you
  fold a data point into the picture.
- **Connect across sources.** The value is in the join: this email from the breach = the
  username on the forum = the face in the avatar = the person named in the local news = the
  officer on the company register. Keep a running provenance table so the graph is auditable.
- **Stay open, cap the loop.** Explore widely but timebox (roughly 5 to 8 pivots); when a
  branch goes cold, say so and move on. Absence of evidence is not evidence; note gaps
  honestly rather than inventing bridges.

Keep a scratchpad table as you go: `finding | source | confidence | pivots it opens`.

## The CLI (keyless by default; on PATH)

`intel <target> [--json] [--deep]` auto-detects and runs:
- **email** -> Gravatar profile (+ headshot URL) + LeakCheck breach sources + Hudson Rock
  stealer exposure + holehe (which sites it is registered on).
- **@username / handle** -> maigret (3000+ sites, metadata, auto-recursion) + other IDs +
  Hudson Rock username exposure.
- **domain.com** -> RDAP whois + crt.sh subdomains + oldest Wayback snapshot (public age).
- **"Acme Ltd"** (company) -> GLEIF entity + LEI + auto GDELT news.
- **"a person + clues"** -> GDELT news pivot + tells you to run the akinator loop (below).

Keyless pivots (each is a separate subcommand, JSON out):
- `intel news "<name or company>"` - global press mentions, country-tagged (GDELT).
- `intel localnews "<name>" <locale>` - native local-language press GDELT under-indexes.
  Locales: hr rs ba si de fr it us gb (Croatian/Balkan press is the point here).
- `intel court "<name>"` - US federal court dockets + opinions (CourtListener). US-only.
- `intel emailguess "First Last" domain.com` - email-pattern permutations, Gravatar-verified
  (which candidate is a real person's address). Confirm survivors with `intel <email>`.
- `intel handles "First Last"` - username permutations, GitHub-existence checked as a cheap
  anchor. Run `intel <@handle>` (maigret) on the promising ones.
- `intel archive <url>` - Wayback first-seen + latest snapshot + a live-vs-archive text diff
  (catches a stealth-edited source page; banded, and inconclusive on JS-rendered pages).
- `intel media <profile-or-article-url>` - the preview/headshot image + title a page
  advertises (og:/twitter: card), for Claude to view.
- `intel embed <image-url>` - fetch an image as a self-contained `data:` URI (for the brief).

Explicit LinkedIn (paid Apify, cookieless, your login never used, ~$0.004/lookup):
- `intel linkedin <profile-or-company-url>` - full profile or company page.
- `intel linkedin-search "title location keywords"` - people search ($0.10/page, deliberate).
`--deep` also auto-enriches any LinkedIn URL a username scan surfaces.
Tool: `~/Code/personal/intel/intel.py`. Apify token: `~/.config/intel/apify_token`.

## Investigation loop (find -> verify -> pivot -> fetch -> analyze)

1. **Find:** `intel <@handle>` / `intel <email>`. `linkook <handle>` adds a link-graph ->
   pipe to `/graphify`. `theHarvester -d <domain>` aggregates emails/hosts/names for a
   company. `spiderfoot` (self-host) auto-correlates a name/email/domain/username outward
   into an entity graph when you want the widest net for non-obvious links.
2. **Verify (critical):** finder output is noisy; common names collide. Cross-check display
   name / avatar / bio / linked handles, collapse to one identity, assign confidence, only
   proceed on high/medium. Write down *why* each account is (or is not) the target.
3. **Pivot (the open-minded part):** from each confirmed node, spawn the next queries
   (see Mindset). Name -> `intel handles "First Last"` (username variants, GitHub-checked) and
   `intel emailguess "First Last" <domain>` (email variants, Gravatar-checked) to systematize
   the approximations. Reused handle -> `intel <@that-handle>`. Distinctive bio phrase -> dork
   it. Employer -> `intel linkedin-search`. Phone -> `phoneinfoga scan -n <+E164>`. Local
   angle -> `intel localnews`. Legal angle -> `intel court`. Widest net for non-obvious links
   -> `spiderfoot`.
4. **Fetch content** with a tool you already have (route by platform):
   IG -> `reach` (Apify) / `instaloader` / `agent-reach`. X -> `agent-reach`. Reddit ->
   `reach`. YouTube -> `reach` (transcripts). LinkedIn -> `intel linkedin`. TikTok/FB ->
   `agent-reach`. Blog/site -> `firecrawl`/`reach web`. Login-walled -> `browser-use`.
   Cookie fetchers = BURNER accounts only.
5. **Normalize** every pull to one schema (JSONL in scratchpad):
   `{platform, account_url, post_id, timestamp, text, media_type, likes, comments, shares, url}`.
6. **Analyze:** themes, sentiment/tone over time, cadence (posts/week, hour-of-day),
   engagement outliers, voice/hooks, bio-vs-reality, who they interact with. Plus the media
   pass below.
7. **Verify (the truth factor):** run the Verification pass before writing anything. Grade
   every claim, demand independent corroboration, red-team for planted/false info. Only then
   assemble the brief.

## Media: photos + video (collect -> Claude views -> display)

The split: tools **gather**, Claude **analyzes** (multimodal vision + transcript reading),
the brief **displays**.

**Photos / headshot:**
- Fastest headshot: `intel <email>` (Gravatar avatar) or `intel media <profile-url>`
  (og:image). maigret output also lists profile-pic URLs.
- Bulk public photos: `gallery-dl <profile-url>` (300+ sites: X, IG, Reddit, Mastodon,
  TikTok...); `gallery-dl -g <url>` prints media URLs without downloading.
- **Claude views them:** save/download the image, then Read it. Describe what is verifiable
  (appearance only as relevant to identity confirmation, setting, brand cues, recurring
  logos/locations), and use avatar matching to confirm/deny that two accounts are the same
  person. Do not guess protected attributes.
- **Authenticity (part of the truth factor):** `exiftool <image>` for device/geo/timestamp
  and to catch stripped/spoofed metadata; reverse-image (browse -> Yandex/Lens) to see if a
  "headshot" is stock, stolen, or reused across identities. See Verification below.
- **Geolocation (when a photo's location matters):** first `exiftool` for embedded GPS. If
  stripped (usual on social uploads), Claude reasons from visual cues, signage/language,
  license-plate format, architecture, vegetation/climate, and sun position/shadow direction
  (shadow angle + timestamp roughly fixes latitude/orientation), then confirms against map
  imagery. Treat the result as an inference to verify, never a certainty.

**Video:**
- Transcript without downloading video: `yt-dlp --write-auto-subs --skip-download
  --sub-format vtt -o '%(title)s.%(ext)s' <url>`, or `youtube-transcript-api <video-id>`,
  or `reach yt "<query>"` + `reach transcribe <url>`.
- Claude reads the transcript for claims, timeline, named associations, tone; note the 2 or
  3 clips that matter with a one-line takeaway each.

**Display:** put the headshot + notable images into the brief (embed via `intel embed`),
list the key clips with links. Keep captions factual and sourced.

## Verification: the truth factor (assume adversarial input)

The system can be fed lies. Someone can plant a fake profile, seed a false news story, run
sockpuppets, impersonate, exploit an empty search space (data void), or post AI-generated
text/photos. So **nothing collected is a fact until it survives verification.** Treat every
finding as a *claim* with a grade, and run this pass before writing the brief.

1. **Separate source from claim.** Log every claim as `claim | who-said-it | when | where`.
   A claim is only as good as its weakest independent source.
2. **Grade it (Admiralty code).** Source reliability A-F x information credibility 1-6 (e.g.
   "B2"). Anchor HIGH on hard-to-forge records: government/company registers, courts, SEC,
   DNS/RDAP, breach data, primary documents. Anchor LOW on self-published social, fresh
   accounts, and anonymous posts. A claim carried only by low-reliability sources stays
   UNVERIFIED no matter how many times it repeats.
3. **Demand INDEPENDENT corroboration.** The classic trap is circular reporting: 30 outlets
   syndicating one wire story looks like consensus but is one source. `intel news` now returns
   a `corroboration` block (distinct-publisher count + syndication clusters); trust the
   independent-domain count, not the article count, and always trace to the primary source.
   Real corroboration = two sources that could not have copied each other.
4. **Provenance / age as a deception tripwire.** Freshly created domain (Wayback first-seen,
   already in the domain module) or brand-new account pushing a suspiciously clean narrative
   is a red flag. Compare the live page against its archived copy (`intel archive <url>`) to
   catch stealth edits, a claim inserted into an old page yesterday is a tell.
   **Read the age signal's three states literally, never collapse them** (`mod_domain` returns
   `first_snapshot_status`): `found` = age known; `none` = checked and NOTHING was ever
   archived, a real red flag worth weighing; `unknown` = the lookup failed, which carries NO
   information. Write "could not verify age" and infer nothing. Treating `unknown` as `none`
   invents a red flag; treating `none` as `unknown` hides one. Same rule for the other
   three-state checks (`archive`'s "inconclusive", the ghost-account identity check): a tool
   saying "I could not check" is not evidence of absence.
5. **Media authenticity.** Reverse-image the headshot (browse -> Yandex/Lens): is it stock,
   stolen from someone else, or reused across unrelated "identities"? Run `exiftool` on any
   original image for device/geo/timestamp and to spot stripped or spoofed metadata. Watch for
   AI-generation tells. A fake photo collapses a fake identity fast.
6. **Negative / refutation search (do this explicitly).** Actively search for the claim being
   FALSE: `"<name>" scam|fake|impersonator|debunked|hoax`, fact-check sites, the subject's own
   denial. Absence of a debunk is not proof, but a debunk is often decisive.
7. **Stylometry when identity is contested.** If "are these two accounts the same person" is
   the question, compare writing style (idioms, punctuation, errors, vocabulary) across their
   text, not just the handle. Style is harder to fake than a username.
8. **ACH-lite deception pass.** For each key conclusion list competing hypotheses INCLUDING
   "this is a plant / impersonation / a different same-named person." Score each piece of
   evidence by how well it DISCRIMINATES between hypotheses (diagnostic evidence >> merely
   consistent evidence), and pick the hypothesis with the least *inconsistency*, not the most
   corroboration (deception exploits confirmation bias).
9. **Label, never launder.** In the brief every claim is FACT (multi-source / hard anchor),
   INFERENCE (reasoned), UNVERIFIED (single soft source), or DISPUTED (sources conflict). An
   unverified claim is never written as fact. Put unresolved disputes in the Reliability
   section, do not bury them.
10. **Three states for "is this account theirs", and absence is not denial.** A candidate
    account is CONFIRMED-theirs (positive signal: avatar matches their known face, linked from
    a profile you trust, bio/location/handle line up), CONFIRMED-NOT-theirs (**contradicting**
    signal: different face, different city, a repo/era that can't be them), or UNVERIFIED. A
    ghost account (no name, bio, repos, avatar, or links, e.g. a default identicon and zero
    activity) has NO signal either way, so it is UNVERIFIED, never "not them." Marking a ghost
    "not them" is a false negative: "not them" requires evidence that *contradicts*, not merely
    the *absence* of evidence. `intel handles` returns `identifying_signal` per hit and lists
    `ghost_accounts` for exactly this reason. When only the subject or a human with ground
    truth can settle it, say so instead of guessing.

### The evaluator (independent adversarial pass)

Run verification as a **separate step by a different agent**, for the same reason `/codex`
reviews code Claude wrote: the collector is the worst judge of its own findings. Spawn a
**skeptic** agent, hand it the findings + provenance table, and instruct it to *assume an
adversary planted disinformation* and try to break the brief: refute each high-confidence
claim, run the negative searches, check corroboration independence and media authenticity,
and return an Admiralty grade per claim + an overall reliability rating naming the specific
red flags and gaps. Only claims that survive go in as FACT. For high-stakes subjects use
3 skeptics and majority-vote (the adversarial-verify pattern). This is the "true factor":
a dedicated, independent check whose job is to disbelieve.

## The BRIEF deliverable (the output the user wants)

A visual dossier: headshot + a tight highlights box + sections + sources, exportable to PDF.

1. Copy the template: `~/Code/personal/intel/brief_template.html`.
2. Fill the `{{...}}` slots from your scratchpad. Sections: highlights (4 to 7 punchy
   bullets, the things that matter most), Identity & Presence (accounts table with a
   confidence chip each), Media (headshot + notable images/clips), Analysis (what the
   content reveals), Timeline, News & Mentions (from `intel news`/`localnews`/`court`),
   Connections (the joined puzzle pieces), Sources (every tool + the finding it confirmed).
3. Embed the headshot self-contained: `intel embed <headshot-url>` -> paste the `data:` URI
   into `src`. Do the same for any inline image so the file stands alone.
4. Save the filled HTML to the scratchpad and show the user (SendUserFile, or Artifact for
   a shareable page).
5. **Optional PDF export:** `browse goto file://<abs-path.html>` then `browse pdf <out.pdf>`
   (headless-Chrome print gives best fidelity for embedded images/fonts). Fallback:
   `make-pdf` / `pdf` skill. Then SendUserFile the PDF.

Scale the brief to the ask: a quick "who is this handle" gets a 3-line summary, not a full
dossier. Offer the PDF; do not always generate it.

## BUSINESS / brand intel (compose on top of the CLI)

- **Entity + ownership:** `intel "Company"` (GLEIF + auto news), Wikidata (`wbsearchentities`
  + SPARQL for occupation/country/parent), EU VIES (VAT -> name/address), national registers
  (keyless unless noted): Croatia **sudreg-data.gov.hr** (free, register once), France
  `recherche-entreprises.api.gouv.fr`, Norway `data.brreg.no`, Czech `ares.gov.cz`, Poland
  `api-krs.ms.gov.pl`, Switzerland `zefix.ch`, Denmark `cvrapi.dk`, UK Companies House (free
  key). OpenCorporates is keyed now (skip unless you add one).
- **Infra + tech:** `intel <domain>` (RDAP + crt.sh + first Wayback snapshot). Tech stack via
  response headers / `reach`.
- **Financials:** public US -> `edgartools` (SEC EDGAR, keyless: 10-K/10-Q, XBRL, Form 4).
  Live quotes -> Finnhub (free key, 60/min). UK private -> Companies House. Otherwise private
  funding is mostly paywalled (be honest).
- **People at the company:** `intel linkedin-search`, `intel linkedin <company-url>`.
- **History + reputation:** Wayback CDX, HN Algolia (`hn.algolia.com/api`), reviews via
  `firecrawl`. **Investigative/leaks:** OCCRP Aleph (Balkan-strong; metadata keyless),
  DocumentCloud (`api.www.documentcloud.org/.../search`), ICIJ Offshore Leaks (manual pivot).
- **Sanctions/PEP:** OpenSanctions (bulk data CC-BY, or self-host `yente`; hosted API keyed).
Then run the fetch->analyze->brief pipeline on the brand's official socials.

## The AKINATOR resolver (name a person/company from clues)

No tool names a person from fuzzy clues; run a Claude-driven loop (cap ~5 iterations, cache
queries, keep a provenance table):
1. **Extract** hard constraints (role, country, employer, era, awards, named associations,
   numeric facts) vs soft (vibe).
2. **Recall in parallel:** Exa neural search via `reach` (`category:company`/`people`) +
   Wikidata SPARQL (rule candidates in/out on hard facts) + `ddgs`/Serper keyword pass on the
   single most distinctive verbatim clue with `site:` filters.
3. **Enrich** top ~5 candidates (homepage/LinkedIn/Wikipedia via `reach`/`firecrawl`).
4. **Score** each candidate x constraint (hit/miss + confidence + provenance); **prune**
   hard-constraint violators.
5. **Re-query** the single most discriminating unverified attribute; converge when the leader
   clears all hard + N soft and the runner-up is clearly behind, else return top-K with
   confidences and missing evidence.
Companies resolve far better than people; the prune -> re-query step pins a person. If a
handle surfaces, pivot to `intel <@handle>`.

## Search / dorking

Do not scrape Google (ToS + instant block). Use `ddgs` (keyless, honors
`site:`/`filetype:`/`intitle:`) and, if keyed, Serper (2,500 free) for full Google dork
operators. Pull dork templates from the GHDB corpus per task. `reach` wraps Exa/Jina/
Firecrawl; `mcp__grep__searchGitHub` dorks GitHub for leaked emails/handles.

## Reverse image (light, and the red line)

**OK (content search):** to find where else a *photo* appears, drive an engine through the
`browse` headless browser (Yandex Images or Google Lens); upload the subject's public avatar.
This asks "where else is this image", which is a legitimate source-tracing pivot.
**DO NOT** wire dedicated facial-recognition people-search (see Ethics). That asks "where else
is this person's face", which is the surveillance line.

## Breach / exposure (keyless)

`intel <email>` and `intel <@username>` both run Hudson Rock (infostealer-log exposure).
`intel <email>` also runs LeakCheck public (breach source names, not passwords) and holehe.
HIBP Pwned Passwords (`api.pwnedpasswords.com/range/`) is keyless k-anonymity for password
checks. HIBP email/domain breach API is $3.50/mo (optional).

## Tools inventory

Keyless CLIs (installed, on PATH): `intel`, `maigret`, `holehe`, `linkook`, `sherlock`,
`theHarvester` (domain/company email+host aggregation), `gallery-dl` (photo collection),
`yt-dlp` + `youtube_transcript_api` (video/transcript), `exiftool` (image metadata/
authenticity), `phoneinfoga` (phone OSINT: `phoneinfoga scan -n <+E164>`), `ddgs`,
`edgartools`, `whois`/`dig`/`nmap`. Heavy correlation: `spiderfoot` at
`~/Code/tools/spiderfoot` (its own venv: `~/Code/tools/spiderfoot/.venv/bin/python sf.py -s
<target> -q` for CLI, or `... sf.py -l 127.0.0.1:5001` for the web UI) - auto-expands a
name/email/domain/username into an entity graph. Fetchers you already have: `reach`
(Exa/Jina/Firecrawl/search/IG/Reddit/YouTube), `agent-reach` (cookie social), `instaloader`,
`firecrawl`, `crawl4ai`, `browser-use`, `browse` (headless Chrome, has `pdf`). PDF:
`make-pdf`/`pdf` skills. Paid-per-run: Apify actors via `intel linkedin*` (harvestapi
LinkedIn, apidojo X, compass Maps, clockworks TikTok).

## Ethics / scope

Self, consenting, authorized, or public brand/company subjects only. Finders are
passive/public; content fetching with cookies is ToS-gray (burners only, never a primary
account); breach and register lookups are legal but sensitive. For non-public individuals,
surface privacy/GDPR/anti-stalking concerns instead of building a dossier. Absence is not
proof; finder hits are leads to verify, not facts.

**DO-NOT-WIRE (surveillance red line).** Never build or call facial-recognition
people-search: **PimEyes, FaceCheck.ID, Clearview AI, Search4faces, Lenso.ai, Faceagle,
PicTriev, Betaface, Telegram facematch bots**, or a `face_recognition` pipeline pointed at a
scraped face corpus. The principle: general reverse image search ("where else is this
image") is fine; matching a person's face across images they never consented to link is not.
Also skip keyed-now-not-keyless services (OpenCorporates, IntelX, OsintCat APIs) unless a key
is deliberately added.
