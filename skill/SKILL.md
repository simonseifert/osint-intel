---
name: intel
description: Unified OSINT and intelligence. Auto-detects the target (email, username/handle, phone number, domain, company, or a person described by clues) and runs the right modules, then fetches, ANALYZES (text, images, video), and assembles a visual BRIEF (with optional PDF export). Use for "osint X", "check my/this footprint" / "how exposed am I" (self-audit mode), "who is this GitHub/Discord account", "who is this username/email", "who is behind this phone number / who called me / is this number spam", "look up this company/domain", "find the person who <clues>" (akinator), "analyze this brand's socials", "is this email breached", "dig into <company>", "build a brief/dossier on X". Covers people, businesses, brands, domains, breaches, LinkedIn, local news, photos and video. Self / authorized / brand / consenting subjects only.
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
- **+43... / 0664...** (phone) -> libphonenumber identity (validity, country, carrier,
  line type, timezone) + official number-block allocation (AT/RTR, incl. the premium-range
  service provider's name+address) + crowd spam reports + search-format variants.
- **domain.com** -> RDAP whois + crt.sh subdomains + oldest Wayback snapshot (public age).
- **"Acme Ltd"** (company) -> GLEIF entity + LEI + auto news (legal suffix stripped for
  the press query; GDELT, falling back to Google News RSS when GDELT 429s or is empty).
- **"a person + clues"** -> news pivot + tells you to run the akinator loop (below).
- **github.com/<user>** -> GitHub exposure audit (profile, linked socials, orgs, GPG-key
  emails, SSH key count, author identities in its own commits: real address vs noreply)
  + maigret on the handle.
- **Discord/X numeric ID** (17-20 digits, or `discord.com/users/<id>`) -> snowflake decode:
  creation time, offline. Names no one.
- **any other URL** -> the page's preview card + its domain. Profile URLs (x.com,
  instagram, tiktok, youtube/@, reddit/u, t.me, medium, keybase, gitlab) resolve to the
  handle; `tel:` / `mailto:` unwrap. Empty input or `file:`/`javascript:` -> `invalid`.

**Read every module's status field literally.** `unavailable` (tool not installed),
`failed`/`unknown` (rate-limited, CAPTCHA, timeout) and holehe's `COULD NOT CHECK` carry
NO information; they are never "not found". maigret prints profile hits separately from
`weak` search/root-page hits (no evidence), and a hit means the *handle exists* there,
not that it is the same person. Hudson Rock on a username matches the *string*: common
handles collide, so it is a lead about the handle, never proof about the person.
Every result carries `retrieved_at`; keep it in the provenance table.

Keyless pivots (each is a separate subcommand, JSON out):
- `intel news "<name or company>"` - global press mentions, country-tagged (GDELT).
- `intel localnews "<name>" <locale>` - native local-language press GDELT under-indexes.
  Locales: hr rs ba si de fr it us gb (Croatian/Balkan press is the point here).
- `intel court "<name>"` - US federal court dockets + opinions (CourtListener). US-only.
- `intel emailguess "First Last" domain.com` - email-pattern permutations, Gravatar-verified
  (which candidate is a real person's address). Confirm survivors with `intel <email>`.
- `intel handles "First Last"` - username permutations, GitHub-existence checked as a cheap
  anchor. Run `intel <@handle>` (maigret) on the promising ones.
- `intel phone <number> [--region=XX]` - force phone mode. A national-format number
  ("0664...") has no country in it; the CLI assumes AT and SAYS SO (`region_assumed`),
  because every downstream lookup inherits that guess. Pass `--region` when it is wrong.
- `intel archive <url>` - Wayback first-seen + latest snapshot + a live-vs-archive text diff
  (catches a stealth-edited source page; banded, and inconclusive on JS-rendered pages).
- `intel media <profile-or-article-url>` - the preview/headshot image + title a page
  advertises (og:/twitter: card), for Claude to view.
- `intel embed <image-url>` - fetch an image as a self-contained `data:` URI (for the brief).
- `intel capture <url> [--no-wayback]` - preserve evidence: raw page + response headers +
  sha256 + UTC time under `~/.local/share/intel/evidence/`, plus a Wayback Save-Page-Now
  copy (anonymous tier is slow and often 429s; that is reported, not hidden). Appends to
  `evidence/log.jsonl`. Capture anything the brief will cite, at the moment you find it.
- `intel sun <lat,lon> <YYYY-MM-DD[THH:MM]> [shadow_bearing]` - sun azimuth/elevation and
  shadow direction/length for a place and UTC time; with a measured shadow bearing it
  returns the UTC time bands that day. Offline (NOAA formula, ~0.5 deg).

Explicit LinkedIn (paid Apify, cookieless, your login never used, ~$0.004/lookup):
- `intel linkedin <profile-or-company-url>` - full profile or company page.
- `intel linkedin-search "title location keywords"` - people search ($0.10/page, deliberate).
`--deep` also auto-enriches any LinkedIn URL a username scan surfaces.
Tool: `intel.py`. Apify token: `~/.config/intel/apify_token`.

## Investigation loop (find -> verify -> pivot -> fetch -> analyze)

0. **Scope + proportionality (before any person-subject run).** Write down, in one line
   each: who the subject is to the user (self / consenting / client brand / public figure /
   other), the purpose, and which fields that purpose actually needs. Collect only those
   (data minimisation, the Berkeley Protocol rule). If the subject is a private individual
   with no consent and no legitimate purpose that needs it, stop and say so (see Ethics).
   **Logging:** keep the scratchpad as an append-only log that includes dead ends and
   failed lookups, not just hits; "did you only keep what supported the conclusion?" is the
   first challenge any finding gets. `intel capture <url>` every page the brief will cite.
1. **Find:** `intel <@handle>` / `intel <email>`. `linkook <handle>` adds a link-graph ->
   pipe to `/graphify`. `theHarvester -d <domain>` aggregates emails/hosts/names for a
   company. (`spiderfoot` would auto-correlate an entity graph, but it is dormant and
   not built on this box; see Tools inventory.)
2. **Verify (critical):** finder output is noisy; common names collide. Cross-check display
   name / avatar / bio / linked handles, collapse to one identity, assign confidence, only
   proceed on high/medium. Write down *why* each account is (or is not) the target.
3. **Pivot (the open-minded part):** from each confirmed node, spawn the next queries
   (see Mindset). Name -> `intel handles "First Last"` (username variants, GitHub-checked) and
   `intel emailguess "First Last" <domain>` (email variants, Gravatar-checked) to systematize
   the approximations. Reused handle -> `intel <@that-handle>`. Distinctive bio phrase -> dork
   it. Employer -> `intel linkedin-search`. Phone -> `intel phone <number>` (phoneinfoga is unmaintained; see the phone section). Local
   angle -> `intel localnews`. Legal angle -> `intel court`.
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
- **Geolocation, then chronolocation (where first, then when).** Use only for the
  subject's own/consented media or public-interest verification (is this news photo really
  from where it claims?), never to locate a private person.
  1. `exiftool` for embedded GPS/time. Social uploads strip it; absence is normal, not
     suspicious.
  2. **Anchor on searchable features, not atmosphere:** shop names and signage text,
     distinctive facades, road furniture (bollards, kerb paint, sign shapes), plate format,
     language/script, power poles. One searchable string beats ten "looks Mediterranean".
  3. Narrow region -> candidate spot, then confirm against Street View / map imagery. Use
     Street View's **"See more dates"**: an older capture may lack a newer building.
  4. **When:** measure the camera heading and a shadow's bearing on the map (Google Earth
     ruler along a straight shadow edge), then `intel sun <lat,lon> <date> <bearing>` for the
     UTC time bands. Shadows are least diagnostic near solar noon (bands widen); date
     itself needs other evidence (weather history, foliage, posters, construction state).
  5. Output = coordinates + heading + time band + confidence + **"what would falsify
     this"**. It is an inference, never a certainty.

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
   AI-generation tells. A fake photo collapses a fake identity fast. **C2PA Content
   Credentials** (`c2patool <img>`, not installed by default) give cryptographic provenance
   when present: a valid manifest is strong evidence; a *missing* one is `unknown`, because
   every social platform strips it. And the reverse trap ("liar's dividend"): never call
   authentic media fake without positive evidence of manipulation.
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
11. **Every link has an as-of date; eras need a bridge.** A 2016 breach email and a 2026
    profile only describe the same living identity if something connects them across time
    (the old address in a recent profile, a continuous handle history). People change
    jobs, cities, and handles; recycled usernames and reassigned phone numbers are common.
    Put the date of each finding (`retrieved_at` + the source's own date) in the provenance
    table and flag stale-only chains.
12. **Breach-derived findings are labelled `provenance: breach`.** They are useful leads
    and legal to look up, but tainted for any formal use and often outdated. Never present
    them as current fact, and never include passwords or full leaked records in a brief.

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

## SELF-AUDIT: look me up like a scammer, then fix it

The highest-value use of this toolkit, and the cleanest ethically: the user (or a consenting
person) is the subject. Trigger: "check my footprint", "what can people find about me",
"how exposed am I", "self-audit".

1. **Collect identifiers** the person gives you: emails (all of them, old ones matter
   most), handles, phone, domains, GitHub. Do not go hunting for identifiers they did not
   give; ask instead.
2. **Run every module** on each: `intel <email>` (breach sources, stealer exposure,
   registrations), `intel @handle`, `intel phone`, `intel <domain>` (whois privacy, old
   subdomains), `intel github.com/<user>` (real address in commit metadata is the classic
   finding), `intel handles "First Last"`, `intel localnews "<name>" hr`, plus the format
   dorks for the phone and the name via `ddgs`.
3. **Think like the attacker**, not the scanner: what would a scammer *do* with this? A
   breach with passwords + a reused handle = account takeover risk; phone + employer +
   photo = a convincing vishing pretext (the carrier social-engineering demo pattern:
   spoofed caller ID + urgency + one small piece of real info); an exposed home address
   or a daily-routine pattern in posts = physical risk.
4. **Output an exposure table, ranked:** `item | where | who can see it | severity |
   fix | status`. Severity: credential/stealer exposure > address/routine > phone+employer
   pretext material > old accounts > cosmetic.
5. **Fix actions** (concrete, not advice-shaped):
   - stealer or breach-with-password hits -> rotate those passwords, enable 2FA, check
     the infected machine (Hudson Rock = malware on a device, not just a site breach).
   - dead accounts -> delete via JustDeleteMe (justdeleteme.xyz) direct links.
   - Google results -> "Results about you" (myactivity.google.com/results-about-you)
     removal requests for contact info.
   - EU data holders (B2B enrichers: Apollo, ZoomInfo, RocketReach, Lusha,
     PeopleDataLabs; data brokers) -> GDPR Art. 15 access / Art. 17 erasure requests.
     Draft them (EN or HR) for the user to send; never send on their behalf.
   - GitHub real address in commits -> set a noreply address for future commits.
   - phone -> "Ne zovi" register (HR), unlist from Truecaller-style apps.
6. **Re-run quarterly and diff** against the last table; new exposure is the signal.

## The BRIEF deliverable (the output the user wants)

A visual dossier: headshot + a tight highlights box + sections + sources, exportable to PDF.

1. Copy the template: `brief_template.html`.
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
- **Sanctions/PEP:** OpenSanctions. The hosted API now needs a key (401 without); bulk data
  is keyless at `data.opensanctions.org/datasets/latest/default/` (names.txt ~110 MB: grep
  it locally) or self-host `yente`.
- **Croatia, keyless (all verified live 2026-10-21; company/legal research only):**
  - `e-oglasna.pravosudje.hr` - court notices: bankruptcy, enforcement, auctions.
  - `odluke.sudovi.hr` - anonymised court decisions, searchable by company/topic.
  - `rgfi.fina.hr/JavnaObjava-web/` - FINA annual financial statements, free.
  - `pretrazivac-obrta.gov.hr` - sole-trader (obrt) register, which sudreg does not cover.
  - `sukobinteresa.hr` - officials' asset declarations (public office holders only).
  - `companywall.hr/tvrtka/...`, `fininfo.hr/Poduzece/...` - single company pages (OIB,
    status) return 200; fetch one page on demand, never crawl (robots blocks search and
    owner graphs). `poslovna.hr` is login/trial only.
  - `sudreg-data.gov.hr` is NOT keyless: free registration -> OAuth2 client id/secret.
    Best HR anchor (OIB/MBS, officers, status) once you register.
  - `data.gov.hr` CKAN API (`/ckan/api/3/action/package_search?q=`) - association and
    other public registers.
  - Out of scope: the land registry (`oss.uredjenazemlja.hr`) is public but is a
    person-locating tool; do not use it on individuals.
- **EU beneficial ownership:** UBO registers have been closed to the general public since
  the 2022 CJEU ruling; access now needs a "legitimate interest". A missing UBO record
  means "not visible to us", never "no owner". BRIS (e-justice.europa.eu) is free but
  browser-only.
Then run the fetch->analyze->brief pipeline on the brand's official socials.

## Platform notes (what each one actually exposes)

- **GitHub:** `intel github.com/<user>`. Commit author name/email is self-asserted by
  whoever ran `git commit` (grade C, can be anything), but a consistent real address
  across years of commits is a strong lead. SSH-key count and GPG-key emails are public
  by design. The events API stopped carrying commit lists in 2025; the CLI reads commits
  per repo instead (5 most recently pushed own repos, 30 commits each).
- **Discord:** usernames are unique handles, but there is **no keyless lookup** by
  username or ID. What is public: the ID itself dates the account (`intel <id>`). Profile
  fields need a bot token or a logged-in client; do not use self-bots or user-token
  scrapers (ToS violation, account ban), and do not join servers to observe a subject.
  maigret's Discord "hit" is a root-page false positive. The realistic pivots are the
  handle string itself (`intel @handle`: people reuse it) and anything the person links
  publicly (bio links, a GitHub/Steam/Twitch profile naming the same handle).
- **Handles in general:** a username match proves the string exists, not the person.
  Confirm with a bridge: one profile linking to the other, the same uncommon avatar,
  the same uncommon bio phrase, or a consistent cross-platform timeline.

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
operators. **`reach search` is NOT a dork engine:** it falls through Exa -> SearXNG, and
SearXNG ignores `site:` (checked 2026-10-21), so operator queries go to `ddgs` only. Exa
indexes little non-English local content; for Croatian sources SearXNG/ddgs found what
Exa did not. The Bing Search API was retired 2025-08-11; ignore any guide built on it. Pull dork templates from the GHDB corpus per task. `reach` wraps Exa/Jina/
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
holehe's last release is 2024-09 and on a 2026-10 test 77 of 123 modules returned
could-not-check (rate limit / CAPTCHA). Its `used` hits are decent leads; its `not used`
is weak evidence (a stale module can miss a live account) and `COULD NOT CHECK` is none.
A sound replacement candidate is `sharsil/mailcat` (active), not yet source-reviewed.
HIBP Pwned Passwords (`api.pwnedpasswords.com/range/`) is keyless k-anonymity for password
checks. HIBP email/domain breach API is $3.50/mo (optional).

## PHONE numbers (who is behind this call)

`intel phone <number>` does the deterministic half. The judgement half is below. Run the
ladder in order; stop as soon as the number is explained.

**1. Identity of the line (offline, unfalsifiable).** Validity, country, carrier, line
type, timezone via libphonenumber. Read `line_type` as triage, not trivia:
`voip`/`uan`/`premium_rate` are the cheap, recyclable, spoofable ranges a call centre
actually dials from; a real `mobile` on a real carrier behaves differently. `valid:false`
or an unallocated range means the caller ID was **forged** and there is no subscriber to
find - stop investigating the number and start investigating the campaign.

**2. Official allocation (the hard anchor).** Regulators publish which operator holds each
number block, and this is a government record, not a crowd guess - grade it A1.
- **AT: wired.** RTR, automatic in the CLI. For premium ranges ((0)900/901/810/820/930/
  931/939) it returns the service provider's **name and address outright** - that is the
  single highest-value keyless answer to "who is behind this number", and it exists
  because premium-rate operators must be publicly identifiable.
- **HR: links only.** HAKOM's two useful lookups are image-CAPTCHA gated, so the CLI
  hands over the URLs (never bypass a CAPTCHA): **e-Prenosivost** (the network the number
  is on *now*; 098/099/091/095 are only the *original* ranges and numbers port) and the
  **"Ne zovi" register** (whether telemarketing to a number is illegal). Neither names a
  subscriber. HAKOM has no public porting API.
- **Not wired, check by hand:** DE `bundesnetzagentur.de` (+ its premium-number search at
  `nvmwd.bundesnetzagentur.de`), CH `bakom.admin.ch`. Most EU regulators publish an
  equivalent.
- Ordinary end subscribers are **not** public anywhere in the EU. If the number is a
  normal mobile, the operator name is the end of the official trail. Say so plainly
  rather than implying more is obtainable.

**3. Crowd reputation (soft, and actively booby-trapped).**
- `spamcalls.net` - wired. **The trap:** an unlisted number does not 404, it redirects to
  a numerically *adjacent* listed number whose page returns 200 with a lurid "Scam Call
  (508 reports)" title. PhoneInfoga-era scripts and Phunter's `spam.py` read `status ==
  200` as "spammer" and so invent reports for clean numbers. The CLI compares the final
  URL's digits to the queried digits; keep that guard if you touch it.
- `werruft.info` - wired, DE/AT/CH. Answers 200 for *every* number, so the rating counts
  are the signal and the status code is worthless. `ratings=0` = nobody reported it.
- `tellows.{at,de}` - the best DE/AT score, now Cloudflare-gated. The CLI returns
  `status: blocked` **with the URL** rather than pretending it found nothing; open it with
  `browse goto <url>`. A source you could not read must never look like a source that
  said "clean". There is no tellows.hr (NXDOMAIN); other countries return `unsupported`.
- **Croatia - the strongest crowd layer we have, wired:** `tko-me-zvao.com.hr` (spam/OK
  votes + comments) and `ciji-broj.hr` (ratings, comments, verdict), both HR-only, plus
  `telefonbroj.com` (any country). Both HR sites 404 an unreported number, which is a clean
  `not_listed`. tko-me-zvao silently prefixes 385 to any number, so never call it for a
  foreign one. **Read the `latest` comments, they are the payload:** on 2026-10-13 they
  identified 098 155 221 as Hrvatski Telekom's outbound sales line ("calling back gets an
  HT recording", HT products pitched, callers knowing the person was an HT/Iskon customer),
  which no register would ever say. Exa has none of these indexed; SearXNG found them.
- **Truecaller / Viber caller ID: manual only.** Look the number up in the app and
  pastes the result (spam count, carrier label). Reputation is useful; a *name* there is
  usually someone else's address-book label, so it is never evidence (see below).
- Crowd reports are self-published, unverifiable and gameable: grade them **D-level, and
  count reporters, not reports.** They establish *that people are being called*, never
  *who is calling*.

**4. The format pivot (where the number actually leaks).** Search engines index the
*format a human typed*, not E.164, so one query on `+436641234567` misses the page that
wrote `0664 123 45 67`. The CLI emits every variant plus ready dorks - run them through
`ddgs`/`reach`. A business number almost always surfaces in an imprint, a classified ad
(willhaben/kleinanzeigen), a scraped directory or a PDF, and *that* is what names people.

**5. Messaging apps (the strongest soft pivot, and you may already own an account).** A
number registered on WhatsApp often exposes a profile photo, an "about", and - if it is a
**business** account - a verified business name. Use the whatsapp MCP `lookup_identity`
and `get_profile_picture` on your own bridge, then Claude views the photo and
reverse-images it. Caveat: `lookup_identity` only searches your *own* bridge history,
so `found:false` means "never talked to", NOT "not on WhatsApp". Telegram/Viber/Signal
similarly leak presence (bellingcat/telegram-phone-number-checker works, needs a burner
Telegram account). Treat presence as a lead, absence as nothing (the three-state rule).

**5b. Account existence (opt-in, `intel phone <n> --accounts`).** phonsint, pinned and
source-reviewed, in its own venv, limited to the silent Microsoft / Amazon / Zoho checks
(yes/no per site). Do NOT enable its `instagram` (it solves Instagram's anti-bot
proof-of-work) or `facebook` (account recovery returns the holder's real name and photo)
modules, never pass `--allow-loud`, and never use `nabz0r/modern-phone-checker`: its
Instagram and Telegram checks SEND a reset / login code to the owner. Anything that can
reach the owner's phone tips them off and is harassment.

**6. Austrian white pages:** `browse goto https://www.herold.at/telefonbuch/was_wer/<national>/`
- a JS app with no API, so it needs the headless browser. Only lists *listed* subscribers.

**Do not** route this into paid people-search / Truecaller-style databases. Truecaller's
"name" comes from other people's uploaded address books, i.e. from contacts who never
consented to being the source - it is the phone equivalent of the facial-recognition red
line, and it is also frequently wrong.

**The honest ending.** For an ordinary spoofed spam call the correct, complete answer is
usually: *the caller ID is forged, the range belongs to operator X, N strangers report the
same pattern, and the subscriber is not publicly obtainable.* Deliver that as a result,
not as a failure, and point at the lever that does work: report it to RTR
(Rufnummernmissbrauch) or the Bundesnetzagentur, who can compel the operator to unmask it.

## Tools inventory

**Check before you plan, never trust this list blindly** (tools rot, machines differ):
`for t in maigret holehe sherlock gallery-dl ddgs exiftool whois theHarvester subfinder
yt-dlp; do printf '%-12s %s\n' $t "$(command -v $t || echo MISSING)"; done`

Tool health as of 2026-10: maigret, sherlock, theHarvester, subfinder, WhatsMyName,
blackbird = active. holehe = stale (see Breach). PhoneInfoga = docs-only commits.
SpiderFoot = dormant since 2023-11; treat it as unavailable unless you build it. Dropped: social-analyzer (crash bug), h8mail (dead
2022), Eyes (archived), amass (v5 removed `intel`), crawl4ai (reach covers it),
castrickclues (domain gone).

Fetchers: `reach` (Exa/Jina/Firecrawl/search/IG/Reddit/YouTube; Jina, Firecrawl and the
Apify-backed Reddit route can run out of credits, so check `reach doctor` when results
look empty), `agent-reach` (cookie social), `browser-use`, `browse` (headless Chrome, has
`pdf`). PDF: `make-pdf`/`pdf` skills. Paid-per-run: Apify actors via `intel linkedin*`.

**Manual-only services (use in the browser, never wire):** Epieos free tier (30/mo),
Predicta Search free tier (check that any image search is not face matching first),
IntelTechniques tools (query builders that run in your browser), BRIS. OSINT Industries
(from GBP 19/mo) relies on account-recovery and private-API checks, so manual at most.

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

**Also never wire:**
- Phone-to-name people search: StoryCheck ($29.99/week, licensed broker data), Truecaller
  private-API wrappers.
- Anything that contacts or notifies the subject: password-reset or login-code probes
  (`modern-phone-checker`), phonsint's loud modules, joining a subject's Discord server
  or following them to see more.
- Account-takeover-adjacent tooling: GHunt (needs logged-in Google cookies, private API),
  Discord self-bots or user-token scrapers.
- CAPTCHA or bot-wall solvers, including Scrapling's stealth/Turnstile mode. Its plain
  fetcher is fine.
- Tracking links or IP loggers ("send them a link and get their location"): that is
  active deception of the subject, not OSINT.

**Proportionality is the gate, not the tool list.** The same lookup is fine for
self-audit, a consenting person, a company, or a public figure's public role, and is not
fine for profiling a private individual who has not consented and where no legitimate
purpose needs it (an ex, a stranger from a game, a neighbour). In that case say so plainly
and offer what is legitimate instead: blocking and reporting on the platform, the
platform's own safety tools, or a lawyer/police report if there is a real threat.
