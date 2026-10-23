"""Offline regression tests for intel.py. Stdlib only, no network.

Each parser test feeds a small SYNTHETIC page shaped like the real site (not a
scraped copy), so the logic is pinned without committing third-party pages.
Real-site drift is caught by the live canary, `tests/canary.py`.

    python3 -m unittest discover -s tests -v
"""
import importlib.util
import io
import json
import os
import unittest
from typing import Any

_HERE = os.path.dirname(os.path.abspath(__file__))
_spec = importlib.util.spec_from_file_location("intel", os.path.join(_HERE, "..", "intel.py"))
assert _spec and _spec.loader
intel: Any = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(intel)


class FakeFetch:
    """Stand-in for intel._fetch_final: returns (status, final_url, body)."""

    def __init__(self, status, body="", final=None):
        self.status, self.body, self.final = status, body, final

    def __call__(self, url, *a, **k):
        return self.status, self.final or url, self.body


class Patched(unittest.TestCase):
    def setUp(self):
        self._orig = intel._fetch_final

    def tearDown(self):
        intel._fetch_final = self._orig

    def fake(self, *a, **k):
        intel._fetch_final = FakeFetch(*a, **k)


# ---------------------------------------------------------------- detection

class Classify(unittest.TestCase):
    CASES = {
        "john@doe.com": ("email", "john@doe.com"),
        "mailto:a@b.com?subject=x": ("email", "a@b.com"),
        "@simon": ("username", "@simon"),
        "simon_seifert": ("username", "simon_seifert"),
        "example.com": ("domain", "example.com"),
        "žuta-kuća.hr": ("domain", "xn--uta-kua-b5a87h.hr"),
        "+385 98 155 221": ("phone", "+385 98 155 221"),
        "(098) 155 221": ("phone", "(098) 155 221"),
        "+385 98 155 221 ext 5": ("phone", "+385 98 155 221"),
        "tel:+385981552210": ("phone", "+385981552210"),
        "Hrvatski Telekom d.d.": ("company", "Hrvatski Telekom d.d."),
        "Konzum plus d.o.o.": ("company", "Konzum plus d.o.o."),
        "81793146560": ("company", "81793146560"),  # checksum-valid OIB
        "Ivan Horvat": ("person", "Ivan Horvat"),
        "github.com/torvalds": ("github", "torvalds"),
        "https://x.com/jack": ("username", "jack"),
        "https://www.youtube.com/@mkbhd": ("username", "mkbhd"),
        "reddit.com/u/spez": ("username", "spez"),
        "discord.com/users/80351110224678912": ("snowflake", "80351110224678912"),
        "80351110224678912": ("snowflake", "80351110224678912"),
        "https://example.com/path": ("url", "https://example.com/path"),
    }

    def test_cases(self):
        for q, want in self.CASES.items():
            with self.subTest(q=q):
                self.assertEqual(intel.classify(q), want)

    def test_rejects(self):
        for q in ("", "   ", "@", "+", "javascript:alert(1)", "file:///etc/passwd"):
            with self.subTest(q=q):
                self.assertEqual(intel.classify(q)[0], "invalid")

    def test_flag_shaped_input_never_becomes_a_domain(self):
        # a leading hyphen would reach `whois` as a flag (-h = query another server)
        for q in ("-hevil.com", "--help.com"):
            self.assertNotEqual(intel.classify(q)[0], "domain")

    def test_phone_missing_plus_is_not_an_oib(self):
        self.assertNotEqual(intel.classify("38598155221")[0], "company")


class Oib(unittest.TestCase):
    def test_checksum(self):
        self.assertTrue(intel.valid_oib("81793146560"))
        self.assertFalse(intel.valid_oib("81793146561"))
        self.assertFalse(intel.valid_oib("8179314656"))
        self.assertFalse(intel.valid_oib("abcdefghijk"))


class Fold(unittest.TestCase):
    def test_diacritics_fold_not_vanish(self):
        self.assertEqual(intel.permute_usernames("Rino Tomić")[0], "rinotomic")
        self.assertEqual(intel.permute_usernames("Đuro Đurđević")[0], "djurodjurdjevic")
        self.assertIn("zeljko.simic@x.hr", intel.permute_emails("Željko", "Šimić", "x.hr"))


# ---------------------------------------------------------------- safety

class Sanitize(unittest.TestCase):
    def test_strips_escapes_and_bidi(self):
        s = intel._clean("ok\x1b[2J\x1b]0;pwn\x07 evil‮moc.​x \x9b31m")
        self.assertNotIn("\x1b", s)
        self.assertNotIn("‮", s)
        self.assertNotIn("\x9b", s)
        self.assertNotIn("\x07", s)

    def test_keeps_newlines_and_tabs(self):
        self.assertEqual(intel._clean("a\nb\tc"), "a\nb\tc")

    def test_page_text_drops_script(self):
        self.assertEqual(intel._page_text("<p>a</p><script>evil()</script>").strip(), "a")

    def test_redirect_to_ftp_is_refused(self):
        import email.message
        import io
        import urllib.error
        import urllib.request
        h = intel._HttpOnlyRedirects()
        req = urllib.request.Request("https://a.example/")
        with self.assertRaises(urllib.error.HTTPError):
            h.redirect_request(req, io.BytesIO(), 302, "x", email.message.Message(),
                               "ftp://evil/x")

    def test_get_refuses_file_scheme(self):
        with self.assertRaises(ValueError):
            intel._get("file:///etc/passwd")


# ---------------------------------------------------------------- math

class Sun(unittest.TestCase):
    def test_zagreb_solstices(self):
        # midwinter noon elevation in Zagreb = 90 - 45.8 - 23.44 = ~20.7
        _, el = intel._sun_position(45.815, 15.982, 1798196400)  # 2026-12-21 11:00 UTC
        self.assertAlmostEqual(el, 20.7, delta=0.6)

    def test_shadow_bearing_band(self):
        r = intel.mod_sun("45.815,15.982", "2026-06-21", "334")
        self.assertEqual(r["utc_time_bands"], ["10:07-10:18"])

    def test_impossible_bearing_has_no_band(self):
        # a shadow pointing due south never happens at 45N in June
        self.assertEqual(intel.mod_sun("45.815,15.982", "2026-06-21", "180")["utc_time_bands"], [])

    def test_bad_input(self):
        self.assertIn("error", intel.mod_sun("91,0", "2026-01-01"))
        self.assertIn("error", intel.mod_sun("45,15", "yesterday"))


class Snowflake(unittest.TestCase):
    def test_discord_epoch(self):
        r = intel.mod_snowflake("80351110224678912")
        d = {x["platform"]: x for x in r["readings"]}
        self.assertEqual(d["discord"]["created_utc"], "2015-08-10 17:26:37")


# ---------------------------------------------------------------- phone parsers

HR = {"e164": "+38598155221"}


class Spamcalls(Patched):
    def test_redirect_to_other_number_is_not_a_hit(self):
        self.fake(200, "Scam Call (508 User Reports)",
                  final="https://spamcalls.net/en/num/38598123456")
        r = intel._spamcalls("+385981234987")
        self.assertEqual(r["status"], "not_listed")

    def test_listed_count_from_body_not_sidebar(self):
        body = ("<h1>Who owns</h1><div>Spam-Risk low (2 User Reports)</div>"
                "<div>Most frequently reported (2 User Reports) Telemarketing How would</div>"
                "<aside>+385 1 234 (1,363 User Reports)</aside>")
        self.fake(200, body)
        r = intel._spamcalls("+38598155221")
        self.assertEqual((r["status"], r["reports"], r["verdict"]),
                         ("listed", 2, "Telemarketing"))

    def test_network_error_is_unknown(self):
        def boom(*a, **k):
            raise OSError("down")
        intel._fetch_final = boom
        self.assertEqual(intel._spamcalls("+38598155221")["status"], "unknown")


class Telefonbroj(Patched):
    LISTED = (
        '<script type="application/ld+json">{"@type": "AggregateRating", '
        '"ratingValue": "3.0", "ratingCount": "2"}</script>'
        '<div class="card shadow mb-3 review-card review-danger"><div class="card-body">'
        '<div class="review-text">Uporno zovu</div></div></div>'
        '<div class="card shadow mb-3 review-card review-neutral"><div class="card-body">'
        '<div class="review-text">Broj je od \x1b[31mHTa</div></div></div>'
        '<div class="card shadow mb-3 review-card review-neutral"><div class="card-body">'
        '<div class="review-text">__DESC__</div></div></div>')

    def test_listed(self):
        self.fake(200, self.LISTED)
        r = intel._telefonbroj(HR)
        self.assertEqual((r["status"], r["reports"], r["dangerous"], r["neutral"]),
                         ("listed", 2, 1, 1))
        self.assertTrue(all("\x1b" not in c for c in r["latest"]))

    def test_template_card_alone_is_not_a_report(self):
        body = ('<div class="card shadow mb-3 review-card review-neutral"><div class="card-body">'
                '<div class="review-text">__DESC__</div></div></div>'
                '<p>Još nema prijava za ovaj broj.</p>')
        self.fake(200, body)
        self.assertEqual(intel._telefonbroj(HR)["status"], "not_listed")

    def test_no_match_redirect(self):
        self.fake(200, "", final="https://telefonbroj.com/hr/pretraga-telefona/?match=none&s=1")
        self.assertEqual(intel._telefonbroj(HR)["status"], "not_listed")

    def test_unrecognised_layout_is_unknown_not_clean(self):
        self.fake(200, "<html>totally new design</html>")
        self.assertEqual(intel._telefonbroj(HR)["status"], "unknown")


class Tkomezvao(Patched):
    def test_listed_with_comments(self):
        body = ('<p>Zajednica je dala 1604 SPAM i 184 OK</p><h3>Komentari korisnika (84)</h3>'
                '<time class="comment-date" datetime="2026-07-17T10:00:00">x</time>'
                '<p class="comment-text-large">Buraz broj T-coma</p>')
        self.fake(200, body)
        r = intel._tkomezvao(HR)
        self.assertEqual((r["status"], r["spam_votes"], r["ok_votes"], r["comments"]),
                         ("listed", 1604, 184, 84))
        self.assertEqual(r["latest"], ["17.07.2026: Buraz broj T-coma"])

    def test_404_is_not_listed(self):
        self.fake(404)
        self.assertEqual(intel._tkomezvao(HR)["status"], "not_listed")

    def test_changed_layout_is_unknown(self):
        self.fake(200, "<html>redesign</html>")
        self.assertEqual(intel._tkomezvao(HR)["status"], "unknown")


class Cijibroj(Patched):
    def test_listed(self):
        body = ("<div>Broj evaluacija x 237</div><div>Broj komentara x 163</div>"
                "<div>Procjena Opasno</div><div>Komentari [Opasno] [08.10.2026] : "
                "Kaže aparat Hrv. Telekom [Koristan] [29.09.2026] : Ponuda Zadnji pregledani</div>")
        self.fake(200, body)
        r = intel._cijibroj(HR)
        self.assertEqual((r["status"], r["ratings"], r["comments"], r["verdict"]),
                         ("listed", 237, 163, "Opasno"))
        self.assertEqual(len(r["latest"]), 2)

    def test_404_is_not_listed(self):
        self.fake(404)
        self.assertEqual(intel._cijibroj(HR)["status"], "not_listed")


# ---------------------------------------------------------------- three-state honesty

class ThreeState(unittest.TestCase):
    def test_missing_maigret_is_unavailable_not_empty(self):
        orig = intel.shutil.which
        intel.shutil.which = lambda name: None
        orig_hr = intel._hudsonrock
        intel._hudsonrock = lambda *a: None
        try:
            r = intel.mod_username("someone")
        finally:
            intel.shutil.which, intel._hudsonrock = orig, orig_hr
        self.assertEqual(r["status"], "unavailable")
        self.assertIn("NOT run", r["error"])

    def test_invalid_username_never_reaches_maigret(self):
        r = intel.mod_username("-flag")
        self.assertIn("invalid", r["error"])

    def test_wayback_failure_is_unknown(self):
        orig = intel._json
        intel._json = lambda *a, **k: (_ for _ in ()).throw(OSError("timeout"))
        try:
            self.assertEqual(intel._wayback_first("example.com"), (None, "unknown"))
        finally:
            intel._json = orig


class Output(unittest.TestCase):
    def test_invalid_query_json(self):
        import contextlib
        import io
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            intel.main(["--json", "javascript:alert(1)"])
        d = json.loads(buf.getvalue())
        self.assertEqual(d["detected"], "invalid")
        self.assertIn("retrieved_at", d)


class CorpusBridge(unittest.TestCase):
    """intel reads what corpus already paid for, then HarvestAPI direct, and only
    falls back to Apify when HarvestAPI cannot answer. Every branch here would
    otherwise cost money to test."""

    HV_OK = {"cost": 0.004, "payments": ["linkedinProfileShort"], "element": {"paid": "hv"}}

    def setUp(self):
        self._prof, self._actor, self._hv = intel.corpus_profile, intel.run_actor, intel.harvestapi
        self.actor_calls, self.hv_calls = [], []
        self.hv_reply = dict(self.HV_OK)
        intel.run_actor = lambda *a, **k: self.actor_calls.append(a) or [{"paid": "apify"}]
        intel.harvestapi = lambda path, params, **k: (self.hv_calls.append((path, params))
                                                      or self.hv_reply)
        intel.corpus_profile = lambda t: {"status": "not_tracked"}

    def tearDown(self):
        intel.corpus_profile, intel.run_actor, intel.harvestapi = self._prof, self._actor, self._hv

    def stored(self, **over):
        d = {"status": "found", "complete": True, "relationship": "own",
             "last_scraped_at": intel.time.time() - 86400, "profile": {"firstName": "A"}}
        d.update(over)
        intel.corpus_profile = lambda target: d

    def test_fresh_full_profile_is_free(self):
        self.stored()
        out = intel.linkedin("https://www.linkedin.com/in/someone/")
        self.assertEqual(out["data"], [{"firstName": "A"}])
        self.assertTrue(out["source"].startswith("corpus"))
        self.assertEqual((out["vendor"], out["cost_usd"]), ("corpus", 0.0))
        self.assertEqual((self.hv_calls, self.actor_calls), ([], []))

    def test_author_stub_is_not_a_profile(self):
        self.stored(complete=False)
        out = intel.linkedin("https://www.linkedin.com/in/someone/")
        self.assertEqual(out["corpus"], "stub only")
        self.assertEqual((len(self.hv_calls), self.actor_calls), (1, []))

    def test_stale_profile_is_refetched(self):
        self.stored(last_scraped_at=intel.time.time() - 200 * 86400)
        self.assertEqual(intel.linkedin("https://www.linkedin.com/in/x/")["corpus"], "stale")
        self.assertEqual(len(self.hv_calls), 1)

    def test_fresh_flag_skips_corpus(self):
        self.stored()
        out = intel.linkedin("https://www.linkedin.com/in/x/", fresh=True)
        self.assertEqual(out["data"], [{"paid": "hv"}])

    def test_harvestapi_answers_first_and_states_its_cost(self):
        out = intel.linkedin("https://www.linkedin.com/in/x/")
        self.assertEqual(self.hv_calls[0], ("/linkedin/profile",
                                            {"query": "https://www.linkedin.com/in/x/",
                                             "main": "true"}))
        self.assertEqual((out["vendor"], out["cost_usd"]), ("harvestapi", 0.004))
        self.assertIn("$0.004", out["source"])
        self.assertEqual(self.actor_calls, [])
        for k in ("module", "source", "as_of", "data"):
            self.assertIn(k, out)

    def test_company_url_uses_the_company_endpoint(self):
        intel.linkedin("https://www.linkedin.com/company/acme/")
        self.assertEqual(self.hv_calls[0][0], "/linkedin/company")

    def test_harvestapi_down_falls_back_to_apify(self):
        self.hv_reply = {"error": "harvestapi 402: out of credit", "fallback": True}
        out = intel.linkedin("https://www.linkedin.com/company/acme/")
        self.assertEqual(self.actor_calls[0][0], "harvestapi/linkedin-company")
        self.assertEqual((out["vendor"], out["data"]), ("apify", [{"paid": "apify"}]))
        self.assertIn("402", out["harvestapi"])

    def test_target_not_found_does_not_pay_apify_too(self):
        self.hv_reply = {"error": "harvestapi 404: not found", "fallback": False}
        out = intel.linkedin("https://www.linkedin.com/in/nobody-here/")
        self.assertEqual(self.actor_calls, [])
        self.assertIn("error", out["data"])


class HarvestApiHttp(unittest.TestCase):
    """The HTTP layer itself, with urlopen stubbed: the key travels in a header (never
    the URL), and each failure says whether another vendor is worth paying."""

    class _Resp(io.BytesIO):
        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

    def setUp(self):
        self._open, self.seen = intel.urllib.request.urlopen, []
        self._key = os.environ.get("HARVESTAPI_KEY")
        os.environ["HARVESTAPI_KEY"] = "test-key"

    def tearDown(self):
        intel.urllib.request.urlopen = self._open
        if self._key is None:
            os.environ.pop("HARVESTAPI_KEY", None)
        else:
            os.environ["HARVESTAPI_KEY"] = self._key

    def reply(self, body=None, code=None):
        def fake(req, timeout=None):
            self.seen.append(req)
            if code:
                raise intel.urllib.error.HTTPError(req.full_url, code, "x", {},
                                                   io.BytesIO(json.dumps(body).encode()))
            return self._Resp(json.dumps(body).encode())
        intel.urllib.request.urlopen = fake

    def test_ok_and_key_in_header_only(self):
        self.reply({"cost": 0.004, "error": None, "element": {"name": "Acme"}})
        d = intel.harvestapi("/linkedin/company", {"query": "https://x/company/acme/"})
        self.assertEqual(d["element"], {"name": "Acme"})
        req = self.seen[0]
        self.assertEqual(req.get_header("X-api-key"), "test-key")
        self.assertNotIn("test-key", req.full_url)

    def test_bad_key_falls_back(self):
        self.reply({"status": 401, "error": {"error": "Invalid API key"}}, code=401)
        d = intel.harvestapi("/linkedin/profile", {"query": "x"})
        self.assertTrue(d["fallback"])
        self.assertIn("401", d["error"])

    def test_not_found_does_not_fall_back(self):
        self.reply({"error": "not found"}, code=404)
        self.assertFalse(intel.harvestapi("/linkedin/profile", {"query": "x"})["fallback"])

    def test_error_in_200_body_is_not_success(self):
        self.reply({"cost": 0, "error": "Profile not found", "element": None})
        d = intel.harvestapi("/linkedin/profile", {"query": "x"})
        self.assertIn("error", d)
        self.assertFalse(d["fallback"])

    def test_no_key_falls_back_without_a_request(self):
        os.environ.pop("HARVESTAPI_KEY", None)
        orig = intel._keys_env
        intel._keys_env = lambda name: None
        try:
            self.assertTrue(intel.harvestapi("/linkedin/profile", {"query": "x"})["fallback"])
        finally:
            intel._keys_env = orig
        self.assertEqual(self.seen, [])


class CorpusArgv(unittest.TestCase):
    def setUp(self):
        self._prof = intel.corpus_profile

    def test_ssh_arguments_are_quoted_for_the_remote_shell(self):
        orig = os.environ.get("INTEL_CORPUS_CMD")
        try:
            os.environ["INTEL_CORPUS_CMD"] = "ssh box /bin/corpus"
            argv = intel._corpus_argv(["find", "Ana Horvat; rm -rf ~"])
            self.assertEqual(argv[-1], "'Ana Horvat; rm -rf ~'")
            os.environ["INTEL_CORPUS_CMD"] = "/bin/corpus"
            self.assertEqual(intel._corpus_argv(["find", "Ana Horvat"])[-1], "Ana Horvat")
        finally:
            if orig is None:
                os.environ.pop("INTEL_CORPUS_CMD", None)
            else:
                os.environ["INTEL_CORPUS_CMD"] = orig

    def test_broken_corpus_is_unavailable_not_a_crash(self):
        orig = os.environ.get("INTEL_CORPUS_CMD")
        try:
            os.environ["INTEL_CORPUS_CMD"] = "/nonexistent/corpus"
            self.assertEqual(self._prof("https://www.linkedin.com/in/x/")["status"],
                             "unavailable")
        finally:
            if orig is None:
                os.environ.pop("INTEL_CORPUS_CMD", None)
            else:
                os.environ["INTEL_CORPUS_CMD"] = orig


class CorpusWorkingTogether(unittest.TestCase):
    """corpus lookup in the brief, the privacy gate, and `intel socials`. The
    subprocess is mocked and every handle, name and domain is invented."""

    PUB = {"private": False, "platform": "instagram", "handle": "acme_studio",
           "relationship": "competitor", "url": "https://www.instagram.com/acme_studio/",
           "followers": 900, "posts_stored": 40, "first_post": "2025-01-01",
           "last_post": "2026-10-01", "last_synced": "2026-10-22",
           "cadence_median_days": 3.0, "engagement_median": 25,
           "top_formats": [{"kind": "image", "posts": 30, "median_engagement": 25}],
           "top_posts": [{"date": "2026-01-01", "engagement": 300,
                          "url": "https://www.instagram.com/p/abc/", "opening": "Hello world"}],
           "recent_outliers": [], "brief_cmd": "corpus brief instagram:acme_studio"}
    PRIV = {"private": True, "platform": "linkedin", "handle": "jane-example",
            "relationship": "client", "url": "https://www.linkedin.com/in/jane-example/",
            "followers": 5, "posts_stored": 3, "engagement_median": 7,
            "top_posts": [{"date": "2026-01-01", "engagement": 9,
                           "opening": "SECRET LAUNCH PLAN", "url": "https://x/secret"}],
            "summary": "SECRET SUMMARY", "top_topics": [{"topic": "SECRET TOPIC"}],
            "display_name": "Jane Example", "brief_cmd": "corpus brief linkedin:jane-example"}

    def setUp(self):
        self._run, self._env = intel.subprocess.run, dict(os.environ)
        os.environ["INTEL_CORPUS_CMD"] = "/opt/corpus"
        os.environ.pop("INTEL_NO_CORPUS", None)
        self.calls = []

    def tearDown(self):
        intel.subprocess.run = self._run
        os.environ.clear()
        os.environ.update(self._env)

    def reply(self, matches=None, raises=None, stdout=None):
        def run(argv, **kw):
            self.calls.append((argv, kw))
            if raises:
                raise raises
            out = stdout if stdout is not None else json.dumps(
                {"queries": [], "matches": matches or [], "unmatched": []})
            return type("R", (), {"stdout": out, "returncode": 0})()
        intel.subprocess.run = run

    def modules(self):
        return [{"module": "username", "seed": "acme_studio", "accounts": [
            {"platform": "Instagram", "url": "https://www.instagram.com/acme_studio/", "weak": False},
            {"platform": "LinkedIn", "url": "https://www.linkedin.com/in/acme-founder/", "weak": False},
            {"platform": "Foo", "url": "https://foo.example/", "weak": True}]}]

    def test_lookup_uses_the_corpus_cmd_with_a_short_timeout(self):
        self.reply([self.PUB])
        got = intel.corpus_lookup(["acme_studio", "-evil"])
        self.assertEqual(got["status"], "ok")
        argv, kw = self.calls[0]
        self.assertEqual(argv[:4], ["/opt/corpus", "lookup", "--json", "--"])
        self.assertEqual(argv[4:], ["acme_studio", "-evil"])
        self.assertLessEqual(kw["timeout"], 10)
        self.assertNotIn("--include-private", argv)

    def test_section_added_for_username_run_and_untracked_socials_suggested(self):
        self.reply([self.PUB])
        c = intel.corpus_section("username", "@acme_studio", self.modules())
        self.assertEqual([m["handle"] for m in c["matches"]], ["acme_studio"])
        self.assertEqual(c["matches"][0]["top_posts"][0]["opening"], "Hello world")
        sug = c["suggestions"]
        self.assertEqual([(s["platform"], s["handle"]) for s in sug],
                         [("linkedin", "acme-founder")])
        self.assertTrue(sug[0]["command"].startswith(
            "intel content add https://www.linkedin.com/in/acme-founder --relationship"))

    def test_private_entries_are_rebuilt_from_aggregates_only(self):
        self.reply([self.PRIV])
        c = intel.corpus_section("person", "Jane Example", [])
        blob = json.dumps(c)
        for leak in ("SECRET", "x/secret", "opening", "summary", "display_name",
                     "top_topics"):
            self.assertNotIn(leak, blob)
        self.assertNotIn("Jane Example", json.dumps(c["matches"]))
        m = c["matches"][0]
        self.assertTrue(m["private"])
        self.assertEqual(m["top_posts"], [{"date": "2026-01-01", "engagement": 9}])
        self.assertIn("cloud LLM", m["handling"])
        buf = io.StringIO()
        import contextlib
        with contextlib.redirect_stdout(buf):
            intel._print_content(c)
        self.assertNotIn("SECRET", buf.getvalue())
        self.assertIn("PRIVATE", buf.getvalue())

    def test_private_fails_closed_on_missing_or_wrong_flag(self):
        for m in ({**self.PUB, "private": None}, {**self.PUB, "relationship": "client"},
                  {k: v for k, v in self.PUB.items() if k != "private"}):
            out = intel.sanitize_corpus_match(m)
            self.assertTrue(out["private"])
            self.assertNotIn("opening", json.dumps(out))
        self.assertFalse(intel.sanitize_corpus_match(self.PUB)["private"])

    def test_unreachable_corpus_is_skipped_and_never_fails_the_run(self):
        import subprocess as sp
        for kw in ({"raises": sp.TimeoutExpired("ssh", 10)}, {"raises": OSError("no ssh")},
                   {"stdout": "not json"}, {"stdout": ""}):
            self.reply(**kw)
            self.assertEqual(intel.corpus_lookup(["x"])["status"], "unavailable")
            self.assertIsNone(intel.corpus_section("username", "x", []))
        os.environ["INTEL_CORPUS_CMD"] = ""
        os.environ["PATH"] = "/nonexistent"
        orig = os.path.exists
        os.path.exists = lambda p: False if "corpus_cmd" in str(p) else orig(p)
        try:
            self.assertEqual(intel.corpus_lookup(["x"])["why"], "corpus not configured")
        finally:
            os.path.exists = orig

    def test_skip_is_noted_only_when_verbose(self):
        import contextlib
        self.reply(raises=OSError("down"))
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            intel.corpus_section("domain", "acme.example", [])
        self.assertEqual(err.getvalue(), "")
        os.environ["INTEL_DEBUG"] = "1"
        with contextlib.redirect_stderr(err):
            intel.corpus_section("domain", "acme.example", [])
        self.assertIn("corpus lookup skipped", err.getvalue())

    def test_assemble_attaches_content_and_can_opt_out(self):
        self.reply([self.PUB])
        orig = intel.mod_domain
        intel.mod_domain = lambda q: {"module": "domain", "whois": {}, "subdomains": []}
        try:
            res = intel.assemble("acme.example")
            self.assertEqual(res["content"]["matches"][0]["handle"], "acme_studio")
            self.assertEqual(self.calls[0][0][-1], "acme.example")
            self.calls.clear()
            self.assertNotIn("content", intel.assemble("acme.example", corpus=False))
            self.assertEqual(self.calls, [])
        finally:
            intel.mod_domain = orig

    def test_non_listed_flows_do_not_call_corpus(self):
        self.reply([self.PUB])
        orig = intel.mod_email
        intel.mod_email = lambda q: {"module": "email"}
        try:
            self.assertNotIn("content", intel.assemble("a@b.example"))
        finally:
            intel.mod_email = orig
        self.assertEqual(self.calls, [])

    def test_socials_lists_profiles_from_existing_modules_only(self):
        mods = self.modules() + [{"module": "github", "socials": [
            {"provider": "twitter", "url": "https://twitter.com/acme_dev"}],
            "profile": {"login": "acme-dev", "blog": "https://acme.example"}}]
        got = intel.collect_socials(mods)
        self.assertEqual([(s["platform"], s["handle"], s["source"]) for s in got], [
            ("instagram", "acme_studio", "maigret"), ("linkedin", "acme-founder", "maigret"),
            ("x", "acme_dev", "github profile"), ("github", "acme-dev", "github profile")])
        for s in got:
            self.assertEqual(set(s), {"platform", "handle", "url", "source"})
        orig = intel.assemble
        intel.assemble = lambda t, **k: {"modules": mods}
        try:
            self.assertEqual(intel.socials("@acme_studio"), got)
        finally:
            intel.assemble = orig

    def test_social_from_url(self):
        f = intel.social_from_url
        self.assertEqual(f("https://www.linkedin.com/company/Acme-Co/"), ("linkedin", "acme-co"))
        self.assertEqual(f("https://www.tiktok.com/@acme.tok"), ("tiktok", "acme.tok"))
        self.assertIsNone(f("https://www.instagram.com/p/xyz/"))
        self.assertIsNone(f("https://acme.example/in/x"))

    def test_social_profile_refuses_hostile_urls_and_canonicalises(self):
        f = intel.social_profile
        self.assertEqual(f("https://m.instagram.com/acme.studio/?hl=en"),
                         ("instagram", "acme.studio", "https://www.instagram.com/acme.studio"))
        for bad in ("https://instagram.com/x;rm -rf ~",
                    "https://instagram.com/$(touch%20pwned)",
                    "https://instagram.com/a%27b",
                    "https://evil@instagram.com/acme",
                    "https://instagram.com:8443/acme",
                    "javascript://instagram.com/acme",
                    "https://instagram.com\\@evil.example/acme",
                    "https://instagram.com/acme\x1b[31m"):
            self.assertIsNone(f(bad), bad)

    def test_suggested_command_is_shell_quoted_and_canonical(self):
        orig = intel.corpus_lookup
        intel.corpus_lookup = lambda c, **k: {"status": "ok", "matches": []}
        try:
            mods = [{"module": "username", "accounts": [
                {"url": "https://www.tiktok.com/@acme.tok?lang=en"}]}]
            sec = intel.corpus_section("username", "acme", mods)
        finally:
            intel.corpus_lookup = orig
        cmd = sec["suggestions"][0]["command"]
        self.assertTrue(cmd.startswith("intel content add https://www.tiktok.com/@acme.tok "), cmd)

    def test_nested_corpus_strings_are_cleaned(self):
        m = intel.sanitize_corpus_match({
            "private": False, "relationship": "competitor", "platform": "instagram",
            "handle": "acme", "top_posts": [{"date": "2026-01-01", "engagement": 5,
                                             "url": "https://x.example/p", "opening": "hi\x1b[2Jthere"}]})
        self.assertNotIn("\x1b", json.dumps(m["top_posts"]))


if __name__ == "__main__":
    unittest.main()
