"""Offline regression tests for intel.py. Stdlib only, no network.

Each parser test feeds a small SYNTHETIC page shaped like the real site (not a
scraped copy), so the logic is pinned without committing third-party pages.
Real-site drift is caught by the live canary, `tests/canary.py`.

    python3 -m unittest discover -s tests -v
"""
import importlib.util
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
    """intel reads what corpus already paid for, and only falls back to Apify when
    corpus cannot answer. Every branch here would otherwise cost money to test."""

    def setUp(self):
        self._prof, self._actor = intel.corpus_profile, intel.run_actor
        self.actor_calls = []
        intel.run_actor = lambda *a, **k: self.actor_calls.append(a) or [{"paid": True}]

    def tearDown(self):
        intel.corpus_profile, intel.run_actor = self._prof, self._actor

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
        self.assertEqual(self.actor_calls, [])

    def test_author_stub_is_not_a_profile(self):
        self.stored(complete=False)
        out = intel.linkedin("https://www.linkedin.com/in/someone/")
        self.assertEqual(out["corpus"], "stub only")
        self.assertEqual(len(self.actor_calls), 1)

    def test_stale_profile_is_refetched(self):
        self.stored(last_scraped_at=intel.time.time() - 200 * 86400)
        self.assertEqual(intel.linkedin("https://www.linkedin.com/in/x/")["corpus"], "stale")
        self.assertEqual(len(self.actor_calls), 1)

    def test_fresh_flag_skips_corpus(self):
        self.stored()
        out = intel.linkedin("https://www.linkedin.com/in/x/", fresh=True)
        self.assertEqual(out["data"], [{"paid": True}])

    def test_company_url_uses_the_company_actor(self):
        intel.corpus_profile = lambda t: {"status": "not_tracked"}
        intel.linkedin("https://www.linkedin.com/company/acme/")
        self.assertEqual(self.actor_calls[0][0], "harvestapi/linkedin-company")

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


if __name__ == "__main__":
    unittest.main()
