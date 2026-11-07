#!/usr/bin/env python3
"""Adversarial corpus for the shared detector.

This file is the acceptance spec. It exists because a measurement showed two
gates in the same workflow had drifted to 9/31 and 13/31 detection on these
shapes, and the drift was invisible without a test.

House rule, and the reason the corpus is worth more than the regexes:
  * every shape that ever leaks gets appended to POSITIVE;
  * every false alarm that blocks correctly redacted evidence gets appended
    to NEGATIVE.

All values below are synthetic.

    python3 -m unittest discover -s tests
"""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from secret_patterns import is_redacted, normalize_name, scan_line, scan_lines  # noqa: E402


# Shapes that MUST trip the gate.
POSITIVE = [
    ("Cookie header", "Cookie: QSID=8f3a9b2c1d4e5f6a7b8c9d0e"),
    (
        "Authorization header",
        "authorization: bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjMifQ.s1gnatur3xx",
    ),
    ("HAR Cookie", '{"name":"Cookie","value":"QSID=8f3a9b2c1d4e5f6a7b8c9d0e"}'),
    ("HAR Authorization", '{"name":"Authorization","value":"Bearer 8f3a9b2c1d4e5f6a7b8c"}'),
    ("HAR set-cookie with spaces", '{ "name": "set-cookie", "value": "QSID=abc123def456; Secure" }'),
    ("HAR reversed key order", '{"value":"QSID=8f3a9b2c1d4e5f6a","name":"Cookie"}'),
    ("JSON refresh_token", '{"refresh_token":"rt_8f3a9b2c1d4e5f6a7b8c9d0e"}'),
    ("JSON sessionToken", '{"sessionToken":"st_8f3a9b2c1d4e5f6a7b8c9d0e"}'),
    ("JSON opaque id_token", '{"id_token":"opaque_8f3a9b2c1d4e5f6a7b8c9d0e"}'),
    ("markdown table Set-Cookie", "| Set-Cookie | QSID=8f3a9b2c1d4e5f6a; HttpOnly; Path=/ |"),
    ("markdown table x-csrf-token", "| x-csrf-token | 8f3a9b2c1d4e5f6a7b8c9d0e |"),
    ("prose, non-English", "Cookie o wartosci QSID=8f3a9b2c1d4e5f6a7b8c9d0e zostal wyslany."),
    ("YAML cookie", "cookie: QSID=8f3a9b2c1d4e5f6a7b8c9d0e"),
    ("private key", "-----BEGIN RSA PRIVATE KEY-----"),
    ("credentials in URL", "https://testuser:passw0rd123@sandbox.example.test/api"),
    ("curl -b", "curl -b 'APPSESSID=dR7kPq2mXv9nJ4hL8ZbT8wQ' https://edge.example.test/me"),
    ("curl -u", "curl -u tester-a:Sandbox-Passw0rd https://edge.example.test/me"),
    (
        "Copy as PowerShell",
        '$session.Cookies.Add((New-Object System.Net.Cookie("appctx", '
        '"v3H4sIAAAAAAAAA1WQy07DMBBF", "/", "example.test")))',
    ),
    (
        "token in URL fragment",
        '  "location": "https://sandbox.example.test/oauth/cb'
        '#access_token=8f3c1d9e0a4b7c2d5e6f8a1b3c4d5e6f&token_type=bearer",',
    ),
    (
        "body wrapped in HAR text",
        '  "text": "{\\"login\\":\\"tester-a\\",\\"password\\":\\"Sandbox-Test-Passw0rd\\"}"',
    ),
    (
        "cookie object in HAR",
        '      { "name": "APPSESSID", "value": "8f3a9b2c1d4e5f6a7b8c9d0e1f2a3b4c", "path": "/" },',
    ),
    ("padded base64 in prose", "Account B cookie: c2Vzc2lvbj1hYmNkMTIzNDU2Nzg5MDEyMw=="),
    ("base64 containing a slash", "Set-Cookie;APPSESSID=dR7kPq2mXv9nJ4hL/ZbT8wQ=="),
    ("non-English cookie name", "Ciasteczko sesji konta B: APPSESSID=8f3a9b2c1d4e5f6a7b8c9d0e"),
    ("non-English token name", "Wartość tokenu odświeżania: rt_8f3a9b2c1d4e5f6a7b8c9d0e"),
    ("word-based passphrase", "Test account B password: strawberry-star-bicycle-lamp"),
    (
        "descriptive JSON key",
        '  "set_cookie_observed": "APPSESSID=QDNxfL0yR6hTn8vZ2kM4aWpXcE9dGsB=="',
    ),
    (
        "token in query next to a placeholder",
        "GET /order-service/orders?buyerId=<ACCOUNT_A_ID>"
        "&access_token=8f3ba91c2d7e4f60a5b1c9d8 HTTP/2",
    ),
    ("x-session-id header", "x-session-id: 38b91c2f7d4a4f21a733ce90b41d8e77"),
    # Regression: stripping the auth scheme (needed so "Bearer [REDACTED]" does
    # not block an export) must not let a secret behind the scheme through.
    ("secret behind Bearer scheme", "Authorization: Bearer synthetic-sensitive-value-for-test"),
    ("secret behind Basic scheme", "authorization: Basic dGVzdGVyOlNhbmRib3hQYXNz"),
]

# A HAR expanded by pretty-printing: name and value on SEPARATE lines.
# A purely line-by-line detector is blind to this, hence scan_lines().
MULTILINE_HAR = [
    "        {",
    '          "name": "Cookie",',
    '          "value": "appctx=v3H4sIAAAAAAAAA1WQy07DMBBF; bot_guard=xQ8sPk3Nn2gT"',
    "        },",
]

# CLEAN content: the gate has no right to stop it. A false alarm on clean
# evidence is costly, because it teaches the operator to ignore the result.
NEGATIVE = [
    ("redacted header", "Cookie: <REDACTED>"),
    ("redacted HAR", '{"name":"Cookie","value":"[REDACTED]"}'),
    ("descriptively redacted", "Cookie: [ACCOUNT_B_SESSION_REDACTED]"),
    ("name without a value", "SENSITIVE HEADERS (present, values NOT shown): Cookie"),
    ("output of a request redactor", "GET /objects/{OWNED_OBJECT_ID} HTTP/2"),
    ("timestamp", "Scope was checked at 2026-08-01T12:00:00Z. Both synthetic accounts."),
    ("description without a value", "The request carried a Cookie header; its value is not recorded."),
    ("user placeholder", "Cookie: YOUR_COOKIE_HERE"),
    ("placeholder in an address", "  --ua 'YOUR_ADDRESS@example.test security-research'"),
    ("versioned path", "Cookie set by the endpoint /api/v2/checkout-session"),
    ("task identifier", "Checked the session cookie in test case 009 without recording a value."),
    ("empty header", "Cookie:"),
    ("lifetime description", "The token expired after 3600 seconds; no value was recorded."),
    # False alarms found by adversarial testing, all arise from CORRECTLY
    # redacted evidence.
    ("scheme without a value", "Authorization: Bearer [REDACTED]"),
    ("scheme without a value in JSON", '    "authorization": "Bearer [REDACTED]"'),
    ("table cell with an annotation", "| Cookie | present, value not recorded |"),
    (
        "body hash next to the word Cookie",
        "Response body hash: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 "
        "(Cookie header omitted)",
    ),
    ("path containing an identifier", '  "path": "/api/orders/8121",'),
    ("descriptively redacted header", "Cookie: {OWNED_SESSION_PLACEHOLDER}"),
    # Found by running the gate on this repository's own documentation: the
    # flag letters are shared with unrelated commands.
    ("shred -u takes a path, not credentials", "Then destroy the original:  shred -u /tmp/raw.txt"),
    ("tar -b takes a block count", "Extract with: tar -b 20 -xf archive.tar"),
]


class TestSecretShapes(unittest.TestCase):
    def test_positive_shapes_are_detected(self):
        for name, line in POSITIVE:
            with self.subTest(shape=name):
                self.assertTrue(scan_line(line), f"secret passed the gate: {name}")

    def test_clean_content_is_not_flagged(self):
        for name, line in NEGATIVE:
            with self.subTest(shape=name):
                self.assertFalse(
                    scan_line(line),
                    f"false alarm on clean content: {name} -> {scan_line(line)}",
                )


class TestMultilineHar(unittest.TestCase):
    def test_pretty_printed_har_pair_is_detected(self):
        hits = list(scan_lines(MULTILINE_HAR))
        self.assertTrue(hits, "cookie in an expanded HAR passed the gate")
        self.assertTrue(
            any("multi-line HAR" in label for _, label in hits),
            f"expected a multi-line label, got {hits}",
        )

    def test_redacted_multiline_har_is_clean(self):
        clean = [
            '          "name": "Cookie",',
            '          "value": "[REDACTED]"',
        ]
        self.assertEqual(list(scan_lines(clean)), [])

    def test_distant_name_and_value_do_not_pair(self):
        far = ['"name": "Cookie",'] + ['  "other": 1,'] * 6 + ['"value": "QSID=8f3a9b2c1d4e"']
        self.assertFalse(
            any("multi-line HAR" in label for _, label in scan_lines(far)),
            "paired a name and value further apart than the window",
        )


class TestHelpers(unittest.TestCase):
    def test_normalize_name_collapses_separators(self):
        for variant in ("sessionToken", "session_token", "Session-Token", "SESSION TOKEN"):
            self.assertEqual(normalize_name(variant), "sessiontoken")

    def test_is_redacted_accepts_composite_markers(self):
        for value in ("<REDACTED>", "[REDACTED]", "[ACCOUNT_B_SESSION_REDACTED]", "", "null"):
            self.assertTrue(is_redacted(value), value)

    def test_is_redacted_rejects_real_values(self):
        for value in ("QSID=8f3a9b2c1d4e", "Bearer abc123def456", "rt_8f3a9b2c1d4e5f6a"):
            self.assertFalse(is_redacted(value), value)


class TestGatesShareOneDetector(unittest.TestCase):
    """Two diverging copies of the patterns were the original root cause."""

    def test_cli_imports_the_shared_module(self):
        root = Path(__file__).resolve().parents[1]
        source = (root / "redaction_check.py").read_text(encoding="utf-8")
        self.assertIn("from secret_patterns import", source)


if __name__ == "__main__":
    unittest.main()
