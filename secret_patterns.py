#!/usr/bin/env python3
"""Shared lexical detector for secrets and personal data in evidence files.

This module exists because two separate gates in one research workflow each
carried their own copy of the patterns, and the copies silently drifted apart.
A measurement settled it: on a battery of 31 realistic secret shapes, one gate
caught 9 and the other 13. Making this module the single source of patterns —
imported by every gate — is what stops the drift from coming back.

Design premise: this is a GATE, not a classifier. A false positive costs a
minute of looking at a line; a false negative leaks a session cookie into an
archive that leaves your machine. So the detector leans towards firing. But a
false alarm on correctly redacted evidence is treated as its own bug, because
it teaches the operator to ignore the result — which is worse than no gate.

Matching is by SHAPE wherever possible rather than by name: a cookie-name
dictionary is always a step behind reality, but the structure of a HAR entry,
the meaning of `curl -b`, and the `System.Net.Cookie(...)` constructor are not.

KNOWN LIMITS — stated rather than hidden:
  * A secret split across sentences by the author, additionally encoded, or
    sitting in a screenshot is out of reach for any lexical detector.
  * Secrets shorter than ~16 characters are below the value threshold and will
    not be recognised as values.
  * Hand-wrapped Cookie continuation lines are not reassembled.
  * A green OK means "I did not find one", not "this is clean". Manual review
    of the export stays mandatory.
"""

from __future__ import annotations

import re
from typing import Iterable, Iterator

# ----------------------------------------------------------------------- names

SENSITIVE_NAMES = frozenset(
    {
        "cookie", "cookies", "setcookie",
        "authorization", "proxyauthorization", "authentication", "auth",
        "apikey", "authtoken", "accesstoken", "refreshtoken", "idtoken",
        "sessiontoken", "bearertoken", "csrftoken", "xsrftoken", "csrf", "xsrf",
        "amzsecuritytoken",
        "sessionid", "session", "sid", "jsessionid", "phpsessid", "aspnetsessionid",
        "password", "passwd", "pwd", "passphrase",
        "secret", "clientsecret", "apisecret", "privatekey", "signingkey",
        "token", "bearer", "otp", "totp", "onetimecode", "verificationcode",
    }
)

# Stems matched by prefix, for evidence and notes that are not written in
# English. Real research notes say "Ciasteczko konta B" (Polish for "account B
# cookie"), never "Cookie". These are used only where a strong value is also
# required, so ordinary prose cannot trip them. Add stems for your own working
# language here.
SENSITIVE_STEMS = (
    "ciasteczk", "ciastk", "sesj", "hasl", "haslo",
    "poswiadcz", "uwierzytelni", "token", "klucz", "sekret",
)

_DIACRITICS = str.maketrans(
    {"ł": "l", "ą": "a", "ć": "c", "ę": "e", "ń": "n", "ó": "o", "ś": "s", "ź": "z", "ż": "z"}
)
_NAME_CHARS = re.compile(r"[^a-z0-9]")


def normalize_name(name: str) -> str:
    return _NAME_CHARS.sub("", name.casefold().translate(_DIACRITICS))


def name_is_exact(name: str) -> bool:
    """Exact match. removeprefix('x') closes the whole X-Session-Id family."""
    norm = normalize_name(name)
    return norm in SENSITIVE_NAMES or norm.removeprefix("x") in SENSITIVE_NAMES


def name_is_sensitive(name: str) -> bool:
    """Looser match — callers must additionally require a strong value."""
    if name_is_exact(name):
        return True
    norm = normalize_name(name)
    return any(norm.startswith(stem) for stem in SENSITIVE_STEMS)


# ---------------------------------------------------------------- placeholders

_MARKERS = r"redacted|placeholder|masked|removed|usunieto|zredagowano|object_id|pominiet\w*"
_NEGATIONS = (
    r"brak|nie[\s_-]*zapisan\w*|niezapisan\w*|nie[\s_-]*pokazan\w*|nie[\s_-]*dotyczy"
    r"|bez[\s_-]*wartosci|obecny|obecne|not[\s_-]*recorded|not[\s_-]*shown|present"
    r"|value|n/?a|null|none|false|true|-"
)

# The whole string must be a marker plus decoration. When a marker was allowed
# anywhere in the string, "k3Yh8s2Nq1Xz (value removed)" passed as clean.
_PLACEHOLDER_ONLY = re.compile(
    rf"^[\[<{{(]?[\s_*\-]*(?:[A-Z0-9_]*[_-])?(?:{_MARKERS}|{_NEGATIONS})[\s_*\-]*[\]>}})]?$",
    re.I,
)
_EMPTYISH = re.compile(r"^[\s_*.\-]*$|^x{3,}$|^\*{3,}$", re.I)
_PLACEHOLDER_USER = re.compile(r"^(?:your|twoj|twoje)[_-][A-Za-z0-9_-]+$", re.I)

# An authentication scheme is not a value. Without this, the canonical output of
# every header redactor — "Authorization: Bearer [REDACTED]" — blocked exports,
# because the word "Bearer" itself was being read as the value.
_AUTH_SCHEME = re.compile(
    r"^(?:Bearer|Basic|Digest|Token|Negotiate|MAC|Hawk|AWS4-HMAC-SHA256)\s*", re.I
)


def strip_auth_scheme(value: str) -> str:
    return _AUTH_SCHEME.sub("", value.strip(), count=1)


def is_redacted(value: str) -> bool:
    stripped = strip_auth_scheme(value.strip().strip("\"'`,;")).strip()
    if _EMPTYISH.match(stripped) or _PLACEHOLDER_USER.match(stripped):
        return True
    return bool(_PLACEHOLDER_ONLY.match(stripped))


# ------------------------------------------------------------- shape of values

_ISO_DATE = re.compile(r"^\d{4}-\d{2}-\d{2}(?:[T ]\d{2}:\d{2}(?::\d{2})?(?:\.\d+)?Z?)?$")
_VERSION = re.compile(r"^v?\d+(?:\.\d+){1,3}$")
_ONLY_DIGITS = re.compile(r"^\d+$")
_ONLY_LETTERS = re.compile(r"^[A-Za-z]+$")
# Standard base64 contains '/' and ends with '='. Java, PHP, ASP.NET and Laravel
# session cookies have exactly this form, so a slash cannot be an unconditional
# reason to reject a token as "looks like a path".
_B64ISH = re.compile(r"^[A-Za-z0-9+/=_.-]{16,}$")
_PATHISH = re.compile(r"(?:^|[\"'(\[:])[.~]{0,2}[/\\]|[A-Za-z]:[\\/]")
_DIGEST = re.compile(
    r"^(?:sha\d*:)?[0-9a-f]{32}$|^(?:sha\d*:)?[0-9a-f]{40}$|^(?:sha\d*:)?[0-9a-f]{64}$", re.I
)
_HASH_MARKER = re.compile(
    r"\b(?:hash|sha\d*|digest|checksum|suma\s+kontrolna|md5|body_sha256)\b", re.I
)

_TRIM = "\"'`,;|()[]{}<>"


def looks_like_value(token: str) -> bool:
    token = token.strip().strip(_TRIM)
    if len(token) < 8 or is_redacted(token):
        return False
    if _PATHISH.search(token) or "://" in token:
        return False
    if ("/" in token or "\\" in token) and not _B64ISH.match(token):
        return False
    if _ISO_DATE.match(token) or _VERSION.match(token):
        return False
    if _ONLY_DIGITS.match(token) or _ONLY_LETTERS.match(token):
        return False
    if "=" in token:
        return True
    return any(c.isdigit() for c in token) and any(c.isalpha() for c in token)


def looks_like_strong_value(token: str) -> bool:
    """Stricter threshold for rules based on proximity rather than syntax.

    The bare word "token" in a descriptive sentence must not trip the gate;
    research notes are full of such sentences.
    """
    cleaned = token.strip().strip(_TRIM)
    # A secret is a token, not a sentence. Without this, a table cell such as
    # "`401` Bearer authentication required" reads as a value.
    if cleaned.split() != [cleaned]:
        return False
    if not looks_like_value(cleaned) or len(cleaned) < 16:
        return False
    core = cleaned.rstrip("=")  # base64 padding is not an assignment
    if "=" in core:
        return len(core.partition("=")[2]) >= 8
    if len(core) >= 20 and any(c.islower() for c in core) and any(c.isupper() for c in core):
        return True
    return sum(c.isdigit() for c in core) >= 3


# ------------------------------------------------------------------- patterns

_NAME = r"[A-Za-z][A-Za-z0-9_\- .]{1,30}"

HEADER_RE = re.compile(
    rf"(?:^|[|>\-*\s\"'{{,])(?P<name>{_NAME})[\"']?\s*[:=]\s*[\"']?(?P<value>[^\s|\"']+)"
)

# Headers carrying an authentication scheme need the value to run to end of
# line rather than to the first token: otherwise the "value" is the word
# "Bearer", which looks empty once the scheme is stripped, and the real secret
# standing behind it walks straight through.
AUTH_HEADER_RE = re.compile(
    rf"(?:^|[|>\-*\s\"'{{,])(?P<name>(?:proxy-)?authorization|authentication|www-authenticate)"
    rf"[\"']?\s*[:=]\s*[\"']?(?P<value>[^\"'\r\n]+)",
    re.I,
)
TABLE_CELL_RE = re.compile(
    r"\|\s*(?P<name>[A-Za-z][A-Za-z0-9_\- ]{1,30})\s*\|\s*(?P<value>[^|\r\n]{1,200}?)\s*\|"
)

HAR_NAME_FIRST_RE = re.compile(
    r"\"name\"\s*:\s*\"(?P<name>[^\"]{1,64})\"\s*,\s*\"value\"\s*:\s*\"(?P<value>[^\"]*)\"", re.I
)
HAR_VALUE_FIRST_RE = re.compile(
    r"\"value\"\s*:\s*\"(?P<value>[^\"]*)\"\s*,\s*\"name\"\s*:\s*\"(?P<name>[^\"]{1,64})\"", re.I
)
# A cookie object in a HAR: there "name" is the COOKIE's name, not a header's,
# so a name dictionary cannot help — recognise it by the neighbouring fields.
HAR_COOKIE_OBJ_RE = re.compile(
    r"\"name\"\s*:\s*\"[^\"]{1,64}\"\s*,\s*\"value\"\s*:\s*\"(?P<value>[^\"]*)\""
    r"(?=[^\r\n]*\"(?:path|domain|httpOnly|secure|expires)\")",
    re.I,
)

COOKIE_ATTR_RE = re.compile(
    r"[A-Za-z0-9_.\-]{2,64}=[^\s;|]{4,}\s*;\s*"
    r"(?:HttpOnly|Secure|SameSite|Path\s*=|Domain\s*=|Max-Age\s*=|Expires\s*=)",
    re.I,
)

# OAuth tokens come back in the URL FRAGMENT (#access_token=...), not only in
# the query string.
SECRET_QUERY_RE = re.compile(
    r"(?:^|[\"'?&#;\s])(?P<name>[A-Za-z][A-Za-z0-9_-]{1,30})=(?P<value>[^&#\s\"']{6,})"
)
# Names that matter only inside a URL. "code" in the global dictionary would
# fire on {"code": "NotFoundException"}, which appears in every other report.
QUERY_ONLY_NAMES = frozenset({"code", "authcode", "ticket", "sig", "signature", "requesttoken"})

# HTTP client flags that carry a secret. The meaning of the flag is
# unambiguous, so the cookie name does NOT have to be in the dictionary.
CLIENT_FLAG_RE = re.compile(
    r"(?:^|\s)(?:-b|-u|--cookie|--user|--oauth2-bearer)\s+[\"']?(?P<value>[^\"'\s]{8,})"
)
# DevTools "Copy as PowerShell" — name and value as positional arguments.
PS_COOKIE_RE = re.compile(
    r"System\.Net\.Cookie\(\s*\"[^\"]{1,64}\"\s*,\s*\"(?P<value>[^\"]{8,})\""
)

# Wrapper keys under which HAR and "Copy as fetch" hide an entire body.
WRAPPER_KEYS = frozenset({"text", "body", "payload", "raw", "content", "data", "postdata"})
WRAPPER_RE = re.compile(rf"\"(?P<name>{_NAME})\"\s*:\s*\"(?P<value>[^\r\n]{{20,}})\"")

PROVIDER_PATTERNS = {
    "JWT-like token": re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{5,}"),
    "private key": re.compile(r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----"),
    "AWS access key": re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b"),
    "GitHub token": re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,})\b"),
    "Slack token": re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b"),
    "Google API key": re.compile(r"\bAIza[0-9A-Za-z_-]{30,}\b"),
    "Stripe secret key": re.compile(r"\b(?:sk|rk)_(?:live|test)_[0-9A-Za-z]{16,}\b"),
    "URL credentials": re.compile(r"\bhttps?://[^\s/:@]+:[^\s/@]+@", re.I),
    "email address / PII": re.compile(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", re.I),
}

# Mask the placeholder ITSELF, not the whole token around it. Surrounding \S*
# used to swallow '...&access_token=...' together with an adjacent
# <ACCOUNT_A_ID>, hiding a real secret behind a redaction marker.
_PLACEHOLDER_TOKEN = re.compile(
    r"(?:your|twoj|twoje)[_-][A-Za-z0-9_-]+"
    r"|<[A-Za-z_][A-Za-z0-9_ .-]*>"
    r"|\{[A-Z_][A-Z0-9_]*\}"
    r"|\[[^\]\s]*(?:REDACTED|PLACEHOLDER)[^\]\s]*\]",
    re.I,
)

_WORD = re.compile(r"[A-Za-zÀ-ſ][A-Za-z0-9À-ſ_-]{2,30}")
_CHUNK = re.compile(r"[^\s,;|]{8,}")
_PROXIMITY_CHARS = 40


def mask_placeholders(line: str) -> str:
    return _PLACEHOLDER_TOKEN.sub("<PLACEHOLDER>", line)


def _named_pair_hits(line: str, found: set[str]) -> None:
    for match in AUTH_HEADER_RE.finditer(line):
        value = match.group("value").strip().rstrip(",;")
        if not is_redacted(value):
            found.add(f"sensitive {match.group('name').strip().lower()} value")

    for regex in (HEADER_RE, TABLE_CELL_RE):
        for match in regex.finditer(line):
            raw_name, value = match.group("name"), match.group("value")
            if is_redacted(value):
                continue
            exact = name_is_exact(raw_name)
            parts = [p for p in re.split(r"[_\- .]+", raw_name) if p]
            partial = any(name_is_sensitive(p) for p in parts)
            # Exact name -> looser value test. Composite or descriptive name ->
            # demand a strong value, otherwise "| Cookie | present |" fires.
            if exact and any(looks_like_value(t) for t in _CHUNK.findall(value) or [value]):
                found.add(f"sensitive {raw_name.strip().lower()} value")
            elif partial and looks_like_strong_value(value):
                found.add(f"sensitive {raw_name.strip().lower()} value")


def _proximity_hit(line: str) -> str | None:
    names = [m for m in _WORD.finditer(line) if name_is_sensitive(m.group(0))]
    if not names:
        return None
    hash_context = bool(_HASH_MARKER.search(line))
    for chunk in _CHUNK.finditer(line):
        token = chunk.group(0).strip(_TRIM)
        if hash_context and _DIGEST.match(token):
            continue
        if not looks_like_strong_value(token):
            continue
        for name in names:
            if min(abs(chunk.start() - name.end()), abs(name.start() - chunk.end())) <= _PROXIMITY_CHARS:
                return name.group(0)
    return None


def _labelled_value_hit(line: str) -> str | None:
    """Catches 'Test account B password: strawberry-star-bicycle-lamp'.

    All-letter values do not clear the strong-value threshold, so they are
    caught structurally instead: a sensitive name somewhere in the line, and a
    short tail after the last colon. Requiring a single token keeps prose out.
    """
    if ":" not in line:
        return None
    names = [m.group(0) for m in _WORD.finditer(line) if name_is_sensitive(m.group(0))]
    if not names:
        return None
    tail = line.rsplit(":", 1)[1].strip().strip(_TRIM)
    # A single token, not a phrase — "Cleanup: Revoke tokens." is prose.
    if len(tail) < 8 or tail.split() != [tail] or is_redacted(tail):
        return None
    # "name: X-API-Key" — the tail is a header name, not its value.
    if name_is_sensitive(tail):
        return None
    if _PATHISH.search(tail) or "://" in tail or _ISO_DATE.match(tail):
        return None
    if _DIGEST.match(tail) and _HASH_MARKER.search(line):
        return None
    # An ordinary single-case word is not a value. A secret has a digit, a
    # separator, or mixed case — a passphrase "a-b-c-d" has separators.
    if not (
        any(c.isdigit() for c in tail)
        or any(c in "-_.=+/" for c in tail)
        or (any(c.islower() for c in tail) and any(c.isupper() for c in tail))
    ):
        return None
    return names[0]


def scan_line(line: str, *, _depth: int = 0) -> set[str]:
    """Returns a set of finding labels. An empty set means the line is clean."""
    found: set[str] = set()
    line = mask_placeholders(line)

    for label, pattern in PROVIDER_PATTERNS.items():
        if pattern.search(line):
            found.add(label)

    if COOKIE_ATTR_RE.search(line):
        found.add("Set-Cookie value")

    for match in HAR_COOKIE_OBJ_RE.finditer(line):
        if not is_redacted(match.group("value")):
            found.add("cookie value in HAR entry")

    for regex in (HAR_NAME_FIRST_RE, HAR_VALUE_FIRST_RE):
        for match in regex.finditer(line):
            if name_is_exact(match.group("name")) and not is_redacted(match.group("value")):
                found.add(f"sensitive {match.group('name').strip().lower()} in HAR entry")

    _named_pair_hits(line, found)

    for match in SECRET_QUERY_RE.finditer(line):
        name, value = normalize_name(match.group("name")), match.group("value")
        if is_redacted(value):
            continue
        if name_is_exact(match.group("name")):
            found.add("secret-like URL query value")
        elif name in QUERY_ONLY_NAMES and len(value) >= 16 and not _ONLY_DIGITS.match(value):
            found.add("authorization code in URL")

    for label, regex in (
        ("secret in HTTP client flag", CLIENT_FLAG_RE),
        ("cookie in PowerShell export", PS_COOKIE_RE),
    ):
        for match in regex.finditer(line):
            value = match.group("value")
            # The flag letters are shared with other commands: `shred -u FILE`
            # and `tar -b N` are not credentials. Requiring the argument to
            # look like a value rejects paths and bare numbers.
            if not is_redacted(value) and looks_like_value(value):
                found.add(label)

    # A HAR packs an entire body into postData.text, so an innocuous wrapper key
    # hides the secret inside it. One level of descent is enough in practice.
    if _depth == 0:
        for match in WRAPPER_RE.finditer(line):
            if normalize_name(match.group("name")) in WRAPPER_KEYS:
                inner = match.group("value").replace("\\\"", "\"").replace("\\/", "/")
                found |= {
                    f"{label} (in field {match.group('name')})"
                    for label in scan_line(inner, _depth=1)
                }

    if not found:
        name = _proximity_hit(line) or _labelled_value_hit(line)
        if name:
            found.add(f"sensitive {name.lower()} near a value-like token")

    return found


# --------------------------------------------------------- multi-line scanning

_HAR_NAME_LINE = re.compile(r"^\s*\"name\"\s*:\s*\"(?P<name>[^\"]{1,64})\"\s*,?\s*$", re.I)
_HAR_VALUE_LINE = re.compile(r"^\s*\"value\"\s*:\s*\"(?P<value>[^\"]*)\"\s*,?\s*$", re.I)
_HAR_PAIR_WINDOW = 3


def scan_lines(lines: Iterable[str]) -> Iterator[tuple[int, str]]:
    """Scan with memory between lines.

    Why this exists: a HAR opened in an editor, or piped through `jq .` or
    `python -m json.tool`, breaks apart so that "name" and "value" land on
    SEPARATE lines. A purely line-by-line detector is blind to that by
    construction — and it is the most common real-world shape of captured
    traffic.
    """
    pending_name: tuple[int, str] | None = None
    pending_value: tuple[int, str] | None = None

    for number, line in enumerate(lines, start=1):
        for label in sorted(scan_line(line)):
            yield number, label

        name_match = _HAR_NAME_LINE.match(line)
        value_match = _HAR_VALUE_LINE.match(line)

        if name_match:
            pending_name = (number, name_match.group("name"))
            if pending_value and number - pending_value[0] <= _HAR_PAIR_WINDOW:
                if name_is_exact(name_match.group("name")) and not is_redacted(pending_value[1]):
                    yield pending_value[0], (
                        f"sensitive {name_match.group('name').lower()} in multi-line HAR entry"
                    )
                pending_value = None
        elif value_match:
            pending_value = (number, value_match.group("value"))
            if pending_name and number - pending_name[0] <= _HAR_PAIR_WINDOW:
                if name_is_exact(pending_name[1]) and not is_redacted(value_match.group("value")):
                    yield number, (
                        f"sensitive {pending_name[1].lower()} in multi-line HAR entry"
                    )
                pending_name = None
