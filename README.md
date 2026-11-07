# evidence-redaction-gate

[![tests](https://github.com/kubakozub/evidence-redaction-gate/actions/workflows/tests.yml/badge.svg)](https://github.com/kubakozub/evidence-redaction-gate/actions/workflows/tests.yml)

A fail-closed, offline gate that refuses to let secrets and personal data leave
your machine inside security-research evidence.

You captured a request, you redacted it, you are about to attach it to a report.
This runs last and says no if a session cookie is still in there.

```
$ python3 redaction_check.py evidence/
evidence/notes.md:14: potential sensitive cookie value
evidence/capture.har:882: potential sensitive cookie in multi-line HAR entry
DENY_EXPORT: 2 potential sensitive value(s); inspect and redact locally.
```

No dependencies, no network, no telemetry. Python 3.9+, standard library only.

## Why this exists

I had two gates in one workflow, each carrying its own copy of the patterns.
They had silently drifted apart. Measuring them against a battery of realistic
secret shapes settled it:

| | shapes detected (of 31) | false alarms on clean evidence (of 21) |
|---|---|---|
| gate A, before | 9 | 2 |
| gate B, before | 13 | 5 |
| shared detector, now | **31** | **0** |

The fix was not a longer list of regexes. It was making one module the single
source of patterns, importing it everywhere, and writing down the corpus that
proves it, so the divergence cannot come back unnoticed. A test in this repo
asserts that the CLI imports the shared module, which is the cheap structural
guard against the original root cause.

## What it catches that a naive grep does not

Real captured traffic does not look like `Cookie: abc123` on one tidy line.

- **HAR entries after `jq .`**: pretty-printing puts `"name"` and `"value"` on
  *separate lines*. A line-by-line scanner is blind to this by construction; the
  detector keeps a three-line window (`scan_lines()`).
- **HAR cookie objects**, where `"name"` is the *cookie's* name and no
  dictionary can help: recognised by the neighbouring `path`/`domain`/`httpOnly`
  fields instead.
- **Bodies wrapped in `postData.text`**, where an innocuous key hides the secret
  inside it, one level of recursive descent.
- **`curl -b` / `-u` / `--oauth2-bearer`**: the flag's meaning is unambiguous,
  so the cookie name does not have to be in any dictionary.
- **DevTools "Copy as PowerShell"**, where name and value are positional
  arguments to `System.Net.Cookie(...)`.
- **OAuth tokens in the URL *fragment*** (`#access_token=`), not just the query.
- **Base64 with `/` and `=` padding**: Java, PHP, ASP.NET and Laravel session
  cookies all have that shape, so a slash cannot mean "this is a path".
- **Non-English evidence.** Notes written in your working language say
  "Ciasteczko konta B", never "Cookie". Stem matching with diacritic folding
  covers that; extend `SENSITIVE_STEMS` for your own language.
- **The whole `X-*` family**, via `removeprefix("x")` on the normalised name.

## The two decisions that took real use to find

Both of these came from the gate being wrong in production, not from design:

**Stripping the auth scheme.** `Authorization: Bearer [REDACTED]`, the canonical
output of every header redactor, was *blocking* exports, because the word
"Bearer" was being read as the value. There is now an explicit
`strip_auth_scheme()`, plus a regression test proving a secret standing *behind*
the scheme still fires.

**Two value thresholds.** `looks_like_value()` for syntactic rules where a name
is unambiguous, and a stricter `looks_like_strong_value()` for proximity rules.
Without the second one, ordinary prose containing the word "token" trips the
gate, and a gate that cries wolf on clean evidence is worse than no gate,
because it trains you to ignore it.

## What it does not catch

Stated plainly, because a security tool that oversells itself is a liability:

- A secret deliberately split across sentences, additionally encoded, or sitting
  in a screenshot. Lexical detection cannot reach any of those.
- Secrets shorter than ~16 characters: below the value threshold.
- Hand-wrapped `Cookie:` continuation lines are not reassembled.
- Binary formats. Only text files under 5 MB with known suffixes are scanned.

**A green OK means "I did not find one", not "this is clean."** The gate is fit
to *block* an automated export. It is not fit to *authorise* one without a human
looking at the diff.

## Usage

```bash
python3 redaction_check.py path/to/evidence/     # directory or single file
```

Exit codes: `0` nothing found, `1` findings printed as `file:line: potential
<label>`, `2` bad path. That makes it usable as a pre-commit hook or a CI step:

```yaml
- run: python3 redaction_check.py evidence/
```

As a library:

```python
from secret_patterns import scan_lines

for line_number, label in scan_lines(open("capture.har")):
    print(line_number, label)
```

## Extending it

The corpus is the contract. House rule:

- every shape that ever leaks past the gate gets appended to `POSITIVE`;
- every false alarm that blocks correctly redacted evidence gets appended to
  `NEGATIVE`.

Then make both pass. Adding a pattern without adding its test is how the two
gates diverged in the first place.

```bash
python3 -m unittest discover -s tests
python3 redaction_check.py .          # the gate runs on its own repository
```

That second command is not decoration. It is how the last two `NEGATIVE` cases
were found: `shred -u /tmp/raw.txt` in the documentation was being read as
curl's `-u` credential flag, because the flag letters are shared with unrelated
commands. The rule now requires the flag's argument to look like a value, which
rejects paths and bare numbers.

## License

MIT, see [LICENSE](LICENSE).
