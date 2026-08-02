#!/usr/bin/env python3
"""Offline gate: refuse to export evidence that still contains secrets or PII.

Exits 1 and prints every finding as `file:line: potential <label>` when
anything is found, so it drops straight into a pre-commit hook or a CI job.
Exits 0 with an explicit reminder that manual review is still required.

    python3 redaction_check.py path/to/evidence/
"""

from __future__ import annotations

import argparse
from pathlib import Path

from secret_patterns import scan_lines

TEXT_SUFFIXES = {".md", ".txt", ".json", ".jsonl", ".csv", ".yaml", ".yml", ".http", ".har", ".log"}
MAX_FILE_BYTES = 5_000_000


def arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("path", type=Path, help="file or directory to scan")
    return parser.parse_args()


def files_under(path: Path):
    if path.is_file():
        yield path
        return
    for candidate in sorted(path.rglob("*")):
        if (
            candidate.is_file()
            and candidate.suffix.lower() in TEXT_SUFFIXES
            and candidate.stat().st_size <= MAX_FILE_BYTES
        ):
            yield candidate


def main() -> int:
    args = arguments()
    if not args.path.exists():
        print(f"no such path: {args.path}")
        return 2

    findings: list[tuple[Path, int, str]] = []
    for path in files_under(args.path):
        try:
            lines = path.read_text(encoding="utf-8").splitlines()
        except UnicodeDecodeError:
            continue
        for number, label in scan_lines(lines):
            findings.append((path, number, label))

    if findings:
        for path, number, label in findings:
            print(f"{path}:{number}: potential {label}")
        print(
            f"DENY_EXPORT: {len(findings)} potential sensitive value(s); "
            "inspect and redact locally."
        )
        return 1

    print("OK: no configured secret/PII patterns found. Manual review is still required.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
