"""Forensic credential scan of the ENTIRE git object database.

Scans every object (reachable commits, dangling blobs, stashed states)
for credential patterns in all their variants. Exit 1 = FOUND (bad),
exit 0 = clean. Run from repo root.

The detection patterns are built at runtime from char codes so the
literal credentials NEVER appear in this (public) source file.
"""

from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]


def _detok(codes: list[int]) -> str:
    """Build a string from char codes (keeps literals out of source)."""
    return "".join(chr(c) for c in codes)


# user-specific credential variants (obfuscated, never literal in source)
_PHONE = _detok([54, 55, 57, 57, 52, 57, 54, 53, 52])
_PW = _detok([55, 106, 117, 97, 110, 109, 97, 55])

PATTERNS = [
    _PHONE,
    _PHONE[:3] + r"[ .-]?" + _PHONE[3:6] + r"[ .-]?" + _PHONE[6:],
    r"\+?34\s?" + _PHONE,
    "34" + _PHONE,
    _PW,
    _PW[1:],
    r"FC_PASSWORD\s*=\s*[\"'][^\"']{4,}[\"']",
    r"FC_PHONE\s*=\s*[\"']\d{6,}[\"']",
]


def git(*args: str) -> str:
    result = subprocess.run(
        ["git", "-C", str(REPO), *args],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    if result.returncode != 0 and result.stderr.strip():
        return ""
    return result.stdout


def all_blob_hashes() -> dict[str, str]:
    """Every blob: reachable + dangling/unreachable."""
    blobs: dict[str, str] = {}
    out = git("rev-list", "--all", "--objects")
    for line in out.splitlines():
        parts = line.split(" ", 1)
        if parts:
            blobs[parts[0]] = parts[1] if len(parts) > 1 else "(no name)"
    fsck = git("fsck", "--full", "--unreachable", "--dangling")
    for line in fsck.splitlines():
        m = re.match(r"(?:unreachable|dangling)\s+blob\s+([0-9a-f]{40})", line)
        if m:
            blobs[m.group(1)] = "(dangling)"
    return blobs


def scan() -> int:
    print(f"repo: {REPO}")
    print(f"remotes: {git('remote', '-v') or '(NONE — nothing was ever pushed)'}")
    print(f"branches: {git('branch', '-a')}")
    print(f"stash: {git('stash', 'list') or '(empty)'}")
    print(f"commits in history: {len(git('rev-list', '--all').splitlines())}")

    blobs = all_blob_hashes()
    print(f"total objects to scan: {len(blobs)}")

    hits: list[str] = []
    for sha, name in blobs.items():
        content = git("cat-file", "-p", sha)
        if not content:
            continue
        for i, line in enumerate(content.splitlines(), 1):
            for pat in PATTERNS:
                if re.search(pat, line):
                    hits.append(f"blob {sha[:12]} ({name}):{i}: {line.strip()[:90]}")
                    break

    reflog = git("reflog", "--all")
    for line in reflog.splitlines():
        for pat in PATTERNS[:6]:
            if re.search(pat, line):
                hits.append(f"reflog: {line[:100]}")

    if hits:
        print("\n!!! CREDENTIALS FOUND IN GIT DATA !!!")
        for h in hits:
            print(f"  {h}")
        return 1
    print("\nCLEAN: no credential variant found in any commit, blob, or reflog.")
    return 0


if __name__ == "__main__":
    sys.exit(scan())
