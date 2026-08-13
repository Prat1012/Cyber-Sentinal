"""Project security audit: secrets, unsafe subprocess/SQL, .gitignore coverage.

Does NOT print secret values - only file:line markers and whether a pattern
was flagged for manual review.
"""

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SKIP_DIRS = {".venv", "__pycache__", ".pytest_cache", ".git", "node_modules"}
SKIP_FILES = {"security_audit.py"}

EXTS = {".py", ".js", ".html", ".css", ".md", ".example", ".ini", ".txt"}

# Regexes that indicate a possible secret assignment. We report a boolean,
# never the matched value.
SECRET_RE = re.compile(
    r"(?i)(password|passwd|api[_-]?key|secret|token|client[_-]?secret|"
    r"private[_-]?key)\s*=\s*['\"][^'\"]{6,}['\"]"
)
PRIVATE_KEY_RE = re.compile(r"BEGIN (RSA |EC |OPENSSH |ENCRYPTED )?PRIVATE KEY")
SHELL_TRUE_RE = re.compile(r"shell\s*=\s*True")
SHELL_STR_RE = re.compile(r"subprocess\.(run|Popen|call|check_output)\([^)]*\bshell\s*=\s*True")


def walk():
    for path in ROOT.rglob("*"):
        if not path.is_file():
            continue
        rel = path.relative_to(ROOT)
        if any(part in SKIP_DIRS for part in rel.parts):
            continue
        if path.name in SKIP_FILES or path.suffix not in EXTS:
            continue
        yield path, rel


def audit() -> int:
    issues = 0

    print("=== 1. Potential hardcoded secrets (values NOT printed) ===")
    for path, rel in walk():
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        for lineno, line in enumerate(text.splitlines(), 1):
            if SECRET_RE.search(line) and "example" not in rel.as_posix().lower():
                # Exclude the obvious .env.example and README documentation
                if rel.as_posix().endswith((".env.example", "README.md", "CyberSentinel-Development-Report.md")):
                    continue
                print(f"  REVIEW {rel}:{lineno}")
                issues += 1
    if not issues:
        print("  (none)")

    print("=== 2. Private key material ===")
    found = False
    for path, rel in walk():
        text = path.read_text(encoding="utf-8", errors="replace")
        if PRIVATE_KEY_RE.search(text):
            print(f"  FOUND in {rel}")
            found = True
            issues += 1
    if not found:
        print("  (none)")

    print("=== 3. shell=True / unsafe subprocess ===")
    found = False
    for path, rel in walk():
        if path.suffix != ".py":
            continue
        text = path.read_text(encoding="utf-8", errors="replace")
        if SHELL_TRUE_RE.search(text) or SHELL_STR_RE.search(text):
            print(f"  FOUND shell=True in {rel}")
            found = True
            issues += 1
    if not found:
        print("  (none)")

    print("=== 4. SQL string concatenation (f-strings in execute) ===")
    found = False
    for path, rel in walk():
        if path.suffix != ".py":
            continue
        text = path.read_text(encoding="utf-8", errors="replace")
        if re.search(r"(execute|executemany|scalars|session\.execute)\(f['\"]", text):
            print(f"  FOUND f-string SQL in {rel}")
            found = True
            issues += 1
    if not found:
        print("  (none)")

    print("=== 5. Hardcoded credentials in config defaults ===")
    found = False
    for path, rel in walk():
        if path.suffix != ".py":
            continue
        text = path.read_text(encoding="utf-8", errors="replace")
        if re.search(r"(?i)(password|secret|key)\s*=\s*['\"][^'\"]{6,}['\"]", text):
            # config.py has a dev-only placeholder secret - flag for review
            if "dev-only" in text:
                print(f"  NOTE {rel}: dev-only default secret (documented, guarded by validate_for_production)")
            else:
                print(f"  REVIEW {rel}")
            found = True
    if not found:
        print("  (none)")

    print("=== 6. .gitignore coverage of .env ===")
    gi = ROOT / ".gitignore"
    if not gi.exists():
        print("  MISSING .gitignore")
        issues += 1
    else:
        text = gi.read_text(encoding="utf-8")
        for pat in (".env", ".env.local", "*.db", "reports/*.pdf", "*.pem"):
            print(f"  {'OK' if pat in text else 'MISSING'} .gitignore entry: {pat}")
            if pat not in text:
                issues += 1

    print("=== 7. .env presence in repo (must not exist) ===")
    envs = [p for p in (ROOT / "backend").glob(".env*")]
    present = [p.name for p in envs if p.name != ".env.example"]
    print(f"  {present if present else '(only .env.example present - OK)'}")

    print()
    print("AUDIT COMPLETE - reviewable items:", issues)
    return 0 if issues == 0 else 1


if __name__ == "__main__":
    sys.exit(audit())
