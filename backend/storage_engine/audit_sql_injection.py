"""
backend/storage_engine/audit_sql_injection.py

Scans every .py file in the repo for SQL built with f-strings,
.format(), or string concatenation instead of parameterized (?)
placeholders -- the #1 way SQLite apps get exploited.

This does NOT modify anything -- pure read-only audit.

Usage (from backend/storage_engine/):
    python3 audit_sql_injection.py
"""

import re
from pathlib import Path

REPO_ROOT = Path(__file__).parent.parent.parent

# Patterns that indicate DANGEROUS SQL construction
DANGEROUS_PATTERNS = [
    (re.compile(r'execute\(\s*f["\']', re.IGNORECASE), "f-string passed directly to .execute()"),
    (re.compile(r'execute\(\s*["\'].*["\']\s*%\s', re.IGNORECASE), "% string formatting used to build SQL"),
    (re.compile(r'execute\(\s*["\'].*["\']\.format\(', re.IGNORECASE), ".format() used to build SQL"),
    (re.compile(r'execute\(\s*["\'][^"\']*["\'].*\+.*\)', re.IGNORECASE), "string concatenation (+) used to build SQL"),
]

SAFE_INDICATOR = re.compile(r'execute\(\s*["\'\)]')  # execute("...", (params,)) style


def scan_file(filepath):
    findings = []
    try:
        text = filepath.read_text(encoding="utf-8", errors="ignore")
    except Exception:
        return findings

    for line_num, line in enumerate(text.splitlines(), start=1):
        if ".execute(" not in line and "executemany(" not in line:
            continue
        for pattern, description in DANGEROUS_PATTERNS:
            if pattern.search(line):
                findings.append((line_num, description, line.strip()))
    return findings


def main():
    py_files = [f for f in REPO_ROOT.rglob("*.py") if "venv" not in str(f) and "__pycache__" not in str(f)]

    print(f"[*] Scanning {len(py_files)} Python files for SQL injection risk...\n")

    total_findings = 0
    for filepath in sorted(py_files):
        findings = scan_file(filepath)
        if findings:
            total_findings += len(findings)
            rel_path = filepath.relative_to(REPO_ROOT)
            print(f"[!!] {rel_path}")
            for line_num, description, line in findings:
                print(f"     Line {line_num}: {description}")
                print(f"       {line[:100]}")
            print()

    print("=" * 60)
    if total_findings == 0:
        print("[+] No SQL injection risk patterns found.")
        print("    All .execute() calls appear to use parameterized queries.")
    else:
        print(f"[!!] {total_findings} risky pattern(s) found -- review above before your demo.")


if __name__ == "__main__":
    main()