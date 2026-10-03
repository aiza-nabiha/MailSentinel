"""
backend/scripts/load_phishing_pot.py

ONE-TIME, OFFLINE loader for the rf-peixoto/phishing_pot dataset
(https://github.com/rf-peixoto/phishing_pot) -- 8,614 real phishing
.eml samples, ~623MB total.

What this does and does NOT do:
  - Does NOT commit the raw dataset to git (623MB of .eml files
    would make every future clone download that).
  - Does NOT run the full live pipeline (WHOIS/DNS/TLS/JARM network
    lookups) against all 8,614 emails -- that would take hours and
    hammer those external services for no benefit here.
  - DOES extract just the sender/URL domains from each sample (reusing
    the same extract_domains() logic the live pipeline already uses)
    and upserts them into the tiny known_phishing_indicators table,
    which domain_reputation.check_phishing_pot_corpus() then reads
    exactly the way it reads Spamhaus DBL / PhishTank.

This is a one-time (or occasional re-run) offline job -- it is NOT
called from api.py and is NOT part of any request path.

Usage:
    # Clone the dataset first if you haven't:
    git clone --depth 1 https://github.com/rf-peixoto/phishing_pot.git /tmp/phishing_pot

    # Then load it:
    cd backend/scripts
    python load_phishing_pot.py /tmp/phishing_pot

    # Or let the script clone it for you into a temp dir:
    python load_phishing_pot.py --clone
"""

import argparse
import os
import re
import sys
import tempfile
import subprocess
from datetime import datetime, timezone

THIS_DIR = os.path.dirname(os.path.abspath(__file__))
BACKEND_DIR = os.path.dirname(THIS_DIR)
INFRA_ENGINE_DIR = os.path.join(BACKEND_DIR, "infrastructure_engine")
STORAGE_ENGINE_DIR = os.path.join(BACKEND_DIR, "storage_engine")

for path in (INFRA_ENGINE_DIR, STORAGE_ENGINE_DIR):
    if path not in sys.path:
        sys.path.insert(0, path)

from domain_extract import extract_domains  # noqa: E402
from db import get_connection  # noqa: E402

DATASET_REPO_URL = "https://github.com/rf-peixoto/phishing_pot.git"

FROM_DOMAIN_RE = re.compile(r"From:.*@([\w.-]+)", re.IGNORECASE)


def clone_dataset(dest_dir=None):
    """
    Shallow-clones phishing_pot into a temp dir (or dest_dir) and
    returns the path. Caller is responsible for cleanup if they care
    about disk space -- this is a one-off script, not a server
    process, so we don't auto-delete by default.
    """

    dest_dir = dest_dir or tempfile.mkdtemp(prefix="phishing_pot_")

    print(f"[*] Cloning {DATASET_REPO_URL} -> {dest_dir} (depth=1)")

    subprocess.run(
        ["git", "clone", "--depth", "1", DATASET_REPO_URL, dest_dir],
        check=True,
    )

    return dest_dir


def find_eml_files(dataset_dir):
    eml_paths = []

    for root, _dirs, files in os.walk(dataset_dir):
        for name in files:
            if name.lower().endswith(".eml"):
                eml_paths.append(os.path.join(root, name))

    return sorted(eml_paths)


def sender_domain_for(eml_path):
    """
    Quick, resilient sender-domain extraction straight from the raw
    bytes -- doesn't need a full parse, just enough to tag this one
    domain as 'sender_domain' instead of the generic 'url_domain'
    bucket that extract_domains() returns everything else as.
    """

    try:
        with open(eml_path, "rb") as f:
            # From header is always near the top; reading the whole
            # file is fine too, these are small individual samples.
            head = f.read(8192).decode("utf-8", errors="ignore")

        match = FROM_DOMAIN_RE.search(head)

        if match:
            return match.group(1).lower().rstrip(".")

    except Exception:
        pass

    return None


def upsert_indicator(conn, value, value_type, now):
    conn.execute(
        """
        INSERT INTO known_phishing_indicators
            (value, value_type, source, sample_count, first_seen, last_seen)
        VALUES (%s, %s, 'phishing_pot', 1, %s, %s)
        ON CONFLICT (value, value_type, source) DO UPDATE SET
            sample_count = known_phishing_indicators.sample_count + 1,
            last_seen = EXCLUDED.last_seen
        """,
        (value, value_type, now, now),
    )


def load(dataset_dir, batch_commit_every=250):
    eml_files = find_eml_files(dataset_dir)

    print(f"[*] Found {len(eml_files)} .eml files under {dataset_dir}")

    if not eml_files:
        print("[!] No .eml files found -- wrong path?")
        return

    conn = get_connection()
    now = datetime.now(timezone.utc)

    total_indicators = 0
    failed = 0

    try:
        for i, eml_path in enumerate(eml_files, start=1):

            try:
                domains = extract_domains(eml_path)
                sender_domain = sender_domain_for(eml_path)

                for domain in domains:
                    value_type = (
                        "sender_domain"
                        if domain == sender_domain
                        else "url_domain"
                    )
                    upsert_indicator(conn, domain, value_type, now)
                    total_indicators += 1

            except Exception as e:
                failed += 1
                print(f"    [!] {eml_path}: {e}")

            if i % batch_commit_every == 0:
                conn.commit()
                print(f"    ... {i}/{len(eml_files)} emails processed")

        conn.commit()

    finally:
        conn.close()

    row_count_conn = get_connection()
    try:
        unique_rows = row_count_conn.execute(
            "SELECT COUNT(*) FROM known_phishing_indicators WHERE source = 'phishing_pot'"
        ).fetchone()[0]
    finally:
        row_count_conn.close()

    print("\n[*] Done.")
    print(f"    Emails processed:        {len(eml_files) - failed}")
    print(f"    Emails failed to parse:  {failed}")
    print(f"    Domain upserts issued:   {total_indicators}")
    print(f"    Unique domains stored:   {unique_rows}")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "dataset_dir",
        nargs="?",
        default=None,
        help="Path to an already-cloned phishing_pot checkout.",
    )
    parser.add_argument(
        "--clone",
        action="store_true",
        help="Clone phishing_pot into a temp dir instead of using an existing checkout.",
    )
    args = parser.parse_args()

    if args.clone:
        dataset_dir = clone_dataset()
    elif args.dataset_dir:
        dataset_dir = args.dataset_dir
    else:
        parser.error("Provide a dataset_dir, or pass --clone to clone it automatically.")
        return

    load(dataset_dir)


if __name__ == "__main__":
    main()
