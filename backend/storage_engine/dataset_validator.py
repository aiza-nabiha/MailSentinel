"""
backend/storage_engine/dataset_validator.py

Run this FIRST against indian_email_dataset_500k.csv, train_data.csv,
test_data.csv before doing anything else with them. It tells you:
  - what columns actually exist
  - how many rows
  - whether it looks like raw email text or a labeled feature table
  - a random sample of rows so you can eyeball the content

This does NOT modify anything -- pure inspection.

Usage:
    python dataset_validator.py --csv ../../data/indian_email_dataset_500k.csv
"""

import argparse
import csv
import random


def validate(csv_path, sample_size=3):
    with open(csv_path, newline="", encoding="utf-8", errors="replace") as f:
        reader = csv.reader(f)
        header = next(reader)
        rows = list(reader)

    print(f"[+] File: {csv_path}")
    print(f"[+] Columns ({len(header)}): {header}")
    print(f"[+] Row count: {len(rows)}")

    if not rows:
        print("[!] No data rows found.")
        return

    print(f"\n[+] {min(sample_size, len(rows))} random sample rows:")
    for row in random.sample(rows, min(sample_size, len(rows))):
        preview = {col: (val[:80] + "..." if len(val) > 80 else val)
                   for col, val in zip(header, row)}
        print(f"  {preview}")

    # Heuristic: does this look like raw email text, or pre-extracted features?
    text_like_cols = [c for c in header if c.lower() in
                       ("body", "text", "content", "email", "message", "raw")]
    label_like_cols = [c for c in header if c.lower() in
                        ("label", "class", "is_phishing", "target", "spam")]

    print("\n[+] Heuristic read:")
    if text_like_cols:
        print(f"    Looks like raw email text is in column(s): {text_like_cols}")
        print("    -> convertible to .eml for the pipeline, one row at a time")
    if label_like_cols:
        print(f"    Looks like it has ground-truth labels in column(s): {label_like_cols}")
        print("    -> usable for Person 1's classifier training/validation")
    if not text_like_cols and not label_like_cols:
        print("    Column names don't obviously match text/label patterns --")
        print("    inspect the sample rows above manually.")

    if len(rows) > 5000:
        print(f"\n[!] {len(rows)} rows is too many to run through live WHOIS/DNS/TLS")
        print("    lookups (Person 3's pipeline) in hackathon time.")
        print("    Recommend sampling a few hundred rows for the live demo pipeline,")
        print("    and reserving the full set only for Person 1's offline model training.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--csv", required=True)
    parser.add_argument("--sample-size", type=int, default=3)
    args = parser.parse_args()
    validate(args.csv, args.sample_size)