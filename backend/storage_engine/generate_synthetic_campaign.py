"""
backend/storage_engine/generate_synthetic_campaign.py

Generates 5 fake phishing .eml files that deliberately share
infrastructure (same nameserver-style hosting domain, same
template wording) so Person 4's clustering/correlation demo has
a guaranteed-good input on stage, independent of whether real
scraped data conveniently clusters.

Usage (from backend/storage_engine/):
    python generate_synthetic_campaign.py --out ../../data/synthetic_campaign
"""

import argparse
import os

TEMPLATE = """From: "{brand} Security" <alerts@{domain}>
To: victim{n}@example.com
Subject: {subject}
Date: Mon, 0{day} Sep 2026 1{n}:00:00 +0530
Message-ID: <camp-a-{n}@{domain}>
Received: from {relay_host} ({relay_host} [185.220.101.{ip_suffix}]) by mail.example.com; Mon, 0{day} Sep 2026 1{n}:00:00 +0530
Authentication-Results: mx.example.com; spf=fail smtp.mailfrom=alerts@{domain}; dkim=fail header.i=@{domain}; dmarc=fail header.from={domain} p=reject

Dear Customer, {body}
"""

# 5 emails, different surface brand/domain each time, but ALL sharing
# the same relay_host (nameserver-equivalent signal) on purpose.
CAMPAIGN_EMAILS = [
    {"brand": "SBI", "domain": "sbi-verify123.xyz", "subject": "Urgent: Your account will be suspended",
     "body": "click here to verify your account immediately or it will be suspended."},
    {"brand": "HDFC", "domain": "hdfc-secure456.xyz", "subject": "Action required: KYC update pending",
     "body": "your KYC has expired, click here to update it now to avoid account freeze."},
    {"brand": "ICICI", "domain": "icici-alert789.xyz", "subject": "Unusual login detected on your account",
     "body": "we detected a login from a new device, click here to secure your account."},
    {"brand": "Paytm", "domain": "paytm-kyc321.xyz", "subject": "Your wallet will be deactivated",
     "body": "complete your pending KYC now, click here to avoid wallet deactivation."},
    {"brand": "SBI", "domain": "sbi-rewards654.xyz", "subject": "You have a pending reward of Rs 5000",
     "body": "claim your reward before it expires, click here to claim now."},
]

SHARED_RELAY_HOST = "bulk-mailer-node7.cheaphost.net"  # the deliberate shared signal


def generate(out_dir):
    os.makedirs(out_dir, exist_ok=True)
    written = []
    for i, e in enumerate(CAMPAIGN_EMAILS, start=1):
        content = TEMPLATE.format(
            brand=e["brand"], domain=e["domain"], subject=e["subject"], body=e["body"],
            n=i, day=i, relay_host=SHARED_RELAY_HOST, ip_suffix=10 + i,
        )
        fname = f"campaign_a_email_{i}.eml"
        fpath = os.path.join(out_dir, fname)
        with open(fpath, "w") as f:
            f.write(content)
        written.append(fpath)
        print(f"  [ok] wrote {fpath}  (domain: {e['domain']}, shared relay: {SHARED_RELAY_HOST})")

    print(f"\n[+] Generated {len(written)} synthetic campaign emails in {out_dir}")
    print(f"[+] All 5 share Received-header relay host: {SHARED_RELAY_HOST}")
    print("    This is the signal Person 4's clustering should pick up on.")
    return written


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--out", default="../../data/synthetic_campaign")
    args = parser.parse_args()
    generate(args.out)