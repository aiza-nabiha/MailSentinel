"""
backend/storage_engine/diagnose_pipeline.py

Run this ONCE to find every missing package Person 3's pipeline
needs, instead of installing one at a time and re-running to find
the next error. Doesn't touch the network -- just tries to import
every module in infrastructure_engine and reports what's missing.

Usage (from backend/storage_engine/):
    python3 diagnose_pipeline.py
"""

import importlib
import sys
from pathlib import Path

INFRA_DIR = Path(__file__).parent.parent / "infrastructure_engine"
sys.path.append(str(INFRA_DIR))

# Every .py file in infrastructure_engine, based on your file explorer screenshot
MODULES_TO_CHECK = [
    "analyzer", "dns_lookup", "domain_extract", "domain_reputation",
    "hop_analyzer", "infrastructure_analyzer", "ip_intelligence",
    "pipeline", "risk_scorer", "threat_intelligence", "tls_lookup",
    "whois_lookup",
]

missing_packages = set()
broken_modules = []
working_modules = []

if not INFRA_DIR.exists():
    print(f"[!] {INFRA_DIR} does not exist -- run this from backend/storage_engine/")
    sys.exit(1)

print(f"[*] Checking modules in {INFRA_DIR}\n")

for mod_name in MODULES_TO_CHECK:
    mod_path = INFRA_DIR / f"{mod_name}.py"
    if not mod_path.exists():
        print(f"  [--] {mod_name}.py -- file doesn't exist yet, skipping")
        continue
    try:
        importlib.import_module(mod_name)
        print(f"  [OK] {mod_name}.py imports cleanly")
        working_modules.append(mod_name)
    except ModuleNotFoundError as e:
        pkg = str(e).split("'")[1] if "'" in str(e) else str(e)
        missing_packages.add(pkg)
        broken_modules.append((mod_name, str(e)))
        print(f"  [!!] {mod_name}.py -- MISSING PACKAGE: {pkg}")
    except Exception as e:
        broken_modules.append((mod_name, str(e)))
        print(f"  [!!] {mod_name}.py -- OTHER ERROR: {e}")

print("\n" + "=" * 60)
if missing_packages:
    # Map common import names to their actual pip package names
    PIP_NAME_MAP = {
        "dns": "dnspython",
        "whois": "python-whois",
        "OpenSSL": "pyOpenSSL",
        "requests": "requests",
        "tldextract": "tldextract",
        "cryptography": "cryptography",
    }
    pip_names = [PIP_NAME_MAP.get(p, p) for p in missing_packages]
    print("MISSING PACKAGES FOUND. Run this single command:\n")
    print(f"  pip3 install {' '.join(sorted(set(pip_names)))}")
else:
    print("No missing packages detected.")

if broken_modules:
    print(f"\n{len(broken_modules)} module(s) still have issues after checking imports:")
    for name, err in broken_modules:
        print(f"  - {name}: {err}")

print(f"\n{len(working_modules)}/{len(MODULES_TO_CHECK)} modules import cleanly right now.")