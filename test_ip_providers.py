
import json
from dotenv import load_dotenv

load_dotenv()

from backend.infrastructure_engine.ip_intelligence import (
    investigate_ip,
    IPINFO_TOKEN,
    ABUSEIPDB_API_KEY,
)

TEST_IP = "8.8.8.8"

# Empty cache forces a fresh lookup for this test.
cache = {}

result = investigate_ip(
    TEST_IP,
    cache,
    IPINFO_TOKEN,
    ABUSEIPDB_API_KEY,
)

print("\n========== COMBINED IP INTELLIGENCE ==========")
print(json.dumps(result, indent=2, default=str))

print("\n========== PROVIDER STATUS ==========")

for key in ("ipinfo", "ipapi_is", "iplocate", "reputation"):
    provider = result.get(key) or {}
    print(
        f"{key}: "
        f"status={provider.get('status')}, "
        f"source={provider.get('source')}, "
        f"error={provider.get('error', 'None')}"
    )
