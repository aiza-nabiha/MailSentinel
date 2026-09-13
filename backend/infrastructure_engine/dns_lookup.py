import dns.resolver
import tldextract

# Use a bundled/cached suffix list instead of fetching from
# publicsuffix.org on every run -- avoids a slow network call (or
# outright failure, e.g. if that site rate-limits or blocks you)
# in the middle of a live demo. Falls back to tldextract's built-in
# snapshot automatically if this can't reach the network either.
_extract = tldextract.TLDExtract(cache_dir=None, suffix_list_urls=())
from concurrent.futures import ThreadPoolExecutor, as_completed

RECORD_TYPES = ["A", "AAAA", "CNAME", "MX", "NS", "TXT", "SOA", "CAA", "SRV"]

def resolve_record(domain, record_type):
    resolver = dns.resolver.Resolver()
    resolver.timeout = 2
    resolver.lifetime = 3
    try:
        answers = resolver.resolve(domain, record_type)
        return record_type, [str(a) for a in answers]
    except Exception:
        return record_type, []

def get_dns_records(domain):
    result = {"domain": domain, "records": {}}
    with ThreadPoolExecutor(max_workers=len(RECORD_TYPES)) as executor:
        futures = [executor.submit(resolve_record, domain, rt) for rt in RECORD_TYPES]
        for future in as_completed(futures):
            record_type, records = future.result()
            if records:
                result["records"][record_type] = records
    return result

def get_registrable_domain(domain):
    extracted = _extract(domain)
    if not extracted.domain or not extracted.suffix:
        return None
    return f"{extracted.domain}.{extracted.suffix}".lower()