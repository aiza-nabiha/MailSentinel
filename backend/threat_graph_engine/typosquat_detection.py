import re


# A starter list of commonly-impersonated Indian brands, since your
# synthetic campaign data targets Indian banks/wallets. Extend this
# list with whatever brands show up in real test data as you go.
KNOWN_BRANDS = {
    # ---- Indian banks ----
    "sbi": ["sbi.co.in", "onlinesbi.com"],
    "hdfc": ["hdfcbank.com"],
    "icici": ["icicibank.com"],
    "axis": ["axisbank.com"],
    "kotak": ["kotak.com"],
    "pnb": ["pnbindia.in"],
    "bankofbaroda": ["bankofbaroda.in"],
    "yesbank": ["yesbank.in"],
    "idfcfirst": ["idfcfirstbank.com"],
    "indusind": ["indusind.com"],
    "unionbank": ["unionbankofindia.co.in"],
    "canarabank": ["canarabank.com"],

    # ---- Indian payments/wallets ----
    "paytm": ["paytm.com"],
    "phonepe": ["phonepe.com"],
    "googlepay": ["pay.google.com"],
    "mobikwik": ["mobikwik.com"],
    "cred": ["cred.club"],
    "razorpay": ["razorpay.com"],
    "bharatpe": ["bharatpe.com"],
    "upi": ["npci.org.in"],

    # ---- Indian e-commerce / services ----
    "amazon": ["amazon.in", "amazon.com"],
    "flipkart": ["flipkart.com"],
    "myntra": ["myntra.com"],
    "meesho": ["meesho.com"],
    "swiggy": ["swiggy.com"],
    "zomato": ["zomato.com"],
    "irctc": ["irctc.co.in"],
    "ola": ["olacabs.com"],
    "uber": ["uber.com"],

    # ---- Indian telecom / govt / utility ----
    "jio": ["jio.com"],
    "airtel": ["airtel.in"],
    "vi": ["myvi.in"],
    "epfo": ["epfindia.gov.in"],
    "incometax": ["incometax.gov.in"],
    "aadhaar": ["uidai.gov.in"],
    "digilocker": ["digilocker.gov.in"],
    "gst": ["gst.gov.in"],

    # ---- Global tech / platforms ----
    "google": ["google.com"],
    "microsoft": ["microsoft.com"],
    "apple": ["apple.com"],
    "facebook": ["facebook.com"],
    "instagram": ["instagram.com"],
    "linkedin": ["linkedin.com"],
    "netflix": ["netflix.com"],
    "paypal": ["paypal.com"],
    "whatsapp": ["whatsapp.com"],
    "dropbox": ["dropbox.com"],
    "adobe": ["adobe.com"],

    # ---- Global shipping / courier (common delivery-scam lures) ----
    "dhl": ["dhl.com"],
    "fedex": ["fedex.com"],
    "ups": ["ups.com"],
    "bluedart": ["bluedart.com"],
    "indiapost": ["indiapost.gov.in"],
}


def levenshtein_distance(a, b):
    """
    Minimum number of single-character edits (insert, delete,
    substitute) needed to turn string a into string b. Classic
    dynamic-programming implementation, no external library needed.
    """

    if a == b:
        return 0

    if len(a) == 0:
        return len(b)

    if len(b) == 0:
        return len(a)

    previous_row = list(range(len(b) + 1))

    for i, char_a in enumerate(a):
        current_row = [i + 1]

        for j, char_b in enumerate(b):
            insert_cost = current_row[j] + 1
            delete_cost = previous_row[j + 1] + 1
            substitute_cost = previous_row[j] + (char_a != char_b)

            current_row.append(
                min(insert_cost, delete_cost, substitute_cost)
            )

        previous_row = current_row

    return previous_row[-1]


def _split_into_chunks(domain):
    """
    Strip the TLD and split the remaining name on hyphens/underscores/
    digits, e.g. 'sbi-verify123.xyz' -> ['sbi', 'verify']. We deliberately
    do NOT guess which chunk is "the brand" here -- attacker-added words
    like 'verify' or 'rewards' are often longer than the real brand name,
    so picking "the longest chunk" would silently pick the wrong one.
    Instead every chunk gets compared against every brand in
    check_typosquat(), and the single best match across all of them wins.
    """

    domain = domain.lower()
    name_part = domain.split(".")[0]

    chunks = re.split(r'[-_0-9]+', name_part)

    return [c for c in chunks if c]


def check_typosquat(domain, brands=None):
    """
    Compare a domain against known brand names and flag close
    matches. Checks EVERY chunk of the domain name against EVERY
    known brand, and returns the single closest match found -- so
    'sbi-verify123.xyz' correctly matches on its 'sbi' chunk even
    though 'verify' is a longer chunk in the same domain.
    """

    brands = brands or KNOWN_BRANDS

    domain = domain.strip().lower()
    chunks = _split_into_chunks(domain)

    # exact legitimate domain -- not typosquatting, it's the real thing
    for brand_name, real_domains in brands.items():
        if domain in [d.lower() for d in real_domains]:
            return {
                "domain": domain,
                "is_typosquat": False,
                "matched_brand": brand_name,
                "reason": "This IS the brand's real registered domain"
            }

    best_match = None
    best_distance = None
    best_chunk = None

    for chunk in chunks:
        for brand_name in brands:
            distance = levenshtein_distance(chunk, brand_name)

            if best_distance is None or distance < best_distance:
                best_distance = distance
                best_match = brand_name
                best_chunk = chunk

    if best_match is None:
        return {
            "domain": domain,
            "is_typosquat": False,
            "matched_brand": None,
            "edit_distance": None,
            "reason": "No known brand close enough to compare against"
        }

    # threshold: distance 0 or 1 from a brand name, but NOT the real
    # domain (already handled above) -- means something like "sbii"
    # or "hdfc" used with a fake TLD/extra words
    is_typosquat = best_distance <= 1

    return {
        "domain": domain,
        "matched_chunk": best_chunk,
        "is_typosquat": is_typosquat,
        "matched_brand": best_match,
        "edit_distance": best_distance,
        "reason": (
            f"'{best_chunk}' is {best_distance} edit(s) away from "
            f"brand '{best_match}', but domain is not their real one"
            if is_typosquat else
            f"Closest brand is '{best_match}' but too different "
            f"(distance {best_distance}) to flag as typosquatting"
        )
    }


# ==================================================================
# STANDALONE TESTING
# ==================================================================

if __name__ == "__main__":
    import sys

    if len(sys.argv) > 1:
        test_domains = sys.argv[1:]
    else:
        # the domains from your actual synthetic campaign data
        test_domains = [
            "sbi-verify123.xyz",
            "hdfc-secure456.xyz",
            "icici-alert789.xyz",
            "paytm-kyc321.xyz",
            "sbi-rewards654.xyz",
            "sbi.co.in",
            "google.com",
        ]

    for domain in test_domains:
        result = check_typosquat(domain)
        print(f"\n{domain}")
        print(f"  is_typosquat: {result['is_typosquat']}")
        print(f"  matched_brand: {result['matched_brand']}")
        print(f"  reason: {result['reason']}")