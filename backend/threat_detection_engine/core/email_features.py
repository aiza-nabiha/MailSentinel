import re
import ipaddress

from urllib.parse import urlparse, parse_qs, unquote


# ==========================================================
# CONSTANTS
# ==========================================================

URL_SHORTENERS = {
    "bit.ly",
    "tinyurl.com",
    "t.co",
    "goo.gl",
    "ow.ly",
    "is.gd",
    "buff.ly",
    "rebrand.ly",
    "cutt.ly",
    "shorturl.at",
    "tiny.cc",
    "rb.gy",
    "lnkd.in",
    "s.id",
    "short.io",
    "bl.ink",
    "soo.gd",
    "v.gd",
    "qr.ae",
    "adf.ly",
}

TRACKING_PARAMETERS = {
    "utm_source",
    "utm_medium",
    "utm_campaign",
    "utm_term",
    "utm_content",
    "gclid",
    "dclid",
    "fbclid",
    "msclkid",
    "mc_cid",
    "mc_eid",
    "trk",
    "tracking",
    "tracking_id",
    "vero_id",
    "oly_anon_id",
    "oly_enc_id",
    "mkt_tok",
    "igshid",
    "ref_src",
}

REDIRECT_PARAMETERS = {
    "url",
    "target",
    "redirect",
    "redirect_url",
    "redirect_uri",
    "redirect_to",
    "continue",
    "next",
    "dest",
    "destination",
    "return",
    "return_url",
    "returnto",
    "out",
    "link",
    "to",
    "u",
}

TRACKING_PATH_PATTERNS = [
    re.compile(r"/track(?:ing)?(?:/|$)", re.I),
    re.compile(r"/click(?:/|$)", re.I),
    re.compile(r"/open(?:/|$)", re.I),
    re.compile(r"/pixel(?:/|$)", re.I),
    re.compile(r"/beacon(?:/|$)", re.I),
    re.compile(r"/collect(?:/|$)", re.I),
    re.compile(r"/analytics(?:/|$)", re.I),
    re.compile(r"/imp(?:/|$)", re.I),
]

URGENCY_KEYWORDS = {
    "urgent",
    "immediately",
    "immediate",
    "act now",
    "verify now",
    "action required",
    "account suspended",
    "account suspension",
    "account will be closed",
    "limited time",
    "expire",
    "expired",
    "expires",
    "final warning",
    "final notice",
    "within 24 hours",
    "within 48 hours",
    "as soon as possible",
    "important notice",
    "unusual activity",
    "security alert",
    "avoid suspension",
    "respond immediately",
    "time sensitive",
    "time-sensitive",
    "failure to respond",
}

CREDENTIAL_KEYWORDS = {
    "password",
    "login",
    "log in",
    "sign in",
    "signin",
    "verify your account",
    "confirm your account",
    "account verification",
    "credentials",
    "username",
    "authentication",
    "two factor",
    "two-factor",
    "2fa",
    "one time password",
    "one-time password",
    "otp",
    "security code",
    "reset your password",
    "update your password",
    "validate your account",
    "confirm your identity",
    "bank account details",
    "credit card details",
}

FINANCIAL_KEYWORDS = {
    "payment",
    "invoice",
    "bank",
    "banking",
    "wire transfer",
    "transfer funds",
    "transaction",
    "refund",
    "billing",
    "billing information",
    "credit card",
    "debit card",
    "wallet",
    "cryptocurrency",
    "crypto",
    "bitcoin",
    "ethereum",
    "investment",
    "prize money",
    "tax refund",
    "account balance",
    "financial information",
    "gift card",
}

ATTACHMENT_KEYWORDS = {
    "attached file",
    "attachment",
    "open the attachment",
    "download the attachment",
    "attached document",
    "attached invoice",
    "see attached",
    "please find attached",
    "enable macros",
    "enable content",
    "open the document",
    "download the document",
}

EMAIL_PATTERN = re.compile(
    r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b",
    re.IGNORECASE,
)

URL_PATTERN = re.compile(
    r"""(?ix)
    (?:
        https?://
        |
        www\.
    )
    [^\s<>"']+
    """
)


# ==========================================================
# BASIC HELPERS
# ==========================================================

def _safe_text(value):
    if value is None:
        return ""

    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")

    return str(value)


def _normalize_domain(domain):
    domain = _safe_text(domain).strip().lower()

    if domain.startswith("www."):
        domain = domain[4:]

    return domain.rstrip(".")


def _get_domain(url):
    """
    Extract the hostname from a URL.

    Handles protocol-relative and www URLs.
    """

    if not url:
        return ""

    url = _safe_text(url).strip()

    if url.startswith("//"):
        url = "http:" + url

    elif url.lower().startswith("www."):
        url = "http://" + url

    elif not re.match(r"^[a-z][a-z0-9+.-]*://", url, re.I):
        return ""

    try:
        parsed = urlparse(url)
        hostname = parsed.hostname or ""

        return _normalize_domain(hostname)

    except Exception:
        return ""


def _is_ip_address(domain):
    if not domain:
        return False

    try:
        ipaddress.ip_address(domain.strip("[]"))
        return True

    except ValueError:
        return False


def _count_keyword_matches(text, keywords):
    """
    Count keyword occurrences case-insensitively.

    Phrase matching uses escaped keyword patterns and
    avoids matching words inside larger words.
    """

    text = _safe_text(text).lower()

    count = 0

    for keyword in keywords:
        keyword = keyword.lower().strip()

        if not keyword:
            continue

        pattern = (
            r"(?<!\w)"
            + re.escape(keyword)
            + r"(?!\w)"
        )

        count += len(
            re.findall(pattern, text, flags=re.IGNORECASE)
        )

    return count


def _deduplicate_urls(urls):
    results = []
    seen = set()

    for url in urls or []:
        url = _safe_text(url).strip()

        if not url:
            continue

        url = url.rstrip(".,;:!?")

        normalized = url.lower()

        if normalized in seen:
            continue

        seen.add(normalized)
        results.append(url)

    return results


def _extract_urls_from_text(text):
    text = _safe_text(text)

    results = []

    for match in URL_PATTERN.findall(text):
        url = match.rstrip(".,;:!?")

        if url:
            results.append(url)

    return _deduplicate_urls(results)


# ==========================================================
# URL ANALYSIS
# ==========================================================

def analyze_single_url(url):
    """
    Analyze a single URL.

    Returns the existing URL intelligence fields.
    """

    url = _safe_text(url).strip()

    parsed_url = url

    if parsed_url.startswith("//"):
        parsed_url = "http:" + parsed_url

    elif parsed_url.lower().startswith("www."):
        parsed_url = "http://" + parsed_url

    domain = _get_domain(parsed_url)

    try:
        parsed = urlparse(parsed_url)
    except Exception:
        parsed = urlparse("")

    query_params = parse_qs(
        parsed.query,
        keep_blank_values=True,
    )

    normalized_query_names = {
        name.lower()
        for name in query_params.keys()
    }

    tracking_parameters = sorted(
        normalized_query_names & TRACKING_PARAMETERS
    )

    redirect_parameters = sorted(
        normalized_query_names & REDIRECT_PARAMETERS
    )

    # ------------------------------------------------------
    # Shortener detection
    # ------------------------------------------------------

    is_shortener = int(
        domain in URL_SHORTENERS
    )

    # ------------------------------------------------------
    # IP-based URL detection
    # ------------------------------------------------------

    ip_based = int(
        _is_ip_address(domain)
    )

    # ------------------------------------------------------
    # Tracking detection
    # ------------------------------------------------------

    path = unquote(parsed.path or "").lower()

    tracking_path = any(
        pattern.search(path)
        for pattern in TRACKING_PATH_PATTERNS
    )

    tracking = int(
        bool(tracking_parameters or tracking_path)
    )

    # ------------------------------------------------------
    # Redirect detection
    # ------------------------------------------------------

    redirect = int(
        bool(redirect_parameters)
    )

    # ------------------------------------------------------
    # Long URL detection
    # ------------------------------------------------------

    long_url = int(
        len(url) >= 150
    )

    # ------------------------------------------------------
    # Return analysis
    # ------------------------------------------------------

    return {
        "url": url,
        "domain": domain,
        "ip_based": ip_based,
        "shortener": is_shortener,
        "long_url": long_url,
        "tracking": tracking,
        "redirect": redirect,
        "tracking_parameters": tracking_parameters,
        "redirect_parameters": redirect_parameters,
    }


# ==========================================================
# MULTIPLE URL ANALYSIS
# ==========================================================

def analyze_urls(urls):
    """
    Analyze all supplied URLs.

    Returns aggregate counts and individual details.
    """

    urls = _deduplicate_urls(urls)

    details = []

    for url in urls:
        try:
            details.append(
                analyze_single_url(url)
            )

        except Exception:
            continue

    return {
        "url_count": len(details),

        "ip_url_count": sum(
            item["ip_based"]
            for item in details
        ),

        "shortener_count": sum(
            item["shortener"]
            for item in details
        ),

        "long_url_count": sum(
            item["long_url"]
            for item in details
        ),

        "tracking_url_count": sum(
            item["tracking"]
            for item in details
        ),

        "redirect_url_count": sum(
            item["redirect"]
            for item in details
        ),

        "url_details": details,
    }


# ==========================================================
# HTML LINK MISMATCH
# ==========================================================

def _extract_display_domain(display_text):
    """
    Extract a domain from displayed anchor text.

    Only treats display text as a URL when it resembles
    a URL or hostname.
    """

    display_text = _safe_text(display_text).strip()

    if not display_text:
        return ""

    display_text = display_text.strip(
        " \t\r\n<>[](){}.,;:!?"
    )

    if not display_text:
        return ""

    # Avoid interpreting ordinary sentences as domains.
    if " " in display_text:
        return ""

    if "@" in display_text:
        return ""

    if not (
        display_text.lower().startswith(
            ("http://", "https://", "www.")
        )
        or re.match(
            r"^[a-z0-9-]+(?:\.[a-z0-9-]+)+(?::\d+)?(?:/|$)",
            display_text,
            re.I,
        )
    ):
        return ""

    domain = _get_domain(display_text)

    return domain


def _count_link_mismatches(html_links):
    """
    Count anchor links where displayed URL domain differs
    from the actual href domain.

    Non-URL display text is not considered a mismatch.
    """

    mismatch_count = 0

    for link in html_links or []:
        if not isinstance(link, dict):
            continue

        href = _safe_text(
            link.get("href", "")
        ).strip()

        display_text = _safe_text(
            link.get("display_text", "")
        ).strip()

        actual_domain = _get_domain(href)

        displayed_domain = _extract_display_domain(
            display_text
        )

        if not actual_domain or not displayed_domain:
            continue

        if actual_domain != displayed_domain:
            mismatch_count += 1

    return mismatch_count


# ==========================================================
# MAIN EMAIL FEATURE EXTRACTION
# ==========================================================

def extract_email_features(
    subject="",
    body="",
    urls=None,
    attachments=None,
    html_source="",
    mailto_links=None,
    html_links=None,
):
    """
    Extract numerical and descriptive email features.

    IMPORTANT:
    Numeric ML feature names are preserved for the
    existing trained classifier.
    """

    subject = _safe_text(subject)
    body = _safe_text(body)
    html_source = _safe_text(html_source)

    combined_text = (
        subject + "\n" + body
    )

    text_lower = combined_text.lower()

    # ------------------------------------------------------
    # URL extraction
    # ------------------------------------------------------

    extracted_text_urls = _extract_urls_from_text(
        combined_text
    )

    provided_urls = list(urls or [])

    # Merge provided URLs and text-extracted URLs.
    # This handles callers that pass urls=[].
    all_urls = _deduplicate_urls(
        provided_urls + extracted_text_urls
    )

    url_analysis = analyze_urls(all_urls)

    # ------------------------------------------------------
    # Attachment information
    # ------------------------------------------------------

    attachments = attachments or []

    attachment_count = len(attachments)

    # ------------------------------------------------------
    # Email address and mailto extraction
    # ------------------------------------------------------

    email_addresses = EMAIL_PATTERN.findall(
        combined_text
    )

    mailto_links = list(mailto_links or [])

    extracted_mailto = _extract_urls_from_text(
        ""
    )

    # Explicit mailto extraction from content.
    mailto_pattern = re.compile(
        r"""(?i)mailto:[^\s<>"']+"""
    )

    for match in mailto_pattern.findall(
        combined_text + "\n" + html_source
    ):
        mailto_links.append(
            match.rstrip(".,;:!?")
        )

    mailto_links = _deduplicate_urls(
        mailto_links
    )

    # ------------------------------------------------------
    # HTML links
    # ------------------------------------------------------

    html_links = html_links or []

    link_mismatch_count = _count_link_mismatches(
        html_links
    )

    # ------------------------------------------------------
    # HTML tag count
    # ------------------------------------------------------

    html_tag_count = len(
        re.findall(
            r"<[a-zA-Z][^>]*>",
            html_source,
        )
    )

    html_part_present = int(
        bool(html_source.strip())
    )

    # ------------------------------------------------------
    # Text length and word count
    # ------------------------------------------------------

    text_length = len(combined_text)

    words = re.findall(
        r"\b\w+\b",
        combined_text,
        flags=re.UNICODE,
    )

    word_count = len(words)

    # ------------------------------------------------------
    # Digits, uppercase, punctuation
    # ------------------------------------------------------

    digit_count = sum(
        character.isdigit()
        for character in combined_text
    )

    letters = [
        character
        for character in combined_text
        if character.isalpha()
    ]

    uppercase_count = sum(
        character.isupper()
        for character in letters
    )

    uppercase_ratio = (
        uppercase_count / len(letters)
        if letters
        else 0.0
    )

    exclamation_count = combined_text.count("!")
    question_count = combined_text.count("?")

    # ------------------------------------------------------
    # Keyword indicators
    # ------------------------------------------------------

    urgency_count = _count_keyword_matches(
        text_lower,
        URGENCY_KEYWORDS,
    )

    credential_count = _count_keyword_matches(
        text_lower,
        CREDENTIAL_KEYWORDS,
    )

    financial_count = _count_keyword_matches(
        text_lower,
        FINANCIAL_KEYWORDS,
    )

    attachment_language_count = _count_keyword_matches(
        text_lower,
        ATTACHMENT_KEYWORDS,
    )

    # ------------------------------------------------------
    # Non-ASCII characters
    # ------------------------------------------------------

    non_ascii_count = sum(
        ord(character) > 127
        for character in combined_text
    )

    # ------------------------------------------------------
    # Preserve established numeric feature names
    # ------------------------------------------------------

    features = {
        "text_length": text_length,
        "word_count": word_count,

        "url_count": url_analysis["url_count"],
        "ip_url_count": url_analysis["ip_url_count"],
        "shortener_count": url_analysis["shortener_count"],
        "long_url_count": url_analysis["long_url_count"],
        "tracking_url_count": url_analysis["tracking_url_count"],
        "redirect_url_count": url_analysis["redirect_url_count"],

        "url_details": url_analysis["url_details"],

        "mailto_count": len(mailto_links),
        "email_count": len(set(
            address.lower()
            for address in email_addresses
        )),

        "html_tag_count": html_tag_count,
        "html_part_present": html_part_present,

        "link_mismatch_count": link_mismatch_count,

        "digit_count": digit_count,
        "uppercase_ratio": uppercase_ratio,

        "exclamation_count": exclamation_count,
        "question_count": question_count,

        "urgency_count": urgency_count,
        "credential_count": credential_count,

        "attachment_count": attachment_count,
        "attachment_language_count": attachment_language_count,

        "financial_count": financial_count,
        "non_ascii_count": non_ascii_count,
    }

    return features