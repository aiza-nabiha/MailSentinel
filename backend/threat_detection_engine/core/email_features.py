import re

from urllib.parse import urlparse, parse_qs


URL_SHORTENERS = {
    "bit.ly",
    "tinyurl.com",
    "t.co",
    "goo.gl",
    "ow.ly",
    "is.gd",
    "buff.ly",
    "cutt.ly",
    "rb.gy",
    "shorturl.at",
}


TRACKING_PARAMETERS = {
    "utm_source",
    "utm_medium",
    "utm_campaign",
    "utm_term",
    "utm_content",
    "utm_id",
    "gclid",
    "dclid",
    "fbclid",
    "msclkid",
    "mc_cid",
    "mc_eid",
    "mkt_tok",
    "vero_id",
    "oly_enc_id",
    "oly_anon_id",
}


REDIRECT_PARAMETERS = {
    "url",
    "u",
    "redirect",
    "redirect_url",
    "redirect_uri",
    "redir",
    "destination",
    "dest",
    "target",
    "next",
    "return",
    "return_url",
    "continue",
    "link",
}


TRACKING_PATH_PATTERNS = [
    r"/track(?:ing)?/",
    r"/click/",
    r"/clickthrough/",
    r"/redirect/",
    r"/redir/",
    r"/unsubscribe/",
    r"/open/",
    r"/pixel/",
    r"/beacon/",
]


URGENCY_PATTERNS = [
    r"\burgent\b",
    r"\bimmediately\b",
    r"\basap\b",
    r"\baction required\b",
    r"\bact now\b",
    r"\bfinal notice\b",
    r"\bexpires?\b",
    r"\baccount.{0,20}suspend",
    r"\baccount.{0,20}terminat",
    r"\bwithin\s+\d+\s+(?:hour|hours|day|days)\b",
]


CREDENTIAL_PATTERNS = [
    r"\bpassword\b",
    r"\busername\b",
    r"\bverify\b",
    r"\bverification\b",
    r"\bconfirm\b",
    r"\baccount\b",
    r"\blogin\b",
    r"\blog\s+in\b",
    r"\bsign\s+in\b",
    r"\bcredentials?\b",
    r"\bsecurity.{0,30}verification\b",
    r"\bidentity\b",
    r"\bsecurity\s+check\b",
    r"\bupdate.{0,30}(account|information|details)\b",
    r"\bconfirm.{0,30}(account|information|details)\b",
]


ATTACHMENT_PATTERNS = [
    r"\battachment\b",
    r"\battached\b",
    r"\bdownload.{0,30}file\b",
    r"\bopen.{0,20}attachment\b",
    r"\bsee.{0,20}attachment\b",
    r"\bfile\b",
    r"\bdocument\b",
    r"\banexo\b",
    r"\badjunto\b",
]


FINANCIAL_PATTERNS = [
    r"\bpayment\b",
    r"\bpay\b",
    r"\binvoice\b",
    r"\bbilling\b",
    r"\btransaction\b",
    r"\btransfer\b",
    r"\bbank\b",
    r"\bcredit\s+card\b",
    r"\bdebit\s+card\b",
    r"\brefund\b",
    r"\bwallet\b",
    r"\bcrypto(?:currency)?\b",
    r"\bbinance\b",
    r"\bcpf\b",
    r"\bcnpj\b",
    r"\bimposto\b",
    r"\bfatura\b",
    r"\bpagamento\b",
    r"\btransação\b",
    r"\btransferência\b",
    r"\bbanco\b",
    r"\bcartão\b",
]


def count_matches(text, patterns):

    count = 0

    for pattern in patterns:

        count += len(
            re.findall(
                pattern,
                text,
                re.IGNORECASE
            )
        )

    return count


def extract_urls(text):

    if not text:
        return []

    return re.findall(
        r"https?://[^\s<>'\"]+|www\.[^\s<>'\"]+",
        str(text),
        re.IGNORECASE
    )


def is_ip_address(hostname):

    if not hostname:
        return False

    hostname = hostname.split(":")[0]

    return bool(
        re.fullmatch(
            r"(?:\d{1,3}\.){3}\d{1,3}",
            hostname
        )
    )

def looks_like_redirect_target(value):
    if not value:
        return False

    value = str(value).strip()

    if re.search(
        r"https?://",
        value,
        re.IGNORECASE
    ):
        return True

    if re.search(
        r"^//[^/]+",
        value
    ):
        return True

    if re.search(
        r"www\.[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}",
        value,
        re.IGNORECASE
    ):
        return True

    return False

def analyze_single_url(url):

    candidate = url

    if candidate.lower().startswith("www."):
        candidate = "http://" + candidate

    result = {
        "url": url,
        "domain": "",
        "ip_based": False,
        "shortener": False,
        "long_url": len(url) >= 150,
        "tracking": False,
        "redirect": False,
        "tracking_parameters": [],
        "redirect_parameters": []
    }

    try:

        parsed = urlparse(candidate)

    except ValueError:

        return result

    try:

        hostname = parsed.hostname

    except ValueError:

        hostname = None

    if hostname:

        hostname = hostname.lower()

        result["domain"] = hostname

        result["ip_based"] = is_ip_address(
            hostname
        )

        result["shortener"] = (
            hostname in URL_SHORTENERS
        )

    query_parameters = set()

    try:

        parsed_query = parse_qs(
            parsed.query,
            keep_blank_values=True
        )

        query_parameters = {
            key.lower()
            for key in parsed_query.keys()
        }

    except Exception:

        query_parameters = set()

    tracking_parameters = (
        query_parameters
        .intersection(
            TRACKING_PARAMETERS
        )
    )

    redirect_parameters = []

    for parameter in REDIRECT_PARAMETERS:
        if parameter not in parsed_query:
            continue

        values = parsed_query.get(
            parameter,
            []
        )

        if any(
            looks_like_redirect_target(value)
            for value in values
        ):
            redirect_parameters.append(
                parameter
            )

    result["tracking_parameters"] = sorted(
        tracking_parameters
    )

    result["redirect_parameters"] = sorted(
        redirect_parameters
    )

    result["tracking"] = bool(
        tracking_parameters
    )

    result["redirect"] = bool(
        redirect_parameters
    )

    path = parsed.path.lower()

    if any(
        re.search(
            pattern,
            path,
            re.IGNORECASE
        )
        for pattern in TRACKING_PATH_PATTERNS
    ):

        result["tracking"] = True

    return result


def analyze_urls(urls):

    ip_url_count = 0
    shortener_count = 0
    long_url_count = 0
    tracking_url_count = 0
    redirect_url_count = 0

    url_details = []

    for url in urls:

        detail = analyze_single_url(
            url
        )

        url_details.append(
            detail
        )

        if detail["ip_based"]:
            ip_url_count += 1

        if detail["shortener"]:
            shortener_count += 1

        if detail["long_url"]:
            long_url_count += 1

        if detail["tracking"]:
            tracking_url_count += 1

        if detail["redirect"]:
            redirect_url_count += 1

    return {
        "ip_url_count":
            ip_url_count,

        "shortener_count":
            shortener_count,

        "long_url_count":
            long_url_count,

        "tracking_url_count":
            tracking_url_count,

        "redirect_url_count":
            redirect_url_count,

        "url_details":
            url_details,
    }


def extract_domain(url):

    if not url:
        return ""

    try:

        candidate = url

        if candidate.lower().startswith("www."):
            candidate = "http://" + candidate

        parsed = urlparse(candidate)

        if not parsed.netloc:
            return ""

        return (
            parsed.netloc
            .lower()
            .split("@")[-1]
            .split(":")[0]
        )

    except Exception:

        return ""


def normalize_domain(domain):

    if not domain:
        return ""

    domain = domain.lower().strip()

    if domain.startswith("www."):

        domain = domain[4:]

    return domain


def extract_displayed_url_domain(display_text):

    if not display_text:
        return ""

    match = re.search(
        r"(?:https?://|www\.)"
        r"([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})",
        display_text,
        re.IGNORECASE
    )

    if match:

        return normalize_domain(
            match.group(1)
        )

    return ""


def count_link_mismatches(html_links):

    mismatch_count = 0

    for link in html_links:

        href = link.get(
            "href",
            ""
        )

        display_text = link.get(
            "display_text",
            ""
        )

        actual_domain = normalize_domain(
            extract_domain(href)
        )

        displayed_domain = extract_displayed_url_domain(
            display_text
        )

        if (
            actual_domain
            and displayed_domain
            and actual_domain != displayed_domain
        ):

            mismatch_count += 1

    return mismatch_count


def count_mailto_links(text):

    if not text:
        return 0

    return len(
        re.findall(
            r"mailto:",
            str(text),
            re.IGNORECASE
        )
    )


def count_unicode_non_ascii(text):

    if not text:
        return 0

    return sum(
        1
        for character in str(text)
        if ord(character) > 127
    )


def extract_email_features(
    text,
    urls=None,
    attachments=None,
    html_source="",
    mailto_links=None,
    html_links=None
):

    text = str(text)

    lower_text = text.lower()

    words = re.findall(
        r"\b\w+\b",
        text
    )

    word_count = len(words)

    if urls is None:

        urls = extract_urls(
            text
        )

    if attachments is None:

        attachments = []

    if mailto_links is None:

        mailto_links = []

    if html_links is None:

        html_links = []

    url_analysis = analyze_urls(
        urls
    )

    email_count = len(
        re.findall(
            r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b",
            text
        )
    )

    html_count = len(
        re.findall(
            r"<(?:html|body|a|form|script|iframe)\b",
            text,
            re.IGNORECASE
        )
    )

    digit_count = sum(
        character.isdigit()
        for character in text
    )

    uppercase_count = sum(
        character.isupper()
        for character in text
    )

    alphabetic_count = sum(
        character.isalpha()
        for character in text
    )

    uppercase_ratio = (
        uppercase_count / alphabetic_count
        if alphabetic_count > 0
        else 0
    )

    return {
        "text_length":
            len(text),

        "word_count":
            word_count,

        "url_count":
            len(urls),

        "ip_url_count":
            url_analysis["ip_url_count"],

        "shortener_count":
            url_analysis["shortener_count"],

        "long_url_count":
            url_analysis["long_url_count"],

        "tracking_url_count":
            url_analysis["tracking_url_count"],

        "redirect_url_count":
            url_analysis["redirect_url_count"],

        "url_details":
            url_analysis["url_details"],

        "mailto_count":
            len(mailto_links),

        "email_count":
            email_count,

        "html_tag_count":
            html_count,

        "html_part_present":
            int(bool(html_source)),

        "link_mismatch_count":
            count_link_mismatches(
                html_links
            ),

        "digit_count":
            digit_count,

        "uppercase_ratio":
            uppercase_ratio,

        "exclamation_count":
            text.count("!"),

        "question_count":
            text.count("?"),

        "urgency_count":
            count_matches(
                lower_text,
                URGENCY_PATTERNS
            ),

        "credential_count":
            count_matches(
                lower_text,
                CREDENTIAL_PATTERNS
            ),

        "attachment_count":
            len(attachments),

        "attachment_language_count":
            count_matches(
                lower_text,
                ATTACHMENT_PATTERNS
            ),

        "financial_count":
            count_matches(
                lower_text,
                FINANCIAL_PATTERNS
            ),

        "non_ascii_count":
            count_unicode_non_ascii(
                text
            ),
    }