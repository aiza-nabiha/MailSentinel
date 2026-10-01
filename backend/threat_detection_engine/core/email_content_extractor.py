import re

from html import unescape
from email import policy
from email.parser import BytesParser
from email.utils import parseaddr
from html.parser import HTMLParser

from .text_cleaner import html_to_visible_text


# ==========================================================
# URL CLEANING
# ==========================================================

def clean_url_candidate(url):
    """
    Clean common wrappers and punctuation around URLs.

    Preserve query parameters and fragments.
    Remove only unmatched closing brackets and trailing
    punctuation.
    """

    if not url:
        return ""

    url = unescape(str(url)).strip()
    url = url.strip("<>")

    # Remove common trailing punctuation.
    url = url.rstrip(".,;:!?")

    # Remove unmatched closing brackets.
    pairs = [
        ("(", ")"),
        ("[", "]"),
        ("{", "}"),
    ]

    for opening, closing in pairs:
        while (
            url.endswith(closing)
            and url.count(closing) > url.count(opening)
        ):
            url = url[:-1]

    return url.strip()


def normalize_url_for_dedup(url):
    """
    Normalize URL for duplicate detection only.

    The original URL is retained in the output.
    """

    return str(url or "").strip().lower()


def is_http_or_www_url(url):
    """
    Check whether a URL is an HTTP(S), protocol-relative,
    or www URL.
    """

    if not url:
        return False

    value = str(url).strip().lower()

    return value.startswith(
        (
            "http://",
            "https://",
            "www.",
            "//",
        )
    )


# ==========================================================
# HTML LINK PARSER
# ==========================================================

class LinkParser(HTMLParser):
    """
    Extract anchor href and visible text.

    Output structure:
    [
        {
            "href": "...",
            "display_text": "..."
        }
    ]
    """

    def __init__(self):
        super().__init__(convert_charrefs=True)

        self.links = []
        self.current_href = None
        self.current_text = []
        self.anchor_depth = 0

    def handle_starttag(self, tag, attrs):
        tag = tag.lower()

        if tag != "a":
            return

        attributes = dict(attrs)

        href = attributes.get("href", "")

        # Start collecting only for the outer anchor.
        if self.anchor_depth == 0:
            self.current_href = unescape(
                str(href or "")
            ).strip()

            self.current_text = []

        self.anchor_depth += 1

    def handle_data(self, data):
        if self.anchor_depth > 0:
            self.current_text.append(data)

    def handle_endtag(self, tag):
        if tag.lower() != "a":
            return

        if self.anchor_depth == 0:
            return

        self.anchor_depth -= 1

        # Finalize only when the outer anchor closes.
        if self.anchor_depth == 0:
            if self.current_href:
                display_text = " ".join(
                    "".join(self.current_text).split()
                )

                self.links.append(
                    {
                        "href": self.current_href,
                        "display_text": display_text,
                    }
                )

            self.current_href = None
            self.current_text = []


# ==========================================================
# HTML LINK EXTRACTION
# ==========================================================

def extract_html_links(html_source):
    """
    Extract anchor href and visible text.
    """

    if not html_source:
        return []

    parser = LinkParser()

    try:
        parser.feed(str(html_source))
        parser.close()
    except Exception:
        return []

    return parser.links


# ==========================================================
# URL EXTRACTION
# ==========================================================

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


def extract_urls(text):
    """
    Extract URLs from plain text.

    Supports:
      - http://
      - https://
      - www.

    Removes trailing punctuation and deduplicates
    while preserving original order.
    """

    if not text:
        return []

    text = unescape(str(text))

    matches = URL_PATTERN.findall(text)

    urls = []
    seen = set()

    for match in matches:
        url = clean_url_candidate(match)

        if not url:
            continue

        normalized = normalize_url_for_dedup(url)

        if normalized in seen:
            continue

        seen.add(normalized)
        urls.append(url)

    return urls


# ==========================================================
# MAILTO LINK EXTRACTION
# ==========================================================

MAILTO_PATTERN = re.compile(
    r"""(?i)
    mailto:
    [^\s<>"']+
    """
)


def extract_mailto_links(text):
    """
    Extract unique mailto links from text.
    """

    if not text:
        return []

    text = unescape(str(text))

    matches = MAILTO_PATTERN.findall(text)

    results = []
    seen = set()

    for link in matches:
        link = clean_url_candidate(link)

        if not link:
            continue

        normalized = normalize_url_for_dedup(link)

        if normalized in seen:
            continue

        seen.add(normalized)
        results.append(link)

    return results


# ==========================================================
# SENDER FEATURES
# ==========================================================

def extract_sender_features(message):
    """
    Extract sender metadata and basic domain mismatches.

    A mismatch is a metadata observation, not proof
    of malicious activity.
    """

    from_header = message.get("From", "")
    reply_to_header = message.get("Reply-To", "")
    return_path_header = message.get("Return-Path", "")

    # ------------------------------------------------------
    # Parse headers
    # ------------------------------------------------------

    from_display_name, from_address = parseaddr(
        str(from_header)
    )

    _, reply_to_address = parseaddr(
        str(reply_to_header)
    )

    _, return_path_address = parseaddr(
        str(return_path_header)
    )

    # ------------------------------------------------------
    # Fallback for malformed From header
    # ------------------------------------------------------

    if not from_address:
        match = re.search(
            r"<([^<>@\s]+@[^<>\s]+)>",
            str(from_header),
        )

        if match:
            from_address = match.group(1)

    # ------------------------------------------------------
    # Extract domains
    # ------------------------------------------------------

    def get_domain(address):
        if not address or "@" not in address:
            return ""

        domain = address.rsplit("@", 1)[1]
        domain = domain.lower().strip()

        return domain.rstrip(".")

    from_domain = get_domain(from_address)
    reply_to_domain = get_domain(reply_to_address)
    return_path_domain = get_domain(return_path_address)

    # ------------------------------------------------------
    # Return sender metadata
    # ------------------------------------------------------

    return {
        "from_display_name": from_display_name,
        "from_address": from_address,
        "from_domain": from_domain,

        "reply_to_address": reply_to_address,
        "reply_to_domain": reply_to_domain,

        "return_path_address": return_path_address,
        "return_path_domain": return_path_domain,

        "reply_to_mismatch": int(
            bool(
                from_domain
                and reply_to_domain
                and from_domain != reply_to_domain
            )
        ),

        "return_path_mismatch": int(
            bool(
                from_domain
                and return_path_domain
                and from_domain != return_path_domain
            )
        ),

        "display_name_domain_mismatch": 0,
    }


# ==========================================================
# REMOVE NON-VISIBLE HTML CONTENT
# ==========================================================

def remove_non_visible_html(html_source):
    """
    Remove script, style, and noscript blocks.

    Original HTML is retained separately for link
    extraction.
    """

    if not html_source:
        return ""

    cleaned_html = str(html_source)

    # Remove complete blocks, including multiline content.
    cleaned_html = re.sub(
        r"<(script|style|noscript)\b[^>]*>.*?</\1\s*>",
        " ",
        cleaned_html,
        flags=re.IGNORECASE | re.DOTALL,
    )

    # Remove standalone opening/closing tags that may
    # remain in malformed HTML.
    cleaned_html = re.sub(
        r"</?(script|style|noscript)\b[^>]*>",
        " ",
        cleaned_html,
        flags=re.IGNORECASE,
    )

    return cleaned_html


# ==========================================================
# MIME CONTENT EXTRACTION
# ==========================================================

def extract_content_from_message(message):
    """
    Extract structured content from a parsed email.

    Preserves the return structure expected by the
    existing inference pipeline and Gmail add-on.
    """

    subject = str(message.get("Subject", "") or "")

    # ------------------------------------------------------
    # Sender information
    # ------------------------------------------------------

    sender_features = extract_sender_features(message)

    # ------------------------------------------------------
    # Storage
    # ------------------------------------------------------

    plain_parts = []
    html_parts = []
    attachments = []

    # ------------------------------------------------------
    # Walk through MIME parts
    # ------------------------------------------------------

    for part in message.walk():

        if part.is_multipart():
            continue

        content_type = part.get_content_type().lower()
        disposition = part.get_content_disposition()

        filename = part.get_filename()

        # --------------------------------------------------
        # Attachments
        # --------------------------------------------------

        if disposition == "attachment" or filename:
            attachments.append(
                {
                    "filename": filename,
                    "content_type": content_type,
                }
            )

            continue

        # --------------------------------------------------
        # Only process text/plain and text/html
        # --------------------------------------------------

        if content_type not in {
            "text/plain",
            "text/html",
        }:
            continue

        try:
            content = part.get_content()
        except Exception:
            # Fallback for unusual or malformed MIME parts.
            try:
                payload = part.get_payload(decode=True)

                if not payload:
                    continue

                charset = part.get_content_charset() or "utf-8"

                content = payload.decode(
                    charset,
                    errors="replace",
                )

            except Exception:
                continue

        if not content:
            continue

        content = str(content)

        # --------------------------------------------------
        # Plain text
        # --------------------------------------------------

        if content_type == "text/plain":
            plain_parts.append(content)

        # --------------------------------------------------
        # HTML
        # --------------------------------------------------

        elif content_type == "text/html":
            html_parts.append(content)

    # ======================================================
    # BUILD RAW CONTENT
    # ======================================================

    plain_text = "\n".join(plain_parts)
    html_source = "\n".join(html_parts)

    # ======================================================
    # EXTRACT HTML LINKS FROM ORIGINAL HTML
    # ======================================================

    html_links = extract_html_links(html_source)

    # ======================================================
    # CLEAN HTML FOR VISIBLE TEXT
    # ======================================================

    cleaned_html_source = remove_non_visible_html(
        html_source
    )

    try:
        html_text = html_to_visible_text(
            cleaned_html_source
        ) or ""
    except Exception:
        html_text = ""

    html_text = str(html_text)

    # ======================================================
    # SELECT TEXT REPRESENTATION FOR NLP
    # ======================================================

    # Prefer plain text to avoid counting multipart
    # alternative content twice.
    if plain_text.strip():
        combined_text = plain_text

    elif html_text.strip():
        combined_text = html_text

    else:
        combined_text = ""

    # ======================================================
    # EXTRACT URLS FROM PLAIN TEXT
    # ======================================================

    plain_text_urls = extract_urls(plain_text)

    # ======================================================
    # EXTRACT URLS FROM HTML HREF ATTRIBUTES
    # ======================================================

    html_link_urls = []

    for link in html_links:
        href = link.get("href", "")

        if not href:
            continue

        href = unescape(str(href).strip())

        if is_http_or_www_url(href):
            html_link_urls.append(href)

    # ======================================================
    # COMBINE URLS AND DEDUPLICATE
    # ======================================================

    urls = []
    seen_urls = set()

    for url in plain_text_urls + html_link_urls:

        url = clean_url_candidate(url)

        if not url:
            continue

        normalized = normalize_url_for_dedup(url)

        if normalized in seen_urls:
            continue

        seen_urls.add(normalized)
        urls.append(url)

    # ======================================================
    # MAILTO LINKS
    # ======================================================

    mailto_links = extract_mailto_links(
        html_source
    )

    # Also collect mailto links from plain-text content.
    plain_mailto_links = extract_mailto_links(
        plain_text
    )

    seen_mailto = {
        normalize_url_for_dedup(link)
        for link in mailto_links
    }

    for link in plain_mailto_links:
        normalized = normalize_url_for_dedup(link)

        if normalized not in seen_mailto:
            seen_mailto.add(normalized)
            mailto_links.append(link)

    # ======================================================
    # RETURN STRUCTURED CONTENT
    # ======================================================

    return {
        "subject": subject,

        "plain_text": plain_text,
        "html_source": html_source,
        "html_text": html_text,

        "html_links": html_links,
        "combined_text": combined_text,

        "urls": urls,
        "mailto_links": mailto_links,

        "attachments": attachments,
        "sender_features": sender_features,

        "html_part_count": len(html_parts),
        "plain_part_count": len(plain_parts),
    }


# ==========================================================
# EXTRACT EMAIL CONTENT FROM .EML FILE
# ==========================================================

def extract_email_content(eml_path):
    """
    Parse an .eml file and extract structured content.
    """

    with open(eml_path, "rb") as file:
        message = BytesParser(
            policy=policy.default
        ).parse(file)

    return extract_content_from_message(message)