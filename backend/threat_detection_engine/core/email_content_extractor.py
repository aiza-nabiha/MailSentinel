import re

from html import unescape

from email import policy
from email.parser import BytesParser
from email.utils import parseaddr

from html.parser import HTMLParser

from .text_cleaner import html_to_visible_text


# ==========================================================
# HTML LINK PARSER
# ==========================================================

class LinkParser(HTMLParser):

    def __init__(self):

        super().__init__()

        self.links = []

        self.current_href = None

        self.current_text = []


    def handle_starttag(self, tag, attrs):

        if tag.lower() != "a":
            return

        attributes = dict(attrs)

        self.current_href = attributes.get(
            "href"
        )

        self.current_text = []


    def handle_data(self, data):

        if self.current_href is not None:

            self.current_text.append(
                data
            )


    def handle_endtag(self, tag):

        if tag.lower() != "a":
            return

        if self.current_href:

            display_text = " ".join(
                self.current_text
            ).strip()

            self.links.append(
                {
                    "href": self.current_href,
                    "display_text": display_text
                }
            )

        self.current_href = None

        self.current_text = []


# ==========================================================
# HTML LINK EXTRACTION
# ==========================================================

def extract_html_links(html_source):

    if not html_source:
        return []

    parser = LinkParser()

    try:

        parser.feed(
            str(html_source)
        )

    except Exception:

        return []

    return parser.links


# ==========================================================
# URL EXTRACTION
# ==========================================================

def extract_urls(text):

    if not text:
        return []

    text = unescape(
        str(text)
    )

    urls = re.findall(
        r"https?://[^\s<>'\"]+|www\.[^\s<>'\"]+",
        text,
        re.IGNORECASE
    )

    return list(
        dict.fromkeys(urls)
    )


# ==========================================================
# MAILTO LINK EXTRACTION
# ==========================================================

def extract_mailto_links(text):

    if not text:
        return []

    links = re.findall(
        r"mailto:[^\s<>'\"]+",
        str(text),
        re.IGNORECASE
    )

    return list(
        dict.fromkeys(links)
    )


# ==========================================================
# SENDER FEATURES
# ==========================================================

def extract_sender_features(message):

    from_header = message.get(
        "From",
        ""
    )

    reply_to_header = message.get(
        "Reply-To",
        ""
    )

    return_path_header = message.get(
        "Return-Path",
        ""
    )


    # ------------------------------------------------------
    # Parse From
    # ------------------------------------------------------

    from_display_name, from_address = parseaddr(
        str(from_header)
    )


    # ------------------------------------------------------
    # Parse Reply-To
    # ------------------------------------------------------

    reply_to_display_name, reply_to_address = parseaddr(
        str(reply_to_header)
    )


    # ------------------------------------------------------
    # Parse Return-Path
    # ------------------------------------------------------

    return_path_display_name, return_path_address = parseaddr(
        str(return_path_header)
    )


    # ------------------------------------------------------
    # Fallback for malformed From headers
    # ------------------------------------------------------

    if not from_address:

        match = re.search(
            r"<([^<>@\s]+@[^<>\s]+)>",
            str(from_header)
        )

        if match:

            from_address = match.group(
                1
            )


    # ------------------------------------------------------
    # Extract domain
    # ------------------------------------------------------

    def get_domain(address):

        if not address or "@" not in address:
            return ""

        return address.rsplit(
            "@",
            1
        )[1].lower().strip()


    from_domain = get_domain(
        from_address
    )

    reply_to_domain = get_domain(
        reply_to_address
    )

    return_path_domain = get_domain(
        return_path_address
    )


    # ------------------------------------------------------
    # Return sender features
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


        # Intentionally left for future
        # domain/brand intelligence.
        "display_name_domain_mismatch": 0

    }


# ==========================================================
# REMOVE NON-VISIBLE HTML CONTENT
# ==========================================================

def remove_non_visible_html(html_source):

    if not html_source:
        return ""

    cleaned_html = re.sub(
        r"<(script|style|noscript).*?>.*?</\1>",
        " ",
        str(html_source),
        flags=re.IGNORECASE | re.DOTALL
    )

    return cleaned_html


# ==========================================================
# EXTRACT CONTENT FROM PARSED EMAIL
# ==========================================================

def extract_content_from_message(message):

    subject = message.get(
        "Subject",
        ""
    )


    # ------------------------------------------------------
    # Sender information
    # ------------------------------------------------------

    sender_features = extract_sender_features(
        message
    )


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


        content_type = part.get_content_type()

        disposition = part.get_content_disposition()


        # --------------------------------------------------
        # Attachments
        # --------------------------------------------------

        if disposition == "attachment":

            attachments.append(
                {
                    "filename": part.get_filename(),
                    "content_type": content_type
                }
            )

            continue


        # --------------------------------------------------
        # Only process text/plain and text/html
        # --------------------------------------------------

        if content_type not in {
            "text/plain",
            "text/html"
        }:

            continue


        try:

            content = part.get_content()

        except Exception:

            continue


        if not content:
            continue


        # --------------------------------------------------
        # Plain-text part
        # --------------------------------------------------

        if content_type == "text/plain":

            plain_parts.append(
                str(content)
            )


        # --------------------------------------------------
        # HTML part
        # --------------------------------------------------

        elif content_type == "text/html":

            html_parts.append(
                str(content)
            )


    # ======================================================
    # BUILD RAW CONTENT
    # ======================================================

    plain_text = "\n".join(
        plain_parts
    )

    html_source = "\n".join(
        html_parts
    )


    # ======================================================
    # EXTRACT HTML LINKS
    #
    # Do this BEFORE removing style/script blocks so that
    # actual <a href="..."> links are preserved.
    # ======================================================

    html_links = extract_html_links(
        html_source
    )


    # ======================================================
    # CLEAN HTML FOR VISIBLE TEXT EXTRACTION
    #
    # Remove CSS, JavaScript and other non-visible blocks.
    # ======================================================

    cleaned_html_source = remove_non_visible_html(
        html_source
    )


    # ======================================================
    # EXTRACT VISIBLE HTML TEXT
    # ======================================================

    html_text = html_to_visible_text(
        cleaned_html_source
    )


    # SELECT BEST TEXT REPRESENTATION FOR NLP
    #
    # Prefer plain text when available because it is already
    # intended for human-readable email content and avoids
    # duplicating the same message when both plain and HTML
    # versions exist.
    #
    # If plain text is unavailable, use visible HTML text.
    # ======================================================

    if plain_text.strip():

        combined_text = plain_text

    elif html_text.strip():

        combined_text = html_text

    else:

        combined_text = ""


    # ======================================================
    # EXTRACT URLS FROM PLAIN TEXT
    # ======================================================

    plain_text_urls = extract_urls(
        plain_text
    )


    # ======================================================
    # EXTRACT URLS FROM ACTUAL HTML LINKS
    # ======================================================

    html_link_urls = [

        link["href"]

        for link in html_links

        if (
            link.get("href")

            and link["href"].lower().startswith(
                (
                    "http://",
                    "https://",
                    "www."
                )
            )
        )

    ]


    # ======================================================
    # COMBINE URLS AND REMOVE DUPLICATES
    # ======================================================

    urls = list(
        dict.fromkeys(
            plain_text_urls
            + html_link_urls
        )
    )


    # ======================================================
    # MAILTO LINKS
    # ======================================================

    mailto_links = extract_mailto_links(
        html_source
    )


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


        "html_part_count": len(
            html_parts
        ),


        "plain_part_count": len(
            plain_parts
        )

    }


# ==========================================================
# EXTRACT EMAIL CONTENT FROM .EML FILE
# ==========================================================

def extract_email_content(eml_path):

    with open(
        eml_path,
        "rb"
    ) as file:

        message = BytesParser(
            policy=policy.default
        ).parse(file)


    return extract_content_from_message(
        message
    )