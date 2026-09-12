import re
from email import policy
from email.parser import BytesParser
from html.parser import HTMLParser
from urllib.parse import urlparse


# NOTE: We deliberately do NOT filter out major platforms
# (facebook.com, google.com, etc.) here. Real phishing campaigns
# abuse legitimate platforms' open redirects and tracking links,
# so excluding them by name risks missing genuine abuse. Instead,
# "noise" domains are naturally deprioritized downstream, at the
# risk-scoring stage -- an old, well-reputed, properly-certified
# domain will score as low-risk on its own evidence (WHOIS age,
# TLS issuer trust, reputation feeds), with no exclusion list
# needed. This trades a few extra API calls per email for not
# silently missing a real signal.


class LinkExtractor(HTMLParser):

    def __init__(self):
        super().__init__()
        self.links = []

    def handle_starttag(self, tag, attrs):

        if tag.lower() == "a":

            for name, value in attrs:

                if name.lower() == "href" and value:
                    self.links.append(value)


def extract_domains(eml_path):

    # Parse the email properly
    with open(eml_path, "rb") as f:
        msg = BytesParser(policy=policy.default).parse(f)

    domains = set()

    # ---------------------------------
    # 1. Sender domain
    # ---------------------------------

    from_addr = msg.get("From", "")

    match = re.search(r'@([\w.-]+)', from_addr)

    if match:
        domains.add(match.group(1).lower())


    # ---------------------------------
    # 2. Reply-To domain
    # ---------------------------------

    reply_to = msg.get("Reply-To", "")

    match = re.search(r'@([\w.-]+)', reply_to)

    if match:
        domains.add(match.group(1).lower())


    # ---------------------------------
    # 2b. Return-Path domain (often reveals real sending infra,
    # even when From/Reply-To show a different brand)
    # ---------------------------------

    return_path = msg.get("Return-Path", "")

    match = re.search(r'@([\w.-]+)', return_path)

    if match:
        domains.add(match.group(1).lower())


    # ---------------------------------
    # 3. Process email body
    # ---------------------------------

    for part in msg.walk():

        content_type = part.get_content_type()

        # ==============================
        # HTML
        # ==============================

        if content_type == "text/html":

            html = part.get_content()

            parser = LinkExtractor()

            try:
                parser.feed(html)
            except Exception:
                continue

            # Only actual <a href=""> links
            for url in parser.links:

                if not url.startswith(
                    ("http://", "https://")
                ):
                    continue

                parsed = urlparse(url)

                domain = parsed.hostname

                if domain:
                    domains.add(domain.lower())


        # ==============================
        # Plain text
        # ==============================

        elif content_type == "text/plain":

            text = part.get_content()

            urls = re.findall(
                r'https?://[^\s<>"\']+',
                text
            )

            for url in urls:

                url = url.rstrip(
                    ".,);]}"
                )

                parsed = urlparse(url)

                domain = parsed.hostname

                if domain:
                    domains.add(domain.lower())


    return sorted(domains)

def extract_urls(eml_path):
    """
    Extract actual HTTP/HTTPS URLs from the email.

    Unlike extract_domains(), this preserves the complete URL
    including path and query parameters.

    Used for exact URL-level reputation checks such as PhishTank.
    """

    with open(eml_path, "rb") as f:
        msg = BytesParser(policy=policy.default).parse(f)

    urls = set()

    for part in msg.walk():
        content_type = part.get_content_type()

        # ==============================
        # HTML
        # ==============================
        if content_type == "text/html":
            html = part.get_content()

            parser = LinkExtractor()

            try:
                parser.feed(html)
            except Exception:
                continue

            for url in parser.links:
                if not url.startswith(("http://", "https://")):
                    continue

                urls.add(url.rstrip(".,);]}"))

        # ==============================
        # Plain text
        # ==============================
        elif content_type == "text/plain":
            text = part.get_content()

            found_urls = re.findall(
                r'https?://[^\s<>"\']+',
                text
            )

            for url in found_urls:
                urls.add(url.rstrip(".,);]}"))

    return sorted(urls)    


# -------------------------------------
# Test
# -------------------------------------

if __name__ == "__main__":
    domains = extract_domains("example.eml")

    print("\nExtracted Domains:")
    print("------------------")

    for domain in domains:
        print(domain)