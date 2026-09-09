import re
from email import policy
from email.parser import BytesParser
from html.parser import HTMLParser
from urllib.parse import urlparse


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


# -------------------------------------
# Test
# -------------------------------------

if __name__ == "__main__":
    domains = extract_domains("example.eml")

    print("\nExtracted Domains:")
    print("------------------")

    for domain in domains:
        print(domain)