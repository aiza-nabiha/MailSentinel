import hashlib
import re
from email import policy
from email.parser import BytesParser
from html.parser import HTMLParser


# ==================================================================
# HTML SKELETON EXTRACTION
# ==================================================================

class SkeletonExtractor(HTMLParser):
    """
    Walks an HTML email body and keeps only the structural shape:
    tag names, nesting order, and attribute NAMES (not values, since
    values like href/src/class-with-random-id change between sends
    even when the underlying template is identical).
    """

    def __init__(self):
        super().__init__()
        self.skeleton = []

    def handle_starttag(self, tag, attrs):
        attr_names = sorted(name for name, _ in attrs)
        self.skeleton.append(f"<{tag} {' '.join(attr_names)}>")

    def handle_endtag(self, tag):
        self.skeleton.append(f"</{tag}>")


def _extract_html_skeleton(html_body):
    parser = SkeletonExtractor()
    parser.feed(html_body)
    return "".join(parser.skeleton)


# ==================================================================
# PLAIN-TEXT SKELETON EXTRACTION (fallback for non-HTML emails)
# ==================================================================

# Order matters: replace the more specific patterns first, so e.g.
# a URL doesn't get partially eaten by the number pattern first.
_PLACEHOLDER_PATTERNS = [
    (re.compile(r'https?://\S+'), '<URL>'),
    (re.compile(r'[\w.+-]+@[\w-]+\.[\w.-]+'), '<EMAIL>'),
    (re.compile(r'\b\d{1,2}[/-]\d{1,2}[/-]\d{2,4}\b'), '<DATE>'),
    (re.compile(r'\bRs\.?\s?\d[\d,]*\b', re.IGNORECASE), '<AMOUNT>'),
    (re.compile(r'\$\d[\d,]*(\.\d+)?'), '<AMOUNT>'),
    (re.compile(r'\b\d+\b'), '<NUM>'),
]


def _extract_text_skeleton(text_body):
    """
    Since plain-text phishing emails often vary their actual wording
    (unlike an HTML template, which is usually reused byte-for-byte),
    we can't just hash the raw text. Instead we normalize whitespace
    and swap out the parts that are EXPECTED to change between sends
    (links, emails, dates, amounts, numbers) so what's left reflects
    the message's shape rather than its specific content.
    """

    normalized = text_body.strip()

    for pattern, placeholder in _PLACEHOLDER_PATTERNS:
        normalized = pattern.sub(placeholder, normalized)

    # collapse all whitespace so formatting differences don't matter
    normalized = re.sub(r'\s+', ' ', normalized)

    return normalized.lower()


# ==================================================================
# MAIN ENTRY POINT
# ==================================================================

def get_email_skeleton(eml_path):
    """
    Return the structural skeleton of an email: the HTML tag
    structure if the email has an HTML part, otherwise a
    placeholder-normalized version of the plain-text body.
    """

    with open(eml_path, "rb") as f:
        msg = BytesParser(policy=policy.default).parse(f)

    html_body = None
    text_body = None

    if msg.is_multipart():
        for part in msg.walk():
            content_type = part.get_content_type()

            if content_type == "text/html" and html_body is None:
                html_body = part.get_content()

            elif content_type == "text/plain" and text_body is None:
                text_body = part.get_content()
    else:
        content_type = msg.get_content_type()

        if content_type == "text/html":
            html_body = msg.get_content()
        else:
            text_body = msg.get_content()

    if html_body:
        return "html", _extract_html_skeleton(html_body)

    if text_body:
        return "text", _extract_text_skeleton(text_body)

    return "empty", ""


def fingerprint_email(eml_path):
    """
    Produce a structural fingerprint for an email: a SHA-256 hash
    of its skeleton, plus the skeleton itself and which type it was
    (so two emails only cluster if they're the same skeleton TYPE
    too -- an HTML template should never "match" a plain-text one).
    """

    skeleton_type, skeleton = get_email_skeleton(eml_path)

    fingerprint = hashlib.sha256(
        f"{skeleton_type}:{skeleton}".encode("utf-8")
    ).hexdigest()

    return {
        "eml_path": eml_path,
        "skeleton_type": skeleton_type,
        "skeleton": skeleton,
        "fingerprint_sha256": fingerprint
    }


# ==================================================================
# STANDALONE TESTING
# ==================================================================

if __name__ == "__main__":
    import sys

    if len(sys.argv) < 2:
        print("Usage: python structural_hash.py file1.eml [file2.eml ...]")
    else:
        results = [fingerprint_email(path) for path in sys.argv[1:]]

        for r in results:
            print(f"\n{r['eml_path']}")
            print(f"  Type: {r['skeleton_type']}")
            print(f"  Fingerprint: {r['fingerprint_sha256']}")
            print(f"  Skeleton preview: {r['skeleton'][:150]}")

        # quick cross-check: which of the given emails match each other
        print("\n" + "=" * 60)
        print("MATCHES")
        print("=" * 60)

        seen = {}
        for r in results:
            seen.setdefault(r["fingerprint_sha256"], []).append(r["eml_path"])

        any_match = False
        for fp, paths in seen.items():
            if len(paths) > 1:
                any_match = True
                print(f"\nSame skeleton ({fp[:12]}...):")
                for p in paths:
                    print(f"  {p}")

        if not any_match:
            print("\nNo structural matches among the given emails.")