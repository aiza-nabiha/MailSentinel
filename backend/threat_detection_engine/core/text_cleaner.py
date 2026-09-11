import re
from html import unescape
from html.parser import HTMLParser


class VisibleTextParser(HTMLParser):

    def __init__(self):
        super().__init__()
        self.parts = []

    def handle_data(self, data):
        if data.strip():
            self.parts.append(data.strip())

    def get_text(self):
        return " ".join(self.parts)


def html_to_visible_text(html):
    """
    Extract visible text from HTML while preserving
    word boundaries between HTML elements.
    """

    parser = VisibleTextParser()
    parser.feed(html)

    return parser.get_text()


def clean_email_text(text):
    """
    Clean email content for NLP analysis.
    """

    if not text:
        return ""

    text = str(text)

    # Decode HTML entities
    text = unescape(text)

    # Remove script/style blocks
    text = re.sub(
        r"<(script|style).*?>.*?</\1>",
        " ",
        text,
        flags=re.IGNORECASE | re.DOTALL
    )

    # Detect whether the content contains HTML
    if re.search(r"<[a-zA-Z][^>]*>", text):
        text = html_to_visible_text(text)

    # Replace URLs with a placeholder
    text = re.sub(
        r"https?://\S+|www\.\S+",
        " URL ",
        text,
        flags=re.IGNORECASE
    )

    # Normalize whitespace
    text = re.sub(
        r"\s+",
        " ",
        text
    )

    return text.strip()


def remove_urls_for_structural_analysis(text):
    """
    Remove URL contents before calculating text-based
    structural statistics.
    """

    if not text:
        return ""

    return re.sub(
        r"https?://\S+|www\.\S+",
        " URL ",
        str(text),
        flags=re.IGNORECASE
    )


if __name__ == "__main__":

    sample = """
    <html>
        <body>
            <p>Hello, <b>this is a test</b>.</p>
            <p>Visit https://example.com/tracking/ABC123XYZ</p>
        </body>
    </html>
    """

    print("Cleaned:")
    print(clean_email_text(sample))

    print("\nStructural text:")
    print(remove_urls_for_structural_analysis(sample))