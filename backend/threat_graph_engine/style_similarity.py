import re
from email import policy
from email.parser import BytesParser
from html.parser import HTMLParser


# ==================================================================
# STYLE SIGNATURE EXTRACTION
# ==================================================================

_HEX_COLOR_PATTERN = re.compile(r'#[0-9a-fA-F]{3,6}\b')
_FONT_FAMILY_PATTERN = re.compile(r'font-family\s*:\s*([^;]+)')


class StyleExtractor(HTMLParser):
    """
    Walks an HTML email and pulls out branding signals: colors used
    (from inline style attributes and <style> blocks), font families
    declared, and alt text on images (often the brand/logo name,
    e.g. alt="Microsoft logo").
    """

    def __init__(self):
        super().__init__()
        self.colors = set()
        self.fonts = set()
        self.alt_texts = set()
        self._in_style_block = False
        self._style_block_content = []

    def handle_starttag(self, tag, attrs):
        attr_dict = dict(attrs)

        if tag == "style":
            self._in_style_block = True

        style_value = attr_dict.get("style")
        if style_value:
            self._extract_from_css_text(style_value)

        if tag == "img":
            alt = attr_dict.get("alt", "").strip().lower()
            if alt:
                self.alt_texts.add(alt)

    def handle_endtag(self, tag):
        if tag == "style":
            self._in_style_block = False

    def handle_data(self, data):
        if self._in_style_block:
            self._extract_from_css_text(data)

    def _extract_from_css_text(self, css_text):
        for match in _HEX_COLOR_PATTERN.findall(css_text):
            self.colors.add(match.lower())

        for match in _FONT_FAMILY_PATTERN.findall(css_text):
            # font-family often lists several fallbacks separated by
            # commas -- take the FIRST one, since that's the actual
            # brand-chosen font, not the generic fallback (sans-serif)
            primary_font = match.split(",")[0].strip().strip("'\"").lower()
            if primary_font:
                self.fonts.add(primary_font)


def extract_style_signature(eml_path):
    """
    Return a branding "signature" for an email: the set of colors,
    fonts, and image alt-texts found in its HTML body. Returns an
    empty signature (not an error) for plain-text emails -- there's
    just no style to compare, which is a valid, different outcome
    from "compared and found different."
    """

    with open(eml_path, "rb") as f:
        msg = BytesParser(policy=policy.default).parse(f)

    html_body = None

    if msg.is_multipart():
        for part in msg.walk():
            if part.get_content_type() == "text/html":
                html_body = part.get_content()
                break
    elif msg.get_content_type() == "text/html":
        html_body = msg.get_content()

    if not html_body:
        return {
            "eml_path": eml_path,
            "has_html": False,
            "colors": set(),
            "fonts": set(),
            "alt_texts": set()
        }

    extractor = StyleExtractor()
    extractor.feed(html_body)

    return {
        "eml_path": eml_path,
        "has_html": True,
        "colors": extractor.colors,
        "fonts": extractor.fonts,
        "alt_texts": extractor.alt_texts
    }


# ==================================================================
# SIMILARITY COMPARISON
# ==================================================================

def _jaccard_similarity(set_a, set_b):
    """
    Size of the overlap divided by size of the union -- 1.0 means
    identical sets, 0.0 means nothing in common. Standard way to
    compare two sets of features, used here for colors/fonts/alts.
    """

    if not set_a and not set_b:
        return None  # neither had anything to compare -- not "0% similar"

    union = set_a | set_b

    if not union:
        return None

    return len(set_a & set_b) / len(union)


def compare_signatures(sig_a, sig_b):
    """
    Compare two ALREADY-EXTRACTED style signatures (from
    extract_style_signature). Use this when comparing many emails
    against each other -- extract each email's signature ONCE up
    front, then call this as many times as needed, instead of
    re-parsing the same .eml file on every pairwise comparison.
    """

    if not sig_a["has_html"] or not sig_b["has_html"]:
        return {
            "comparable": False,
            "reason": "One or both emails have no HTML body to compare"
        }

    color_similarity = _jaccard_similarity(sig_a["colors"], sig_b["colors"])
    font_similarity = _jaccard_similarity(sig_a["fonts"], sig_b["fonts"])
    alt_similarity = _jaccard_similarity(
        sig_a["alt_texts"], sig_b["alt_texts"]
    )

    available_scores = [
        s for s in [color_similarity, font_similarity, alt_similarity]
        if s is not None
    ]

    overall = (
        sum(available_scores) / len(available_scores)
        if available_scores else None
    )

    return {
        "comparable": True,
        "color_similarity": color_similarity,
        "font_similarity": font_similarity,
        "alt_text_similarity": alt_similarity,
        "overall_similarity": overall,
        "shared_colors": sorted(sig_a["colors"] & sig_b["colors"]),
        "shared_fonts": sorted(sig_a["fonts"] & sig_b["fonts"])
    }


def compare_style(eml_path_a, eml_path_b):
    """
    Convenience wrapper for comparing exactly two emails by file
    path in one call -- extracts both signatures then compares them.
    Fine for one-off testing; for batch/clustering use, call
    extract_style_signature() once per email yourself and reuse
    compare_signatures() instead, to avoid re-parsing files.
    """

    sig_a = extract_style_signature(eml_path_a)
    sig_b = extract_style_signature(eml_path_b)

    result = compare_signatures(sig_a, sig_b)
    result["eml_path_a"] = eml_path_a
    result["eml_path_b"] = eml_path_b

    return result


# ==================================================================
# STANDALONE TESTING
# ==================================================================

if __name__ == "__main__":
    import sys
    from itertools import combinations

    if len(sys.argv) < 3:
        print("Usage: python style_similarity.py file1.eml file2.eml [file3.eml ...]")
    else:
        paths = sys.argv[1:]

        for path_a, path_b in combinations(paths, 2):
            result = compare_style(path_a, path_b)

            print(f"\n{path_a}")
            print(f"vs {path_b}")

            if not result["comparable"]:
                print(f"  Not comparable: {result['reason']}")
                continue

            print(f"  Color similarity: {result['color_similarity']}")
            print(f"  Font similarity: {result['font_similarity']}")
            print(f"  Alt-text similarity: {result['alt_text_similarity']}")
            print(f"  Overall: {result['overall_similarity']}")

            if result["shared_colors"]:
                print(f"  Shared colors: {result['shared_colors']}")
            if result["shared_fonts"]:
                print(f"  Shared fonts: {result['shared_fonts']}")