import cv2
import easyocr
import re
import socket
import tldextract
from urllib.parse import urlparse, urlunparse
import json


# Initialize OCR reader
reader = easyocr.Reader(['en'], gpu=False)


def extract_qr_urls(image_path):
    image = cv2.imread(image_path)

    if image is None:
        return []

    detector = cv2.QRCodeDetector()

    # Try original image and enhanced versions
    images_to_try = [image]

    # Upscale image
    enlarged = cv2.resize(
        image,
        None,
        fx=2,
        fy=2,
        interpolation=cv2.INTER_CUBIC
    )

    images_to_try.append(enlarged)

    # Grayscale
    gray = cv2.cvtColor(enlarged, cv2.COLOR_BGR2GRAY)
    images_to_try.append(gray)

    # Adaptive thresholding
    thresh = cv2.adaptiveThreshold(
        gray,
        255,
        cv2.ADAPTIVE_THRESH_GAUSSIAN_C,
        cv2.THRESH_BINARY,
        31,
        5
    )

    images_to_try.append(thresh)

    urls = []

    for img in images_to_try:

        success, decoded_info, points, _ = (
            detector.detectAndDecodeMulti(img)
        )

        if success:
            for text in decoded_info:
                if text:
                    urls.append(text.strip())

        # Single QR fallback
        if not urls:
            text, points, _ = detector.detectAndDecode(img)

            if text:
                urls.append(text.strip())

        if urls:
            break

    return list(dict.fromkeys(urls))

def extract_ocr_text(image_path):
    image = cv2.imread(image_path)

    if image is None:
        return ""

    results = reader.readtext(image, detail=0)

    return " ".join(results)


def extract_urls_from_text(text):

    if not text:
        return []

    # Normalize spaces around URL separators
    text = re.sub(r'\s*([:/?.=&])\s*', r'\1', text)

    # Detect domains written with spaces, e.g. "example com"
    words = re.findall(r'[A-Za-z0-9-]+', text)

    reconstructed = []

    for i in range(len(words) - 1):

        host = words[i] + "." + words[i + 1]

        extracted = tldextract.extract(host)

        if extracted.domain and extracted.suffix:
            reconstructed.append(host)

    # Find explicit URLs and ordinary domain candidates
    pattern = r'(?i)\b(?:https?://)?(?:www\.)?[a-z0-9-]+(?:\.[a-z0-9-]+)+(?::\d+)?(?:/[^\s<>"\']*)?'

    candidates = re.findall(pattern, text)

    candidates.extend(reconstructed)

    urls = []

    for candidate in candidates:

        candidate = candidate.strip(".,;:!?")

        if not candidate.startswith(("http://", "https://")):
            candidate = "https://" + candidate

        parsed = urlparse(candidate)

        hostname = parsed.hostname

        if not hostname:
            continue

        extracted = tldextract.extract(hostname)

        if not extracted.domain or not extracted.suffix:
            continue

        normalized = urlunparse(parsed)

        if normalized not in urls:
            urls.append(normalized)

    return urls



# ==================================================================
# WHY THIS MODULE VALIDATES VIA DNS, NOT JUST TLD SYNTAX
# ==================================================================
#
# Many modern gTLDs are ordinary English words: .live, .click, .top,
# .site, .fun, .help, .guide, .company, .men, .win, .college, .work,
# .life, .today, .best, .fan, .fans -- among many others.
#
# This means suffix-only validation (tldextract confirming a string
# "looks like domain.tld") is NOT enough to distinguish a real OCR-
# mangled URL like "linkedin com / company" from two ordinary
# English words that happen to form a syntactically valid domain,
# such as "click live" -> click.live, or "top guide" -> top.guide.
#
# No static wordlist can fully cover this either, since new gTLDs
# keep launching and language keeps evolving. The one source of
# truth that actually settles "is this a real, existing domain" is
# the domain itself: attempt a live DNS resolution. If it resolves,
# it exists. If it doesn't, it was very likely two words, not a URL
# -- this holds regardless of what gTLD happens to be involved, with
# nothing hardcoded about specific words or TLDs.
# ==================================================================


DNS_VALIDATION_TIMEOUT = 2.0


def _looks_syntactically_valid(hostname):
    """
    Cheap first-pass filter: does this even have a real domain +
    real-looking suffix structure? This does NOT prove the domain
    exists -- see _resolves_on_dns() for that. This step just avoids
    wasting a DNS lookup on obvious junk.
    """

    if not hostname:
        return False

    extracted = tldextract.extract(hostname)

    return bool(extracted.domain and extracted.suffix)


def _resolves_on_dns(hostname):
    """
    The actual ground-truth check: does this hostname resolve to a
    real IP address right now? This is what separates a genuine
    (if OCR-mangled) domain from two English words that happen to
    look like one, since real domains resolve and coincidental
    word-pairs essentially never do.
    """

    try:
        socket.setdefaulttimeout(DNS_VALIDATION_TIMEOUT)
        socket.gethostbyname(hostname)
        return True

    except (socket.gaierror, socket.timeout, UnicodeError):
        return False

    finally:
        socket.setdefaulttimeout(None)


# ==================================================================
# MAIN EXTRACTION
# ==================================================================

def extract_urls_from_text(text, validate_reconstructed_via_dns=True):
    """
    Extract URLs from text, including explicit http(s) links, bare
    www links, and OCR-mangled spaced-out domains (e.g. scanned/
    screenshotted text reading "linkedin com / company / abc").

    validate_reconstructed_via_dns: when True (default), any
    candidate URL that was RECONSTRUCTED from spaced-out text (not
    an explicit http/www match) must resolve on live DNS before
    being accepted. This is what prevents ordinary English phrases
    from being reported as URLs -- see the module docstring above.
    Explicit http(s)/www matches are never DNS-gated, since they
    were unambiguously written as URLs in the first place.
    """

    if not text:
        return []

    normalized = re.sub(r'\s*([:/?=&])\s*', r'\1', text)

    explicit_urls = set()
    reconstructed_candidates = set()

    # ---- 1. Explicit http(s) URLs -- unambiguous, no DNS check needed ----
    explicit_pattern = (
        r'https?://[a-zA-Z0-9.-]+'
        r'(?::\d+)?'
        r'(?:/[^\s<>"\']*)?'
    )
    explicit_urls.update(re.findall(explicit_pattern, normalized, flags=re.IGNORECASE))

    # ---- 2. Bare www URLs -- also unambiguous ----
    www_pattern = (
        r'www\.[a-zA-Z0-9-]+\.[a-zA-Z]{2,}'
        r'(?:/[^\s<>"\']*)?'
    )
    explicit_urls.update(re.findall(www_pattern, normalized, flags=re.IGNORECASE))

    # ---- 3. Spaced-out / OCR-mangled domains -- AMBIGUOUS, needs DNS gate ----
    # e.g. "linkedin com / company / abc" -> candidate: linkedin.com/company/abc
    spaced_domain_pattern = (
        r'\b([a-zA-Z0-9-]+)\s+'
        r'([a-zA-Z]{2,})\s*/\s*'
        r'([a-zA-Z0-9._~!$&\'()*+,;=:@%/-]*)'
    )

    for match in re.finditer(spaced_domain_pattern, text):
        domain_guess = f"{match.group(1)}.{match.group(2)}"
        path = match.group(3)

        if _looks_syntactically_valid(domain_guess):
            reconstructed_candidates.add(f"https://{domain_guess}/{path}".rstrip("/"))

    # ==================================================================
    # VALIDATE + DEDUPLICATE
    # ==================================================================

    final_urls = []
    seen = set()

    def _clean_and_check(candidate, needs_dns_check):
        candidate = candidate.strip(".,;:!?")

        if not candidate.startswith(("http://", "https://")):
            candidate = "https://" + candidate

        parsed = urlparse(candidate)
        hostname = parsed.hostname

        if not hostname or not _looks_syntactically_valid(hostname):
            return None

        if needs_dns_check and validate_reconstructed_via_dns:
            if not _resolves_on_dns(hostname):
                return None

        return candidate

    for candidate in explicit_urls:
        cleaned = _clean_and_check(candidate, needs_dns_check=False)
        if cleaned and cleaned not in seen:
            seen.add(cleaned)
            final_urls.append(cleaned)

    for candidate in reconstructed_candidates:
        cleaned = _clean_and_check(candidate, needs_dns_check=True)
        if cleaned and cleaned not in seen:
            seen.add(cleaned)
            final_urls.append(cleaned)

    return final_urls

def extract_image_indicators(image_path):

    qr_urls = extract_qr_urls(image_path)

    ocr_text = extract_ocr_text(image_path)

    ocr_urls = extract_urls_from_text(ocr_text)

    return {
        "source": "image",
        "image_path": image_path,
        "qr_urls": qr_urls,
        "ocr_text": ocr_text,
        "ocr_urls": ocr_urls
    }

if __name__ == "__main__":

    result = extract_image_indicators("image.jpeg")

    print(json.dumps(result, indent=4, ensure_ascii=False))    