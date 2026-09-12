
import os
import sys

# domain_extract.py lives in the sibling infrastructure_engine
# folder, not here -- add it to the path so we can reuse Person 3's
# existing domain extraction instead of duplicating that logic.
_INFRA_ENGINE_PATH = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    "..",
    "infrastructure_engine"
)

if _INFRA_ENGINE_PATH not in sys.path:
    sys.path.insert(0, _INFRA_ENGINE_PATH)

from domain_extract import extract_domains

from structural_hash import fingerprint_email
from typosquat_detection import check_typosquat
from style_similarity import extract_style_signature, compare_signatures


# ==================================================================
# GENERATE: run once per email
# ==================================================================

def generate_fingerprint(eml_path):
    """
    Run all three Part A signals on a single email and return one
    combined, JSON-serializable fingerprint object. Call this ONCE
    per email (whether it's a test file or a brand-new email coming
    into the system) and hand the result to Part B -- there's no
    need to call structural_hash/typosquat_detection/style_similarity
    directly.
    """

    structural = fingerprint_email(eml_path)

    try:
        domains = extract_domains(eml_path)
    except Exception as e:
        domains = []
        domain_extraction_error = str(e)
    else:
        domain_extraction_error = None

    typosquat_matches = []

    for domain in domains:
        result = check_typosquat(domain)

        if result["is_typosquat"]:
            typosquat_matches.append({
                "domain": domain,
                "matched_brand": result["matched_brand"],
                "matched_chunk": result.get("matched_chunk"),
                "edit_distance": result["edit_distance"]
            })

    targeted_brands = sorted({
        m["matched_brand"] for m in typosquat_matches
    })

    style_sig = extract_style_signature(eml_path)

    return {
        "eml_path": eml_path,

        "structural": {
            "skeleton_type": structural["skeleton_type"],
            "fingerprint_sha256": structural["fingerprint_sha256"]
        },

        "typosquat": {
            "domains_checked": domains,
            "matches": typosquat_matches,
            "targeted_brands": targeted_brands,
            "extraction_error": domain_extraction_error
        },

        # kept as sorted lists, not sets, so this whole object is
        # directly json.dump-able without a custom encoder
        "style": {
            "has_html": style_sig["has_html"],
            "colors": sorted(style_sig["colors"]),
            "fonts": sorted(style_sig["fonts"]),
            "alt_texts": sorted(style_sig["alt_texts"])
        }
    }


# ==================================================================
# COMPARE: run for every pair Part B wants to check
# ==================================================================

def compare_fingerprints(fingerprint_a, fingerprint_b):
    """
    Compare two ALREADY-GENERATED fingerprints (from
    generate_fingerprint) and return every signal Part B needs to
    decide whether to draw a graph edge between them: exact
    structural match, shared impersonated brands, and style overlap.

    Generate each email's fingerprint ONCE and reuse it for every
    comparison -- don't call generate_fingerprint() again inside a
    clustering loop, or you'll needlessly re-parse the same files
    and re-run WHOIS-adjacent domain extraction repeatedly.
    """

    structural_match = (
        fingerprint_a["structural"]["fingerprint_sha256"]
        == fingerprint_b["structural"]["fingerprint_sha256"]
        and fingerprint_a["structural"]["skeleton_type"]
        == fingerprint_b["structural"]["skeleton_type"]
    )

    shared_brands = sorted(
        set(fingerprint_a["typosquat"]["targeted_brands"])
        & set(fingerprint_b["typosquat"]["targeted_brands"])
    )

    # style comparison needs sets, but generate_fingerprint() stores
    # sorted lists (so the fingerprint is JSON-serializable) -- convert
    # back to sets just for this comparison
    style_sig_a = {
        "has_html": fingerprint_a["style"]["has_html"],
        "colors": set(fingerprint_a["style"]["colors"]),
        "fonts": set(fingerprint_a["style"]["fonts"]),
        "alt_texts": set(fingerprint_a["style"]["alt_texts"])
    }

    style_sig_b = {
        "has_html": fingerprint_b["style"]["has_html"],
        "colors": set(fingerprint_b["style"]["colors"]),
        "fonts": set(fingerprint_b["style"]["fonts"]),
        "alt_texts": set(fingerprint_b["style"]["alt_texts"])
    }

    style_result = compare_signatures(style_sig_a, style_sig_b)

    return {
        "eml_path_a": fingerprint_a["eml_path"],
        "eml_path_b": fingerprint_b["eml_path"],

        "structural_match": structural_match,

        "shared_targeted_brands": shared_brands,
        "brand_overlap": len(shared_brands) > 0,

        "style_comparable": style_result["comparable"],
        "style_overall_similarity": style_result.get("overall_similarity"),
        "style_shared_colors": style_result.get("shared_colors", []),
        "style_shared_fonts": style_result.get("shared_fonts", [])
    }


# ==================================================================
# STANDALONE TESTING
# ==================================================================

if __name__ == "__main__":
    import sys as _sys
    import json
    from itertools import combinations

    if len(_sys.argv) < 2:
        print("Usage: python fingerprint.py file1.eml [file2.eml ...]")
    else:
        paths = _sys.argv[1:]

        print("=" * 70)
        print("GENERATING FINGERPRINTS")
        print("=" * 70)

        fingerprints = {}

        for path in paths:
            fp = generate_fingerprint(path)
            fingerprints[path] = fp

            print(f"\n{path}")
            print(f"  Structural: {fp['structural']['skeleton_type']} / "
                  f"{fp['structural']['fingerprint_sha256'][:16]}...")
            print(f"  Targeted brands: {fp['typosquat']['targeted_brands']}")
            print(f"  Has HTML: {fp['style']['has_html']}")

        if len(paths) > 1:
            print("\n" + "=" * 70)
            print("PAIRWISE COMPARISON")
            print("=" * 70)

            for path_a, path_b in combinations(paths, 2):
                comparison = compare_fingerprints(
                    fingerprints[path_a], fingerprints[path_b]
                )

                any_signal = (
                    comparison["structural_match"]
                    or comparison["brand_overlap"]
                    or (comparison["style_overall_similarity"] or 0) > 0.3
                )

                if any_signal:
                    print(f"\n{path_a}")
                    print(f"vs {path_b}")
                    print(f"  Structural match: {comparison['structural_match']}")
                    print(f"  Shared brands: {comparison['shared_targeted_brands']}")
                    print(f"  Style similarity: {comparison['style_overall_similarity']}")