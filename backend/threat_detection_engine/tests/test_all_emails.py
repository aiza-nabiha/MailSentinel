import os
from ..core.content_analysis import ContentAnalyzer

# ==========================================================
# TEST CONFIGURATION
# ==========================================================

EMAIL_DIRECTORY = "data/test_emails"

# ==========================================================
# DISPLAY HELPERS
# ==========================================================

def print_separator():
    print("\n" + "=" * 80)

def print_result(filename, result):
    analysis = result["analysis"]

    print_separator()

    print(f"EMAIL: {filename}")

    print_separator()

    print("\nML assessment:")
    print(
        analysis["ml_assessment"]
    )

    print(
        "\nThreat probability:"
    )

    print(
        result["threat_probability"]
    )

    print(
        "\nPrediction:"
    )

    print(
        result["prediction"]
    )

    print(
        "\nSupporting evidence:"
    )

    for evidence in analysis[
        "supporting_evidence"
    ]:

        print(
            evidence
        )

    print(
        "\nContext:"
    )

    context = analysis[
        "context"
    ]

    if context:

        for item in context:
            print(item)

    else:

        print(
            "• No additional context signals"
        )

    print(
        "\nAssessment:"
    )

    print(
        analysis["assessment"]
    )


# ==========================================================
# MAIN TEST
# ==========================================================


def main():

    print_separator()

    print(
        "MAILSENTINEL - ALL EML CONTENT ANALYSIS"
    )

    print_separator()

    # ------------------------------------------------------
    # Check directory
    # ------------------------------------------------------

    if not os.path.isdir(
        EMAIL_DIRECTORY
    ):

        print(
            f"ERROR: Directory not found: "
            f"{EMAIL_DIRECTORY}"
        )

        return

    # ------------------------------------------------------
    # Find EML files
    # ------------------------------------------------------

    eml_files = sorted(

        filename

        for filename in os.listdir(
            EMAIL_DIRECTORY
        )

        if filename.lower().endswith(
            ".eml"
        )
    )

    if not eml_files:

        print(
            "No .eml files found."
        )

        return

    print(
        f"\nFound {len(eml_files)} .eml file(s):"
    )

    for filename in eml_files:

        print(
            f"  - {filename}"
        )

    # ------------------------------------------------------
    # Load model once
    # ------------------------------------------------------

    print(
        "\nLoading content classifier..."
    )

    try:

        analyzer = ContentAnalyzer()

    except Exception as error:

        print(
            "\nERROR loading model:"
        )

        print(error)

        return

    print(
        "Model loaded successfully."
    )

    # ------------------------------------------------------
    # Analyze every email
    # ------------------------------------------------------

    results = []

    for filename in eml_files:

        eml_path = os.path.join(
            EMAIL_DIRECTORY,
            filename
        )

        try:

            result = analyzer.analyze_eml(
                eml_path
            )

            results.append(
                (
                    filename,
                    result
                )
            )

            print_result(
                filename,
                result
            )

        except Exception as error:

            print_separator()

            print(
                f"ERROR analyzing {filename}:"
            )

            print(error)

    # ------------------------------------------------------
    # Summary
    # ------------------------------------------------------

    print_separator()

    print(
        "SUMMARY"
    )

    print_separator()

    print(
        f"\nSuccessfully analyzed "
        f"{len(results)} / {len(eml_files)} email(s).\n"
    )

    if results:

        print(
            f"{'Email':<25}"
            f"{'Probability':<15}"
            f"{'Prediction':<15}"
            f"Assessment"
        )

        print(
            "-" * 80
        )

        for filename, result in results:

            probability = (
                result[
                    "threat_probability"
                ]
            )

            prediction = (
                result[
                    "prediction"
                ]
            )

            assessment = (
                result[
                    "analysis"
                ][
                    "assessment"
                ]
            )

            print(
                f"{filename:<25}"
                f"{probability:<15}"
                f"{prediction:<15}"
                f"{assessment}"
            )

    print_separator()

    print(
        "TEST COMPLETE"
    )

    print_separator()


# ==========================================================
# ENTRY POINT
# ==========================================================


if __name__ == "__main__":

    main()