import os
from ..core.content_analysis import ContentAnalyzer

TEST_DIR = "data/test_emails"

def main():
    analyzer = ContentAnalyzer()

    eml_files = sorted(
        file_name
        for file_name in os.listdir(TEST_DIR)
        if file_name.lower().endswith(".eml")
    )

    if not eml_files:
        print("No .eml files found.")
        return

    print("=" * 70)
    print("MAILSENTINEL - REAL-WORLD EMAIL CONTENT TEST")
    print("=" * 70)

    for file_name in eml_files:
        eml_path = os.path.join(
            TEST_DIR,
            file_name
        )

        try:
            result = analyzer.analyze_eml(
                eml_path
            )

            print("\n" + "=" * 70)
            print(f"FILE: {file_name}")
            print("=" * 70)

            print("\nThreat Probability:")
            print(
                result["threat_probability"]
            )

            print("\nPrediction:")
            print(
                result["prediction"]
            )

            print("\nAssessment:")
            print(
                result["analysis"]["assessment"]
            )

            print("\nML Assessment:")
            print(
                result["analysis"]["ml_assessment"]
            )

            print("\nSupporting Evidence:")

            for evidence in result["analysis"][
                "supporting_evidence"
            ]:
                print(
                    f"- {evidence}"
                )

            print("\nContext:")

            for context in result["analysis"]["context"]:
                print(
                    f"- {context}"
                )

            print("\nContent Features:")

            for name, value in result[
                "content_features"
            ].items():
                print(
                    f"- {name}: {value}"
                )

            print("\nURL Intelligence:")

            for name, value in result[
                "url_intelligence"
            ].items():
                if name != "url_details":
                    print(
                        f"- {name}: {value}"
                    )

        except Exception as error:
            print(
                f"\nERROR processing {file_name}:"
            )
            print(error)


if __name__ == "__main__":
    main()