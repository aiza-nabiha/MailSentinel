from pathlib import Path
import os
import joblib
import pandas as pd

from scipy.sparse import hstack, csr_matrix

from .text_cleaner import clean_email_text
from .email_features import extract_email_features
from .explain_content import generate_analysis
from .email_content_extractor import extract_email_content


PROJECT_ROOT = Path(__file__).resolve().parents[3]

MODEL_PATH = (
    PROJECT_ROOT
    / "ml_models"
    / "content_classifier.joblib"
)


class ContentAnalyzer:

    def __init__(self, model_path=MODEL_PATH):

        if not os.path.exists(model_path):
            raise FileNotFoundError(
                f"Model not found: {model_path}"
            )

        bundle = joblib.load(model_path)

        self.vectorizer = bundle["vectorizer"]
        self.scaler = bundle["scaler"]
        self.classifier = bundle["classifier"]

        if "feature_names" not in bundle:
            raise ValueError(
                "V4 model bundle does not contain feature_names."
            )

        self.ml_feature_names = list(
            bundle["feature_names"]
        )

        if hasattr(self.scaler, "feature_names_in_"):
            scaler_feature_names = list(
                self.scaler.feature_names_in_
            )

            if scaler_feature_names != self.ml_feature_names:
                raise ValueError(
                    "V4 feature-name mismatch between "
                    "model bundle and scaler."
                )
        else:
            raise ValueError(
                "Scaler does not contain feature_names_in_."
            )

    def analyze_extracted_content(self, content):

        subject = content.get("subject", "")
        combined_body = content.get("combined_text", "")

        cleaned_body = clean_email_text(
            combined_body
        )

        combined_text = (
            "SUBJECT: "
            + str(subject)
            + "\nBODY: "
            + cleaned_body
        )

        text_features = self.vectorizer.transform(
            [combined_text]
        )

        features = extract_email_features(
            combined_text,
            urls=content.get("urls", []),
            attachments=content.get("attachments", []),
            html_source=content.get("html_source", ""),
            mailto_links=content.get("mailto_links", []),
            html_links=content.get("html_links", [])
        )

        feature_df = pd.DataFrame([features])

        missing_features = [
            feature
            for feature in self.ml_feature_names
            if feature not in feature_df.columns
        ]

        if missing_features:
            raise ValueError(
                "Missing features required by V4: "
                + ", ".join(missing_features)
            )

        ml_feature_df = feature_df[
            self.ml_feature_names
        ]

        numeric_features = self.scaler.transform(
            ml_feature_df
        )

        combined_features = hstack(
            [
                text_features,
                csr_matrix(numeric_features)
            ],
            format="csr"
        )

        probability = (
            self.classifier
            .predict_proba(
                combined_features
            )[0][1]
        )

        prediction = (
            "threat"
            if probability >= 0.5
            else "legitimate"
        )

        sender_features = content.get(
            "sender_features",
            {}
        )

        analysis = generate_analysis(
            threat_probability=float(probability),
            features=features,
            content=content
        )

        url_intelligence = {
            "url_count": features.get(
                "url_count",
                0
            ),
            "ip_url_count": features.get(
                "ip_url_count",
                0
            ),
            "shortener_count": features.get(
                "shortener_count",
                0
            ),
            "long_url_count": features.get(
                "long_url_count",
                0
            ),
            "tracking_url_count": features.get(
                "tracking_url_count",
                0
            ),
            "redirect_url_count": features.get(
                "redirect_url_count",
                0
            ),
            "link_mismatch_count": features.get(
                "link_mismatch_count",
                0
            ),
            "url_details": features.get(
                "url_details",
                []
            )
        }

        content_features = {
            name: value
            for name, value in features.items()
            if name not in {
                "url_details",
                "url_count",
                "ip_url_count",
                "shortener_count",
                "long_url_count",
                "tracking_url_count",
                "redirect_url_count",
                "link_mismatch_count"
            }
        }

        return {
            "threat_probability": round(
                float(probability),
                4
            ),
            "prediction": prediction,
            "analysis": analysis,
            "content_features": content_features,
            "url_intelligence": url_intelligence,
            "sender_features": sender_features,
            "email_structure": {
                "plain_part_count": content.get(
                    "plain_part_count",
                    0
                ),
                "html_part_count": content.get(
                    "html_part_count",
                    0
                ),
                "url_count": len(
                    content.get(
                        "urls",
                        []
                    )
                ),
                "mailto_count": len(
                    content.get(
                        "mailto_links",
                        []
                    )
                ),
                "attachment_count": len(
                    content.get(
                        "attachments",
                        []
                    )
                )
            }
        }

    def analyze_eml(self, eml_path):

        content = extract_email_content(
            eml_path
        )

        return self.analyze_extracted_content(
            content
        )


def analyze_email_content(
    subject="",
    body=""
):

    analyzer = ContentAnalyzer()

    content = {
        "subject": subject,
        "combined_text": body,
        "plain_text": body,
        "html_source": "",
        "html_text": "",
        "html_links": [],
        "urls": [],
        "mailto_links": [],
        "attachments": [],
        "sender_features": {},
        "html_part_count": 0,
        "plain_part_count": 1 if body else 0
    }

    return analyzer.analyze_extracted_content(
        content
    )


def analyze_email_file(eml_path):

    analyzer = ContentAnalyzer()

    return analyzer.analyze_eml(
        eml_path
    )


if __name__ == "__main__":

    EML_PATH = (
        "data/test_emails/example.eml"
    )

    print("\n" + "=" * 70)
    print("REAL EMAIL CONTENT ANALYSIS")
    print("=" * 70)

    content = extract_email_content(
        EML_PATH
    )

    print("\nSubject:")
    print(content["subject"])

    print("\nEmail structure:")
    print(
        "- Plain-text parts:",
        content["plain_part_count"]
    )
    print(
        "- HTML parts:",
        content["html_part_count"]
    )
    print(
        "- URLs:",
        len(content["urls"])
    )
    print(
        "- Mailto links:",
        len(content["mailto_links"])
    )
    print(
        "- Attachments:",
        len(content["attachments"])
    )

    cleaned_preview = clean_email_text(
        content["combined_text"]
    )

    print("\n" + "=" * 70)
    print("CLEANED CONTENT PREVIEW")
    print("=" * 70)
    print(cleaned_preview[:3000])

    sender = content["sender_features"]

    print("\n" + "=" * 70)
    print("SENDER INFORMATION")
    print("=" * 70)

    print(
        "- From:",
        sender.get("from_address")
    )
    print(
        "- From domain:",
        sender.get("from_domain")
    )
    print(
        "- Reply-To:",
        sender.get("reply_to_address")
    )
    print(
        "- Reply-To domain:",
        sender.get("reply_to_domain")
    )
    print(
        "- Reply-To mismatch:",
        sender.get("reply_to_mismatch")
    )
    print(
        "- Return-Path:",
        sender.get("return_path_address")
    )
    print(
        "- Return-Path domain:",
        sender.get("return_path_domain")
    )
    print(
        "- Return-Path mismatch:",
        sender.get("return_path_mismatch")
    )

    analyzer = ContentAnalyzer()

    result = analyzer.analyze_extracted_content(
        content
    )

    analysis = result["analysis"]

    print("\n" + "=" * 70)
    print("ANALYST ASSESSMENT")
    print("=" * 70)

    print(
        "\nML assessment:",
        analysis["ml_assessment"]
    )

    print(
        "\nThreat probability:",
        result["threat_probability"]
    )

    print("\nSupporting evidence:")

    for evidence in analysis[
        "supporting_evidence"
    ]:
        print(evidence)

    print("\nContext:")

    for context in analysis["context"]:
        print(context)

    print("\nAssessment:")
    print(analysis["assessment"])

    print("\n" + "=" * 70)
    print("CONTENT FEATURES")
    print("=" * 70)

    for name, value in result[
        "content_features"
    ].items():
        print(
            f"- {name}: {value}"
        )

    print("\n" + "=" * 70)
    print("URL INTELLIGENCE")
    print("=" * 70)

    url_intelligence = result[
        "url_intelligence"
    ]

    print(
        "- URL count:",
        url_intelligence["url_count"]
    )

    print(
        "- IP-based URLs:",
        url_intelligence["ip_url_count"]
    )

    print(
        "- Shorteners:",
        url_intelligence["shortener_count"]
    )

    print(
        "- Long URLs:",
        url_intelligence["long_url_count"]
    )

    print(
        "- Tracking URLs:",
        url_intelligence["tracking_url_count"]
    )

    print(
        "- Redirect URLs:",
        url_intelligence["redirect_url_count"]
    )

    print(
        "- Link mismatches:",
        url_intelligence["link_mismatch_count"]
    )

    print("\nPer-URL details:")

    for url in url_intelligence[
        "url_details"
    ]:
        print(url)