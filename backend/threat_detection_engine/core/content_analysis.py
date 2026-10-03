import os
import tempfile
import threading

import joblib
import numpy as np
import pandas as pd

from scipy.sparse import hstack, csr_matrix

from .text_cleaner import clean_email_text
from .email_features import extract_email_features
from .explain_content import generate_analysis

from ...infrastructure_engine.qr_ocr_extract import (
    extract_ocr_text,
    extract_qr_urls,
)

from .shap_explainer import ContentSHAPExplainer


# ==========================================================
# MODEL PATH
# ==========================================================

BASE_DIR = os.path.abspath(
    os.path.join(
        os.path.dirname(__file__),
        "..",
        "..",
        "..",
    )
)

MODEL_PATH = os.path.join(
    BASE_DIR,
    "ml_models",
    "content_classifier.joblib",
)


# ==========================================================
# CONTENT ANALYZER
# ==========================================================

class ContentAnalyzer:
    """
    Load and run the trained MailSentinel content model.

    Existing model bundle structure is preserved.
    """

    def __init__(self, model_path=MODEL_PATH):

        self.model_path = model_path

        self.vectorizer = None
        self.shap_explainer = None
        self.scaler = None
        self.classifier = None

        self.ml_feature_names = None
        self.metadata = {}

        self._loaded = False

        # Prevent simultaneous duplicate initialization.
        self._load_lock = threading.Lock()

    # ======================================================
    # MODEL LOADING
    # ======================================================

    def load_model(self):
        """
        Load model bundle and validate feature names.
        """

        if self._loaded:
            return

        with self._load_lock:

            if self._loaded:
                return

            if not os.path.exists(self.model_path):
                raise FileNotFoundError(
                    "Content classifier not found: "
                    + self.model_path
                )

            bundle = joblib.load(
                self.model_path
            )

            required_keys = {
                "vectorizer",
                "scaler",
                "classifier",
                "feature_names",
            }

            missing_keys = (
                required_keys - set(bundle.keys())
            )

            if missing_keys:
                raise ValueError(
                    "Invalid model bundle. Missing keys: "
                    + ", ".join(sorted(missing_keys))
                )

            self.vectorizer = bundle["vectorizer"]
            self.scaler = bundle["scaler"]
            self.classifier = bundle["classifier"]

            self.ml_feature_names = list(
                bundle["feature_names"]
            )

            self.shap_explainer = ContentSHAPExplainer(
                vectorizer=self.vectorizer,
                scaler=self.scaler,
                classifier=self.classifier,
                feature_names=self.ml_feature_names,
                top_k=10,
            )

            self.metadata = bundle.get(
                "metadata",
                {},
            )

            # --------------------------------------------------
            # Validate feature names against scaler
            # --------------------------------------------------

            scaler_feature_names = getattr(
                self.scaler,
                "feature_names_in_",
                None,
            )

            if scaler_feature_names is not None:

                scaler_feature_names = list(
                    scaler_feature_names
                )

                if (
                    scaler_feature_names
                    != self.ml_feature_names
                ):
                    raise ValueError(
                        "Model feature mismatch: scaler "
                        "feature_names_in_ does not match "
                        "bundle feature_names."
                    )

            # --------------------------------------------------
            # Validate feature count
            # --------------------------------------------------

            expected_feature_count = getattr(
                self.scaler,
                "n_features_in_",
                None,
            )

            if (
                expected_feature_count is not None
                and expected_feature_count
                != len(self.ml_feature_names)
            ):
                raise ValueError(
                    "Model feature count mismatch: "
                    f"scaler expects {expected_feature_count}, "
                    f"but bundle contains "
                    f"{len(self.ml_feature_names)} names."
                )

            # --------------------------------------------------
            # Check predict_proba availability
            # --------------------------------------------------

            if not hasattr(
                self.classifier,
                "predict_proba",
            ):
                raise ValueError(
                    "Classifier does not support "
                    "predict_proba()."
                )

            self._loaded = True

    # ======================================================
    # TEXT PREPARATION
    # ======================================================

    @staticmethod
    def _prepare_text(subject, body):
        """
        Prepare text using the same preprocessing
        format used during model training.
        """

        subject = str(subject or "")
        cleaned_body = clean_email_text(
            body
        )

        return (
            "SUBJECT: "
            + subject
            + "\nBODY: "
            + cleaned_body
        )

    # ======================================================
    # NUMERIC FEATURE PREPARATION
    # ======================================================

    def _prepare_numeric_features(self, features):
        """
        Select numerical features in the exact trained
        model feature order.
        """

        if not self.ml_feature_names:
            raise ValueError(
                "Model feature names are not loaded."
            )

        missing_features = [
            name
            for name in self.ml_feature_names
            if name not in features
        ]

        if missing_features:
            raise ValueError(
                "Missing features required by the model: "
                + ", ".join(missing_features)
            )

        # Build DataFrame in the model's exact feature order.
        feature_row = {
            name: features[name]
            for name in self.ml_feature_names
        }

        feature_df = pd.DataFrame(
            [feature_row],
            columns=self.ml_feature_names,
        )

        # Reject unexpected non-numeric values rather
        # than silently coercing them to arbitrary values.
        for column in feature_df.columns:

            feature_df[column] = pd.to_numeric(
                feature_df[column],
                errors="raise",
            )

        # Prevent NaN and infinity from reaching the model.
        feature_df = feature_df.replace(
            [np.inf, -np.inf],
            np.nan,
        )

        if feature_df.isnull().values.any():
            raise ValueError(
                "Numeric feature extraction produced "
                "missing or non-finite values."
            )

        return feature_df

    # ======================================================
    # MAIN ANALYSIS
    # ======================================================

    def analyze(
        self,
        subject="",
        body="",
        content=None,
    ):
        """
        Analyze an email's content.

        Parameters
        ----------
        subject:
            Email subject.

        body:
            Email body text.

        content:
            Optional structured dictionary returned by
            extract_email_content().
        """

        self.load_model()

        content = content or {}

        # --------------------------------------------------
        # Resolve subject and body
        # --------------------------------------------------

        subject = (
            subject
            or content.get("subject", "")
        )

        plain_text = content.get(
            "plain_text",
            "",
        )

        html_text = content.get(
            "html_text",
            "",
        )

        combined_text = content.get(
            "combined_text",
            "",
        )

        if not combined_text:
            combined_text = (
                plain_text
                or html_text
                or body
                or ""
            )

        if not body:
            body = combined_text

        # --------------------------------------------------
        # Extract URLs and email features
        # --------------------------------------------------

        urls = content.get(
            "urls",
            [],
        )

        attachments = content.get(
            "attachments",
            [],
        )

        # OCR / QR analysis for image attachments

        ocr_text_parts = []
        ocr_urls = []
        qr_urls = []

        for attachment in attachments:

            content_type = str(
                attachment.get("content_type", "")
            ).lower()

            attachment_bytes = attachment.get("content")

            if (
                not content_type.startswith("image/")
                or not attachment_bytes
            ):
                continue

            temp_path = None

            try:
                suffix = os.path.splitext(
                    attachment.get("filename") or ""
                )[1]

                if not suffix:
                    suffix = ".img"

                with tempfile.NamedTemporaryFile(
                    suffix=suffix,
                    delete=False,
                ) as temp_file:
                    temp_file.write(attachment_bytes)
                    temp_path = temp_file.name

                # OCR → content ML
                extracted_ocr = extract_ocr_text(temp_path)

                if extracted_ocr:
                    extracted_ocr = str(extracted_ocr).strip()

                    ocr_text_parts.append(
                        extracted_ocr
                    )

                    # Extract URLs reconstructed from OCR text.
                    from ...infrastructure_engine.qr_ocr_extract import (
                        extract_urls_from_text,
                    )

                    extracted_ocr_urls = extract_urls_from_text(
                        extracted_ocr
                    )

                    if extracted_ocr_urls:
                        ocr_urls.extend(
                            str(url).strip()
                            for url in extracted_ocr_urls
                            if url
                        )

                # QR → URL analysis
                extracted_qr = extract_qr_urls(temp_path)

                if extracted_qr:
                    qr_urls.extend(
                        str(url).strip()
                        for url in extracted_qr
                        if url
                    )

            except Exception:
                # OCR/QR failure should not break normal email analysis.
                continue

            finally:
                if temp_path and os.path.exists(temp_path):
                    try:
                        os.remove(temp_path)
                    except OSError:
                        pass

        # --------------------------------------------------
        # Merge OCR text and QR URLs into email analysis
        # --------------------------------------------------

        if ocr_text_parts:
            ocr_text = "\n".join(ocr_text_parts)

            combined_text = (
                str(combined_text or "")
                + "\n"
                + ocr_text
            ).strip()

            body = (
                str(body or "")
                + "\n"
                + ocr_text
            ).strip()

        # --------------------------------------------------
        # Merge OCR-derived and QR-derived URLs
        # --------------------------------------------------

        image_urls = list(
            dict.fromkeys(
                [
                    *ocr_urls,
                    *qr_urls,
                ]
            )
        )

        if image_urls:
            urls = list(
                dict.fromkeys(
                    [
                        *urls,
                        *image_urls,
                    ]
                )
            )

        html_source = content.get(
            "html_source",
            "",
        )

        mailto_links = content.get(
            "mailto_links",
            [],
        )

        html_links = content.get(
            "html_links",
            [],
        )

        features = extract_email_features(
            subject=subject,
            body=body,
            urls=urls,
            attachments=attachments,
            html_source=html_source,
            mailto_links=mailto_links,
            html_links=html_links,
        )

        # --------------------------------------------------
        # Include text for explanation context
        # --------------------------------------------------

        features["analysis_text"] = (
            str(subject or "")
            + "\n"
            + str(combined_text or "")
        )

        # --------------------------------------------------
        # TF-IDF transformation
        # --------------------------------------------------

        text_for_model = self._prepare_text(
            subject,
            combined_text,
        )

        text_vector = self.vectorizer.transform(
            [text_for_model]
        )

        # --------------------------------------------------
        # Numeric feature transformation
        # --------------------------------------------------

        feature_df = self._prepare_numeric_features(
            features
        )

        scaled_features = self.scaler.transform(
            feature_df
        )

        numeric_matrix = csr_matrix(
            scaled_features
        )

        # --------------------------------------------------
        # Combine text and numeric features
        # --------------------------------------------------

        model_input = hstack(
            [
                text_vector,
                numeric_matrix,
            ],
            format="csr",
        )

        # --------------------------------------------------
        # SHAP explanation
        # --------------------------------------------------

        shap_explanation = None

        try:
            if self.shap_explainer is not None:
                shap_explanation = (
                    self.shap_explainer.explain(
                        model_input
                    )
                )

        except Exception as exc:
            shap_explanation = {
                "error": str(exc),
            }

        # --------------------------------------------------
        # Predict probability
        # --------------------------------------------------

        probabilities = self.classifier.predict_proba(
            model_input
        )[0]

        classes = list(
            self.classifier.classes_
        )

        if 1 not in classes:
            raise ValueError(
                "Classifier does not contain class 1 "
                "for the phishing label."
            )

        phishing_index = classes.index(1)

        threat_probability = float(
            probabilities[phishing_index]
        )

        if not np.isfinite(threat_probability):
            raise ValueError(
                "Classifier returned a non-finite "
                "phishing probability."
            )

        threat_probability = max(
            0.0,
            min(1.0, threat_probability),
        )

        # --------------------------------------------------
        # Classification threshold
        # --------------------------------------------------

        prediction = (
            "phishing"
            if threat_probability >= 0.50
            else "legitimate"
        )

        # --------------------------------------------------
        # Generate explanations
        # --------------------------------------------------

        sender_features = content.get(
            "sender_features",
            {},
        )

        analysis = generate_analysis(
            probability=threat_probability,
            features=features,
            sender_features=sender_features,
        )

        # --------------------------------------------------
        # Prepare URL intelligence
        # --------------------------------------------------

        url_intelligence = {
            "url_count": features["url_count"],
            "ip_url_count": features["ip_url_count"],
            "shortener_count": features["shortener_count"],
            "long_url_count": features["long_url_count"],
            "tracking_url_count": features["tracking_url_count"],
            "redirect_url_count": features["redirect_url_count"],
            "url_details": features["url_details"],
        }

        url_intelligence["ocr_urls"] = list(
            dict.fromkeys(ocr_urls)
        )

        url_intelligence["qr_urls"] = list(
            dict.fromkeys(qr_urls)
        )

        url_intelligence["image_url_count"] = len(
            set(ocr_urls + qr_urls)
        )

        # --------------------------------------------------
        # Prepare email structure
        # --------------------------------------------------

        email_structure = {
            "html_part_count": content.get(
                "html_part_count",
                0,
            ),

            "plain_part_count": content.get(
                "plain_part_count",
                0,
            ),

            "html_part_present": features[
                "html_part_present"
            ],

            "html_tag_count": features[
                "html_tag_count"
            ],

            "attachment_count": features[
                "attachment_count"
            ],

            "mailto_count": features[
                "mailto_count"
            ],
        }

        # --------------------------------------------------
        # Exclude descriptive/non-ML fields
        # --------------------------------------------------

        content_features = {
            key: value
            for key, value in features.items()
            if key not in {
                "url_details",
                "analysis_text",
            }
        }

        # --------------------------------------------------
        # Return API-compatible result
        # --------------------------------------------------

        return {
            "threat_probability": threat_probability,

            "shap_explanation": shap_explanation,

            "prediction": prediction,

            "analysis": analysis,

            "content_features": content_features,

            "url_intelligence": url_intelligence,

            "sender_features": sender_features,

            "email_structure": email_structure,
        }


# ==========================================================
# SINGLETON ANALYZER
# ==========================================================

_analyzer = None
_analyzer_lock = threading.Lock()


def get_analyzer():
    """
    Return the cached analyzer instance.
    """

    global _analyzer

    if _analyzer is None:

        with _analyzer_lock:

            if _analyzer is None:
                _analyzer = ContentAnalyzer()

    return _analyzer


# ==========================================================
# PUBLIC API
# ==========================================================

def analyze_email_content(
    subject="",
    body="",
    content=None,
):
    """
    Public entry point for content analysis.

    Supports both:
        analyze_email_content(subject, body)

    and:
        analyze_email_content(content=extracted_content)
    """

    analyzer = get_analyzer()

    if content is None:
        content = {
            "subject": subject or "",
            "plain_text": body or "",
            "html_text": "",
            "html_source": "",
            "combined_text": body or "",
            "urls": [],
            "attachments": [],
            "mailto_links": [],
            "html_links": [],
            "sender_features": {},
            "html_part_count": 0,
            "plain_part_count": 1 if body else 0,
        }

    return analyzer.analyze(
        subject=subject,
        body=body,
        content=content,
    )

# ==========================================================
# BACKEND COMPATIBILITY FUNCTIONS
# ==========================================================

def get_content_analyzer():
    """
    Return the shared content analyzer and load
    the existing trained V5 model.
    """
    analyzer = get_analyzer()
    analyzer.load_model()
    return analyzer


def analyze_email_file(eml_path):
    """
    Extract an EML file and run the trained
    content classifier on its contents.
    """
    from .email_content_extractor import extract_email_content

    extracted_content = extract_email_content(eml_path)

    return analyze_email_content(
        content=extracted_content
    )