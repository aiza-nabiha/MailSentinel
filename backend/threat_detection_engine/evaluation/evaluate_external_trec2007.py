import pandas as pd
import joblib
from pathlib import Path
from scipy.sparse import hstack, csr_matrix

from sklearn.metrics import (
    accuracy_score,
    roc_auc_score,
    classification_report,
    confusion_matrix
)

from ..core.email_features import extract_email_features
from ..core.text_cleaner import clean_email_text


DATA_PATH = "data/trec2007_prepared.csv"
PROJECT_ROOT = Path(__file__).resolve().parents[3]

MODEL_PATH = (
    PROJECT_ROOT
    / "ml_models"
    / "content_classifier.joblib"
)


# --------------------------------------------------
# V4 ML features
# --------------------------------------------------

ML_FEATURE_NAMES = [
    "text_length",
    "word_count",
    "url_count",
    "ip_url_count",
    "shortener_count",
    "long_url_count",
    "tracking_url_count",
    "redirect_url_count",
    "mailto_count",
    "email_count",
    "html_tag_count",
    "html_part_present",
    "link_mismatch_count",
    "digit_count",
    "uppercase_ratio",
    "exclamation_count",
    "question_count",
    "urgency_count",
    "credential_count",
    "attachment_count",
    "attachment_language_count",
    "financial_count",
    "non_ascii_count"
]


# --------------------------------------------------
# Load external dataset
# --------------------------------------------------

print(
    "Loading TREC-2007 external dataset..."
)

df = pd.read_csv(
    DATA_PATH
)

X_text = df[
    "combined_text"
].fillna("")

y_true = df[
    "label"
]

print(
    "External test samples:",
    len(df)
)


# --------------------------------------------------
# Load V4 model
# --------------------------------------------------

print(
    "\nLoading V4 model..."
)

bundle = joblib.load(MODEL_PATH)

vectorizer = bundle[
    "vectorizer"
]

scaler = bundle[
    "scaler"
]

classifier = bundle[
    "classifier"
]

model_feature_names = list(
    bundle[
        "feature_names"
    ]
)

if model_feature_names != ML_FEATURE_NAMES:
    raise ValueError(
        "V4 model feature names do not match "
        "the expected ML feature order."
    )

print(
    "V4 model loaded successfully."
)

print(
    "Numeric feature count:",
    len(ML_FEATURE_NAMES)
)


# --------------------------------------------------
# Prepare text
# --------------------------------------------------

print(
    "\nPreparing external text..."
)

cleaned_texts = []

for text in X_text:

    text = str(
        text
    )

    if "\nBODY: " in text:

        subject, body = text.split(
            "\nBODY: ",
            1
        )

    else:

        subject = text
        body = ""

    cleaned_body = clean_email_text(
        body
    )

    combined = (
        "SUBJECT: "
        + subject.replace(
            "SUBJECT: ",
            "",
            1
        )
        + "\nBODY: "
        + cleaned_body
    )

    cleaned_texts.append(
        combined
    )


# --------------------------------------------------
# TF-IDF
# --------------------------------------------------

print(
    "\nCreating TF-IDF features..."
)

X_tfidf = vectorizer.transform(
    cleaned_texts
)

print(
    "TF-IDF shape:",
    X_tfidf.shape
)


# --------------------------------------------------
# Structural features
# --------------------------------------------------

print(
    "\nExtracting structural features..."
)

features = pd.DataFrame(
    [
        extract_email_features(text)
        for text in X_text
    ]
)

# Select only the 23 numeric features
# used by the V4 classifier.
#
# url_details is intentionally excluded
# because it contains a list of dictionaries
# and is not an ML feature.

features = features[
    ML_FEATURE_NAMES
]

X_numeric = scaler.transform(
    features
)

X_numeric = csr_matrix(
    X_numeric
)

print(
    "Numeric feature shape:",
    X_numeric.shape
)


# --------------------------------------------------
# Combine features
# --------------------------------------------------

X_external = hstack(
    [
        X_tfidf,
        X_numeric
    ],
    format="csr"
)

print(
    "Combined feature shape:",
    X_external.shape
)


# --------------------------------------------------
# Prediction
# --------------------------------------------------

print(
    "\nRunning V4 predictions..."
)

predictions = classifier.predict(
    X_external
)

probabilities = classifier.predict_proba(
    X_external
)[:, 1]


# --------------------------------------------------
# Metrics
# --------------------------------------------------

accuracy = accuracy_score(
    y_true,
    predictions
)

roc_auc = roc_auc_score(
    y_true,
    probabilities
)


print(
    "\n" + "=" * 60
)

print(
    "V4 — EXTERNAL TREC-2007 RESULTS"
)

print(
    "=" * 60
)

print(
    f"Accuracy : {accuracy:.4f}"
)

print(
    f"ROC-AUC  : {roc_auc:.4f}"
)


print(
    "\nClassification Report:"
)

print(
    classification_report(
        y_true,
        predictions,
        target_names=[
            "Legitimate",
            "Threat"
        ]
    )
)


print(
    "Confusion Matrix:"
)

print(
    confusion_matrix(
        y_true,
        predictions
    )
)


print(
    "\nExternal evaluation complete."
)