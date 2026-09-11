import pandas as pd

from scipy.sparse import hstack, csr_matrix

from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.preprocessing import MaxAbsScaler
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    accuracy_score,
    roc_auc_score,
    classification_report,
    confusion_matrix
)

from ..core.email_features import extract_email_features
from ..core.text_cleaner import clean_email_text


DATA_PATH = "data/train_dedup.csv"
HELD_OUT_SOURCE = "Ling"


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
# Load dataset
# --------------------------------------------------

print("Loading dataset...")

df = pd.read_csv(
    DATA_PATH
)

print(
    "Total samples:",
    len(df)
)

train_df = df[
    df["dataset_name"] != HELD_OUT_SOURCE
].copy()

test_df = df[
    df["dataset_name"] == HELD_OUT_SOURCE
].copy()

print(
    "\nHeld-out source:",
    HELD_OUT_SOURCE
)

print(
    "Training samples:",
    len(train_df)
)

print(
    "Testing samples :",
    len(test_df)
)


# --------------------------------------------------
# Prepare text
# --------------------------------------------------

def prepare_text(text):

    text = str(text)

    if "\nBODY: " in text:

        subject, body = text.split(
            "\nBODY: ",
            1
        )

    else:

        subject = text
        body = ""

    subject = subject.replace(
        "SUBJECT: ",
        "",
        1
    )

    cleaned_body = clean_email_text(
        body
    )

    return (
        "SUBJECT: "
        + subject
        + "\nBODY: "
        + cleaned_body
    )


print(
    "\nPreparing training text..."
)

X_train_text = [
    prepare_text(text)
    for text in train_df[
        "combined_text"
    ].fillna("")
]

print(
    "Preparing testing text..."
)

X_test_text = [
    prepare_text(text)
    for text in test_df[
        "combined_text"
    ].fillna("")
]

y_train = train_df[
    "label"
]

y_test = test_df[
    "label"
]


# --------------------------------------------------
# TF-IDF
# --------------------------------------------------

print(
    "\nCreating TF-IDF features..."
)

vectorizer = TfidfVectorizer(
    lowercase=True,
    strip_accents="unicode",
    ngram_range=(1, 2),
    min_df=3,
    max_df=0.995,
    sublinear_tf=True,
    max_features=150000
)

X_train_tfidf = vectorizer.fit_transform(
    X_train_text
)

X_test_tfidf = vectorizer.transform(
    X_test_text
)

print(
    "TF-IDF train shape:",
    X_train_tfidf.shape
)

print(
    "TF-IDF test shape:",
    X_test_tfidf.shape
)


# --------------------------------------------------
# Structural features
# --------------------------------------------------

print(
    "\nExtracting structural features..."
)

train_features = pd.DataFrame(
    [
        extract_email_features(text)
        for text in train_df[
            "combined_text"
        ].fillna("")
    ]
)

test_features = pd.DataFrame(
    [
        extract_email_features(text)
        for text in test_df[
            "combined_text"
        ].fillna("")
    ]
)

# Select only the numeric features used
# by the V4 classifier.
#
# url_details is intentionally excluded because
# it contains a list of URL-analysis dictionaries.
train_features = train_features[
    ML_FEATURE_NAMES
]

test_features = test_features[
    ML_FEATURE_NAMES
]

print(
    "Numeric feature count:",
    len(ML_FEATURE_NAMES)
)

scaler = MaxAbsScaler()

X_train_numeric = scaler.fit_transform(
    train_features
)

X_test_numeric = scaler.transform(
    test_features
)

X_train_numeric = csr_matrix(
    X_train_numeric
)

X_test_numeric = csr_matrix(
    X_test_numeric
)


# --------------------------------------------------
# Combine
# --------------------------------------------------

X_train = hstack(
    [
        X_train_tfidf,
        X_train_numeric
    ],
    format="csr"
)

X_test = hstack(
    [
        X_test_tfidf,
        X_test_numeric
    ],
    format="csr"
)

print(
    "\nCombined train shape:",
    X_train.shape
)

print(
    "Combined test shape:",
    X_test.shape
)


# --------------------------------------------------
# Train
# --------------------------------------------------

print(
    "\nTraining V4-style model..."
)

classifier = LogisticRegression(
    max_iter=1000,
    class_weight="balanced",
    solver="liblinear"
)

classifier.fit(
    X_train,
    y_train
)

print(
    "Training complete."
)


# --------------------------------------------------
# Evaluate
# --------------------------------------------------

print(
    "\nEvaluating on unseen source..."
)

predictions = classifier.predict(
    X_test
)

probabilities = classifier.predict_proba(
    X_test
)[:, 1]

accuracy = accuracy_score(
    y_test,
    predictions
)

roc_auc = roc_auc_score(
    y_test,
    probabilities
)


print(
    "\n" + "=" * 60
)

print(
    "V4 — UNSEEN SOURCE GENERALIZATION"
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
        y_test,
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
        y_test,
        predictions
    )
)

print(
    "\nUnseen-source evaluation complete."
)