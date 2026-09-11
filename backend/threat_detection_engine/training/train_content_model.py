import pandas as pd
import joblib

from scipy.sparse import hstack, csr_matrix

from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.preprocessing import MaxAbsScaler
from sklearn.linear_model import LogisticRegression

from sklearn.metrics import (
    classification_report,
    confusion_matrix,
    accuracy_score,
    roc_auc_score
)

from ..core.text_cleaner import clean_email_text
from ..core.email_features import extract_email_features


TRAIN_PATH = "data/train_dedup.csv"
TEST_PATH = "data/test_dedup.csv"

MODEL_PATH = "ml_models/content_classifier.joblib"


def prepare_text(subject, body):

    cleaned_body = clean_email_text(
        body
    )

    return (
        "SUBJECT: "
        + str(subject)
        + "\nBODY: "
        + cleaned_body
    )


def split_combined_text(text):

    text = str(text)

    if "\nBODY: " in text:

        subject, body = text.split(
            "\nBODY: ",
            1
        )

        subject = subject.replace(
            "SUBJECT: ",
            "",
            1
        )

        return subject, body

    return "", text


print("Loading datasets...")

train_df = pd.read_csv(
    TRAIN_PATH
)

test_df = pd.read_csv(
    TEST_PATH
)

print(
    "Training samples:",
    len(train_df)
)

print(
    "Testing samples :",
    len(test_df)
)


# ==================================================
# PREPARE TEXT
# ==================================================

print("\nPreparing training text...")

X_train = []

for text in train_df["combined_text"].fillna(""):

    subject, body = split_combined_text(
        text
    )

    X_train.append(
        prepare_text(
            subject,
            body
        )
    )


print("Preparing testing text...")

X_test = []

for text in test_df["combined_text"].fillna(""):

    subject, body = split_combined_text(
        text
    )

    X_test.append(
        prepare_text(
            subject,
            body
        )
    )


y_train = train_df["label"]

y_test = test_df["label"]


# ==================================================
# TF-IDF
# ==================================================

print("\nCreating TF-IDF features...")

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
    X_train
)

X_test_tfidf = vectorizer.transform(
    X_test
)

print(
    "TF-IDF train shape:",
    X_train_tfidf.shape
)

print(
    "TF-IDF test shape :",
    X_test_tfidf.shape
)


# ==================================================
# STRUCTURAL FEATURES
# ==================================================

print("\nExtracting structural features...")

train_features = pd.DataFrame(
    [
        extract_email_features(
            text
        )
        for text in train_df[
            "combined_text"
        ].fillna("")
    ]
)

test_features = pd.DataFrame(
    [
        extract_email_features(
            text
        )
        for text in test_df[
            "combined_text"
        ].fillna("")
    ]
)


print("\nFeature columns:")

for column in train_features.columns:

    print(
        "-",
        column
    )


# ==================================================
# SCALE STRUCTURAL FEATURES
# ==================================================

print(
    "\nScaling structural features..."
)

numeric_feature_names = [
    column
    for column in train_features.columns
    if column != "url_details"
]

print("\nNumeric ML features:")

for column in numeric_feature_names:
    print(
        "-",
        column
    )

scaler = MaxAbsScaler()

X_train_numeric = scaler.fit_transform(
    train_features[numeric_feature_names]
)

X_test_numeric = scaler.transform(
    test_features[numeric_feature_names]
)

X_train_numeric = csr_matrix(
    X_train_numeric
)

X_test_numeric = csr_matrix(
    X_test_numeric
)


# ==================================================
# COMBINE FEATURES
# ==================================================

X_train_combined = hstack(
    [
        X_train_tfidf,
        X_train_numeric
    ],
    format="csr"
)

X_test_combined = hstack(
    [
        X_test_tfidf,
        X_test_numeric
    ],
    format="csr"
)

print(
    "\nCombined train shape:",
    X_train_combined.shape
)

print(
    "Combined test shape :",
    X_test_combined.shape
)


# ==================================================
# TRAIN
# ==================================================

print(
    "\nTraining V4 model..."
)

classifier = LogisticRegression(
    max_iter=1000,
    class_weight="balanced",
    solver="liblinear"
)

classifier.fit(
    X_train_combined,
    y_train
)

print(
    "Training complete."
)


# ==================================================
# EVALUATE
# ==================================================

print(
    "\nEvaluating V4 model..."
)

predictions = classifier.predict(
    X_test_combined
)

probabilities = classifier.predict_proba(
    X_test_combined
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
    "\n"
    + "=" * 60
)

print(
    "CONTENT CLASSIFIER V4 RESULTS"
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


# ==================================================
# SAVE
# ==================================================

print(
    "\nSaving V4 model..."
)

model_bundle = {

    "vectorizer": vectorizer,

    "scaler": scaler,

    "classifier": classifier,

    "feature_names": numeric_feature_names,

    "version": "v4"
}


joblib.dump(
    model_bundle,
    MODEL_PATH
)


print(
    f"V4 model saved to: {MODEL_PATH}"
)