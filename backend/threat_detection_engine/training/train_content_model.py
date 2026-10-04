
import os
import time
import joblib
import pandas as pd

from scipy.sparse import hstack, csr_matrix

from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.preprocessing import MaxAbsScaler
from sklearn.svm import LinearSVC
from sklearn.calibration import CalibratedClassifierCV

from sklearn.metrics import (
    classification_report,
    confusion_matrix,
    accuracy_score,
    roc_auc_score
)

from ..core.text_cleaner import clean_email_text
from ..core.email_features import extract_email_features


# ==================================================
# CONFIGURATION
# ==================================================

TRAIN_PATH = "data/train_dedup.csv"
TEST_PATH = "data/test_dedup.csv"

MODEL_PATH = "ml_models/content_classifier.joblib"

RANDOM_STATE = 42

# Linear SVM configuration
SVM_C = 0.5
SVM_MAX_ITER = 10000

# Calibration configuration
CALIBRATION_METHOD = "sigmoid"
CALIBRATION_CV = 3


# ==================================================
# TEXT PREPARATION
# ==================================================

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


# ==================================================
# LOAD DATASETS
# ==================================================

print("=" * 70)
print("MAILSENTINEL — CALIBRATED LINEAR SVM TRAINING")
print("=" * 70)

print("\nLoading datasets...")

if not os.path.exists(TRAIN_PATH):
    raise FileNotFoundError(
        f"Training dataset not found: {TRAIN_PATH}"
    )

if not os.path.exists(TEST_PATH):
    raise FileNotFoundError(
        f"Testing dataset not found: {TEST_PATH}"
    )

train_df = pd.read_csv(
    TRAIN_PATH
)

test_df = pd.read_csv(
    TEST_PATH
)

required_columns = {
    "combined_text",
    "label"
}

for dataset_name, df in [
    ("Training", train_df),
    ("Testing", test_df)
]:

    missing = required_columns - set(df.columns)

    if missing:
        raise ValueError(
            f"{dataset_name} dataset is missing columns: "
            + ", ".join(sorted(missing))
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
# VALIDATE LABELS
# ==================================================

y_train = train_df["label"].astype(int)
y_test = test_df["label"].astype(int)

if set(y_train.unique()) != {0, 1}:

    raise ValueError(
        "Training labels must be 0 (Legitimate) "
        "and 1 (Threat)."
    )

if set(y_test.unique()) != {0, 1}:

    raise ValueError(
        "Testing labels must be 0 (Legitimate) "
        "and 1 (Threat)."
    )

print("\nTraining label distribution:")
print(y_train.value_counts().sort_index())

print("\nTesting label distribution:")
print(y_test.value_counts().sort_index())


# ==================================================
# PREPARE TRAINING TEXT
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


# ==================================================
# PREPARE TESTING TEXT
# ==================================================

print("\nPreparing testing text...")

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

train_features = pd.DataFrame([
    extract_email_features(
        subject=subject,
        body=body,
    )
    for subject, body in (
        split_combined_text(text)
        for text in train_df["combined_text"].fillna("")
    )
])

test_features = pd.DataFrame([
    extract_email_features(
        subject=subject,
        body=body,
    )
    for subject, body in (
        split_combined_text(text)
        for text in test_df["combined_text"].fillna("")
    )
])

# ==================================================
# CHECK STRUCTURAL FEATURE VARIATION
# ==================================================

print("\nChecking excluded feature values...")

EXCLUDED_FEATURES = {
    "html_tag_count",
    "html_part_present",
    "link_mismatch_count",
    "attachment_count",
}

for feature in sorted(EXCLUDED_FEATURES):
    if feature in train_features.columns:
        print(
            f"{feature}: "
            f"{train_features[feature].nunique()} unique values, "
            f"{(train_features[feature] != 0).sum()} non-zero samples"
        )

print("\nFeature columns:")

for column in train_features.columns:
    print("-", column)


# ==================================================
# SELECT NUMERIC FEATURES
# ==================================================

# Keep only numeric features selected for the production model.
# These four features were always zero in the original training data.

EXCLUDED_FEATURES = {
    "html_tag_count",
    "html_part_present",
    "link_mismatch_count",
    "attachment_count",
}

numeric_feature_names = [
    column
    for column in train_features.columns
    if column != "url_details"
    and column not in EXCLUDED_FEATURES
]

print("\nExcluded features from production model:")
for column in sorted(EXCLUDED_FEATURES):
    print("-", column)

print("\nProduction numeric feature count:", len(numeric_feature_names))

# Ensure train and test feature columns match.
missing_test_features = [
    column
    for column in numeric_feature_names
    if column not in test_features.columns
]

if missing_test_features:

    raise ValueError(
        "Testing data is missing structural features: "
        + ", ".join(missing_test_features)
    )

print("\nNumeric ML features:")

for column in numeric_feature_names:
    print("-", column)


# ==================================================
# SCALE STRUCTURAL FEATURES
# ==================================================

print("\nScaling structural features...")

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
# COMBINE TF-IDF AND STRUCTURAL FEATURES
# ==================================================

print("\nCombining features...")

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
    "Combined train shape:",
    X_train_combined.shape
)

print(
    "Combined test shape :",
    X_test_combined.shape
)


# ==================================================
# TRAIN CALIBRATED LINEAR SVM
# ==================================================

print("\n" + "=" * 70)
print("TRAINING CALIBRATED LINEAR SVM")
print("=" * 70)

base_svm = LinearSVC(
    C=SVM_C,
    class_weight=None,
    max_iter=SVM_MAX_ITER,
    random_state=RANDOM_STATE
)

classifier = CalibratedClassifierCV(
    estimator=base_svm,
    method=CALIBRATION_METHOD,
    cv=CALIBRATION_CV,
    n_jobs=-1
)

start_time = time.time()

classifier.fit(
    X_train_combined,
    y_train
)

training_time = time.time() - start_time

print("\nTraining complete.")

print(
    f"Training time: {training_time:.2f} seconds"
)


# ==================================================
# EVALUATE MODEL
# ==================================================

print("\n" + "=" * 70)
print("EVALUATING CALIBRATED LINEAR SVM")
print("=" * 70)

predictions = classifier.predict(
    X_test_combined
)

probabilities = classifier.predict_proba(
    X_test_combined
)[:, 1]

# ==================================================
# THRESHOLD COMPARISON
# ==================================================

print("\n" + "=" * 70)
print("THRESHOLD COMPARISON")
print("=" * 70)

for threshold in [0.30, 0.40, 0.45, 0.50, 0.55, 0.60, 0.70]:

    threshold_predictions = (
        probabilities >= threshold
    ).astype(int)

    tn, fp, fn, tp = confusion_matrix(
        y_test,
        threshold_predictions,
        labels=[0, 1]
    ).ravel()

    precision = tp / (tp + fp) if (tp + fp) else 0
    recall = tp / (tp + fn) if (tp + fn) else 0

    f1 = (
        2 * precision * recall / (precision + recall)
        if (precision + recall)
        else 0
    )

    print(
        f"Threshold: {threshold:.2f} | "
        f"Precision: {precision:.4f} | "
        f"Recall: {recall:.4f} | "
        f"F1: {f1:.4f} | "
        f"FP: {fp} | FN: {fn}"
    )

accuracy = accuracy_score(
    y_test,
    predictions
)

roc_auc = roc_auc_score(
    y_test,
    probabilities
)

print("\n" + "=" * 60)
print("MAILSENTINEL — V5 MODEL RESULTS")
print("=" * 60)

print(
    f"Model       : Calibrated Linear SVM"
)

print(
    f"Accuracy    : {accuracy:.4f}"
)

print(
    f"ROC-AUC     : {roc_auc:.4f}"
)

print(
    f"Training time: {training_time:.2f} seconds"
)

print("\nClassification Report:")

print(
    classification_report(
        y_test,
        predictions,
        labels=[0, 1],
        target_names=[
            "Legitimate",
            "Threat"
        ],
        zero_division=0
    )
)

print("Confusion Matrix:")

cm = confusion_matrix(
    y_test,
    predictions,
    labels=[0, 1]
)

print(cm)

tn, fp, fn, tp = cm.ravel()

print("\nDetailed Threat Detection Metrics:")

print(
    f"True Negatives  : {tn}"
)

print(
    f"False Positives : {fp}"
)

print(
    f"False Negatives : {fn}"
)

print(
    f"True Positives  : {tp}"
)


# ==================================================
# SAVE MODEL BUNDLE
# ==================================================

print("\n" + "=" * 70)
print("SAVING V5 MODEL")
print("=" * 70)

model_bundle = {

    "vectorizer": vectorizer,

    "scaler": scaler,

    "classifier": classifier,

    "feature_names": numeric_feature_names,

    "version": "v5_calibrated_svm",

    "model_type": "Calibrated Linear SVM",

    "calibration_method": CALIBRATION_METHOD,

    "calibration_cv": CALIBRATION_CV,

    "svm_C": SVM_C,

    "accuracy": float(accuracy),

    "roc_auc": float(roc_auc),

    "training_time_seconds": float(training_time)
}

joblib.dump(
    model_bundle,
    MODEL_PATH,
    compress=3
)

print(
    f"\nProduction model saved to: {MODEL_PATH}"
)

print("\nModel bundle contents:")

for key in model_bundle:
    print("-", key)

print("\nTraining and evaluation finished successfully.")