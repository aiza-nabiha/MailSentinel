import os
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
    roc_auc_score,
)

from ..core.text_cleaner import clean_email_text
from ..core.email_features import extract_email_features


# ============================================================
# CONFIG
# ============================================================

TRAIN_PATH = "data/train_dedup.csv"

HOLDOUT_SOURCE = "CEAS-08"

RANDOM_STATE = 42
SVM_C = 1.0
SVM_MAX_ITER = 10000
CALIBRATION_METHOD = "sigmoid"
CALIBRATION_CV = 3

THRESHOLD = 0.50

EXCLUDED_FEATURES = {
    "html_tag_count",
    "html_part_present",
    "link_mismatch_count",
    "attachment_count",
}


# ============================================================
# HELPERS
# ============================================================

def prepare_text(subject, body):
    cleaned_body = clean_email_text(body)

    return (
        "SUBJECT: "
        + str(subject)
        + "\nBODY: "
        + cleaned_body
    )


def split_combined_text(text):
    text = str(text)

    if "\nBODY: " in text:
        subject, body = text.split("\nBODY: ", 1)
        subject = subject.replace("SUBJECT: ", "", 1)
        return subject, body

    return "", text


# ============================================================
# LOAD DATA
# ============================================================

print("=" * 70)
print("SOURCE HOLDOUT GENERALIZATION EXPERIMENT")
print("=" * 70)

df = pd.read_csv(TRAIN_PATH)

print("\nFull dataset:")
print(df.shape)

print("\nDataset sources:")
print(df["dataset_name"].value_counts())


# ============================================================
# HOLD OUT ONE COMPLETE DATASET
# ============================================================

holdout_df = df[df["dataset_name"] == HOLDOUT_SOURCE].copy()
train_df = df[df["dataset_name"] != HOLDOUT_SOURCE].copy()

print("\n" + "=" * 70)
print(f"HOLDING OUT: {HOLDOUT_SOURCE}")
print("=" * 70)

print("\nTraining data:")
print(train_df.shape)

print("\nHoldout data:")
print(holdout_df.shape)

print("\nTraining sources:")
print(train_df["dataset_name"].value_counts())

print("\nHoldout labels:")
print(holdout_df["label"].value_counts())


# ============================================================
# PREPARE TEXT
# ============================================================

print("\nPreparing training text...")

train_texts = [
    prepare_text(subject, body)
    for subject, body in (
        split_combined_text(text)
        for text in train_df["combined_text"].fillna("")
    )
]

print("Preparing holdout text...")

holdout_texts = [
    prepare_text(subject, body)
    for subject, body in (
        split_combined_text(text)
        for text in holdout_df["combined_text"].fillna("")
    )
]


# ============================================================
# TF-IDF
# ============================================================

print("\nFitting TF-IDF...")

vectorizer = TfidfVectorizer(
    lowercase=True,
    strip_accents="unicode",
    ngram_range=(1, 2),
    min_df=3,
    max_df=0.995,
    sublinear_tf=True,
    max_features=150000,
)

X_train_text = vectorizer.fit_transform(train_texts)
X_holdout_text = vectorizer.transform(holdout_texts)

print("Train TF-IDF shape:", X_train_text.shape)
print("Holdout TF-IDF shape:", X_holdout_text.shape)


# ============================================================
# STRUCTURAL FEATURES
# ============================================================

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

holdout_features = pd.DataFrame([
    extract_email_features(
        subject=subject,
        body=body,
    )
    for subject, body in (
        split_combined_text(text)
        for text in holdout_df["combined_text"].fillna("")
    )
])


# ============================================================
# SAME FEATURE SELECTION AS EXPERIMENTAL MODEL
# ============================================================

numeric_feature_names = [
    column
    for column in train_features.columns
    if column != "url_details"
    and column not in EXCLUDED_FEATURES
]

print("\nNumeric features:", len(numeric_feature_names))
print(numeric_feature_names)


# ============================================================
# SCALE NUMERIC FEATURES
# ============================================================

scaler = MaxAbsScaler()

X_train_numeric = scaler.fit_transform(
    train_features[numeric_feature_names]
)

X_holdout_numeric = scaler.transform(
    holdout_features[numeric_feature_names]
)


# ============================================================
# COMBINE TEXT + NUMERIC FEATURES
# ============================================================

X_train = hstack([
    X_train_text,
    csr_matrix(X_train_numeric),
])

X_holdout = hstack([
    X_holdout_text,
    csr_matrix(X_holdout_numeric),
])

y_train = train_df["label"].values
y_holdout = holdout_df["label"].values

print("\nCombined train shape:", X_train.shape)
print("Combined holdout shape:", X_holdout.shape)


# ============================================================
# TRAIN SVM
# ============================================================

print("\nTraining Linear SVM...")

base_svm = LinearSVC(
    C=SVM_C,
    class_weight="balanced",
    max_iter=SVM_MAX_ITER,
    random_state=RANDOM_STATE,
)

classifier = CalibratedClassifierCV(
    estimator=base_svm,
    method=CALIBRATION_METHOD,
    cv=CALIBRATION_CV,
    n_jobs=-1,
)

classifier.fit(X_train, y_train)

print("Training complete.")


# ============================================================
# EVALUATE ON COMPLETELY UNSEEN SOURCE
# ============================================================

print("\n" + "=" * 70)
print(f"RESULTS — UNSEEN SOURCE: {HOLDOUT_SOURCE}")
print("=" * 70)

probabilities = classifier.predict_proba(X_holdout)[:, 1]

predictions = (
    probabilities >= THRESHOLD
).astype(int)

accuracy = accuracy_score(
    y_holdout,
    predictions,
)

roc_auc = roc_auc_score(
    y_holdout,
    probabilities,
)

cm = confusion_matrix(
    y_holdout,
    predictions,
)

tn, fp, fn, tp = cm.ravel()


print(f"\nThreshold: {THRESHOLD}")
print(f"Accuracy:  {accuracy:.4f}")
print(f"ROC-AUC:   {roc_auc:.4f}")

print("\nConfusion Matrix:")
print(cm)

print(f"\nTrue Negatives:  {tn}")
print(f"False Positives: {fp}")
print(f"False Negatives: {fn}")
print(f"True Positives:  {tp}")

print("\nClassification Report:")
print(
    classification_report(
        y_holdout,
        predictions,
        digits=4,
    )
)

print("\n" + "=" * 70)
print("SOURCE HOLDOUT EXPERIMENT COMPLETE")
print("=" * 70)