import joblib
import pandas as pd

from scipy.sparse import hstack, csr_matrix

from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.preprocessing import MaxAbsScaler
from sklearn.svm import LinearSVC
from sklearn.calibration import CalibratedClassifierCV

from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    confusion_matrix,
    roc_auc_score,
)

from ..core.text_cleaner import clean_email_text
from ..core.email_features import extract_email_features


TRAIN_PATH = "data/train_dedup.csv"
TEST_PATH = "data/test_dedup.csv"

RANDOM_STATE = 42
SVM_MAX_ITER = 10000
CALIBRATION_METHOD = "sigmoid"
CALIBRATION_CV = 3

THRESHOLD = 0.50

C_VALUES = [0.1, 0.5, 1.0, 2.0, 5.0]

EXCLUDED_FEATURES = {
    "html_tag_count",
    "html_part_present",
    "link_mismatch_count",
    "attachment_count",
}


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


print("=" * 70)
print("SVM C COMPARISON")
print("=" * 70)


# ============================================================
# LOAD DATA
# ============================================================

train_df = pd.read_csv(TRAIN_PATH)
test_df = pd.read_csv(TEST_PATH)

print("\nTrain:", train_df.shape)
print("Test: ", test_df.shape)


# ============================================================
# PREPARE TEXT
# ============================================================

print("\nPreparing text...")

train_texts = [
    prepare_text(subject, body)
    for subject, body in (
        split_combined_text(text)
        for text in train_df["combined_text"].fillna("")
    )
]

test_texts = [
    prepare_text(subject, body)
    for subject, body in (
        split_combined_text(text)
        for text in test_df["combined_text"].fillna("")
    )
]


# ============================================================
# TF-IDF — DONE ONCE
# ============================================================

print("\nFitting TF-IDF once...")

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
X_test_text = vectorizer.transform(test_texts)

print("Train TF-IDF:", X_train_text.shape)
print("Test TF-IDF: ", X_test_text.shape)


# ============================================================
# STRUCTURAL FEATURES — DONE ONCE
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


# ============================================================
# SAME 19 FEATURES AS CURRENT EXPERIMENTAL MODEL
# ============================================================

numeric_feature_names = [
    column
    for column in train_features.columns
    if column != "url_details"
    and column not in EXCLUDED_FEATURES
]

print("\nNumeric features:", len(numeric_feature_names))


# ============================================================
# SCALE NUMERIC FEATURES — ONCE
# ============================================================

scaler = MaxAbsScaler()

X_train_numeric = scaler.fit_transform(
    train_features[numeric_feature_names]
)

X_test_numeric = scaler.transform(
    test_features[numeric_feature_names]
)


# ============================================================
# COMBINE FEATURES — ONCE
# ============================================================

X_train = hstack([
    X_train_text,
    csr_matrix(X_train_numeric),
])

X_test = hstack([
    X_test_text,
    csr_matrix(X_test_numeric),
])

y_train = train_df["label"].values
y_test = test_df["label"].values

print("\nCombined train:", X_train.shape)
print("Combined test: ", X_test.shape)


# ============================================================
# TEST EACH C
# ============================================================

results = []

for C in C_VALUES:

    print("\n" + "-" * 70)
    print(f"Training SVM with C = {C}")
    print("-" * 70)

    base_svm = LinearSVC(
        C=C,
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

    probabilities = classifier.predict_proba(X_test)[:, 1]

    predictions = (
        probabilities >= THRESHOLD
    ).astype(int)

    accuracy = accuracy_score(y_test, predictions)
    precision = precision_score(y_test, predictions)
    recall = recall_score(y_test, predictions)
    f1 = f1_score(y_test, predictions)
    roc_auc = roc_auc_score(y_test, probabilities)

    tn, fp, fn, tp = confusion_matrix(
        y_test,
        predictions
    ).ravel()

    results.append({
        "C": C,
        "Accuracy": accuracy,
        "Precision": precision,
        "Recall": recall,
        "F1": f1,
        "ROC-AUC": roc_auc,
        "FP": fp,
        "FN": fn,
    })

    print(f"Accuracy:  {accuracy:.4f}")
    print(f"Precision: {precision:.4f}")
    print(f"Recall:    {recall:.4f}")
    print(f"F1:        {f1:.4f}")
    print(f"ROC-AUC:   {roc_auc:.4f}")
    print(f"FP:        {fp}")
    print(f"FN:        {fn}")


# ============================================================
# FINAL COMPARISON
# ============================================================

results_df = pd.DataFrame(results)

print("\n" + "=" * 70)
print("FINAL C COMPARISON")
print("=" * 70)

print(
    results_df.to_string(
        index=False,
        float_format=lambda x: f"{x:.4f}"
    )
)