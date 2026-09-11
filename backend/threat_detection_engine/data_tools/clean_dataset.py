import pandas as pd
import hashlib

TRAIN_PATH = "data/train_prepared.csv"
TEST_PATH = "data/test_prepared.csv"

CLEAN_TRAIN_PATH = "data/train_clean.csv"
CLEAN_TEST_PATH = "data/test_clean.csv"

def normalize_text(text):
    text = str(text).lower()
    text = " ".join(text.split())
    return text

def text_hash(text):
    normalized = normalize_text(text)

    return hashlib.sha256(
        normalized.encode("utf-8")
    ).hexdigest()

print("Loading datasets...")

train_df = pd.read_csv(TRAIN_PATH)
test_df = pd.read_csv(TEST_PATH)

print("Original train rows:", len(train_df))
print("Original test rows :", len(test_df))

print("\nGenerating hashes...")

train_hashes = train_df["combined_text"].apply(text_hash)
test_hashes = test_df["combined_text"].apply(text_hash)

train_hash_set = set(train_hashes)

# Keep only test emails that do NOT already exist in train
test_mask = ~test_hashes.isin(train_hash_set)

clean_test_df = test_df[test_mask].copy()
clean_train_df = train_df.copy()

removed = len(test_df) - len(clean_test_df)

print("\nRemoved train-test duplicate emails:", removed)

print("\nClean dataset sizes:")
print("Train:", len(clean_train_df))
print("Test :", len(clean_test_df))

print("\nClean train label distribution:")
print(clean_train_df["label"].value_counts().sort_index())

print("\nClean test label distribution:")
print(clean_test_df["label"].value_counts().sort_index())

clean_train_df.to_csv(
    CLEAN_TRAIN_PATH,
    index=False
)

clean_test_df.to_csv(
    CLEAN_TEST_PATH,
    index=False
)

print("\nSaved:")
print(" ", CLEAN_TRAIN_PATH)
print(" ", CLEAN_TEST_PATH)