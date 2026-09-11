import pandas as pd
import hashlib

TRAIN_PATH = "data/train_prepared.csv"
TEST_PATH = "data/test_prepared.csv"

print("Loading prepared datasets...")

train_df = pd.read_csv(TRAIN_PATH)
test_df = pd.read_csv(TEST_PATH)

print("Train rows:", len(train_df))
print("Test rows :", len(test_df))

def normalize_text(text):
    text = str(text).lower()
    text = " ".join(text.split())
    return text

def text_hash(text):
    normalized = normalize_text(text)
    return hashlib.sha256(
        normalized.encode("utf-8")
    ).hexdigest()

print("\nGenerating hashes...")

train_hashes = train_df["combined_text"].apply(text_hash)
test_hashes = test_df["combined_text"].apply(text_hash)

print("Checking exact duplicates within datasets...")

train_duplicates = train_hashes.duplicated().sum()
test_duplicates = test_hashes.duplicated().sum()

print("Duplicate emails inside train:", train_duplicates)
print("Duplicate emails inside test :", test_duplicates)

print("\nChecking train-test overlap...")

train_hash_set = set(train_hashes)
test_hash_set = set(test_hashes)

overlap = train_hash_set.intersection(test_hash_set)

print("Exact train-test duplicate emails:", len(overlap))

if len(overlap) == 0:
    print("\n✅ No exact train-test duplicates found.")
else:
    print("\n⚠️ Exact duplicates exist between train and test.")

print("\nChecking label consistency for overlapping emails...")

if overlap:
    train_lookup = {}

    for text_hash_value, label in zip(train_hashes, train_df["label"]):
        train_lookup.setdefault(text_hash_value, set()).add(label)

    conflicting = 0

    for text_hash_value in overlap:
        test_label = test_df.loc[
            test_hashes == text_hash_value,
            "label"
        ].iloc[0]

        if test_label not in train_lookup[text_hash_value]:
            conflicting += 1

    print("Overlapping emails with conflicting labels:", conflicting)
else:
    print("No overlap, so no conflicting labels to check.")