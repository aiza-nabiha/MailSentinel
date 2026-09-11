import pandas as pd
import hashlib


TRAIN_PATH = "data/train_clean.csv"
TEST_PATH = "data/test_clean.csv"

OUTPUT_TRAIN = "data/train_dedup.csv"
OUTPUT_TEST = "data/test_dedup.csv"


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

print("Original train:", len(train_df))
print("Original test :", len(test_df))


print("\nRemoving duplicate emails from train...")

train_df["_hash"] = train_df["combined_text"].apply(text_hash)

before_train = len(train_df)

train_df = train_df.drop_duplicates(
    subset="_hash",
    keep="first"
).copy()

removed_train = before_train - len(train_df)


print("Removed train duplicates:", removed_train)
print("Clean train:", len(train_df))


print("\nRemoving duplicate emails from test...")

test_df["_hash"] = test_df["combined_text"].apply(text_hash)

before_test = len(test_df)

test_df = test_df.drop_duplicates(
    subset="_hash",
    keep="first"
).copy()

removed_test = before_test - len(test_df)


print("Removed test duplicates:", removed_test)
print("Clean test:", len(test_df))


# Remove temporary hash column
train_df = train_df.drop(columns=["_hash"])
test_df = test_df.drop(columns=["_hash"])


print("\nFinal label distributions:")

print("\nTrain:")
print(train_df["label"].value_counts().sort_index())

print("\nTest:")
print(test_df["label"].value_counts().sort_index())


train_df.to_csv(
    OUTPUT_TRAIN,
    index=False
)

test_df.to_csv(
    OUTPUT_TEST,
    index=False
)


print("\nSaved:")
print(OUTPUT_TRAIN)
print(OUTPUT_TEST)