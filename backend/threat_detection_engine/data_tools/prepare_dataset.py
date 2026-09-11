from datasets import load_dataset
import pandas as pd

DATASET_NAME = "puyang2025/seven-phishing-email-datasets"

print("Loading dataset...")
ds = load_dataset(DATASET_NAME)

def prepare_split(split):
    df = split.to_pandas()

    print("\nOriginal rows:", len(df))

    # Remove rows with empty email body
    df = df[df["text"].fillna("").str.strip() != ""]

    print("After removing empty text:", len(df))

    # Combine subject and body
    df["subject"] = df["subject"].fillna("").astype(str)
    df["text"] = df["text"].fillna("").astype(str)

    df["combined_text"] = (
        "SUBJECT: "
        + df["subject"]
        + "\nBODY: "
        + df["text"]
    )

    # Keep only the fields needed for the baseline classifier
    df = df[
        [
            "combined_text",
            "label",
            "dataset_name"
        ]
    ]

    return df

train_df = prepare_split(ds["train"])
test_df = prepare_split(ds["test"])

print("\nFinal dataset sizes:")
print("Train:", len(train_df))
print("Test :", len(test_df))

print("\nTrain label distribution:")
print(train_df["label"].value_counts().sort_index())

print("\nTest label distribution:")
print(test_df["label"].value_counts().sort_index())

print("\nSample prepared email:")
print(train_df.iloc[0]["combined_text"][:1000])

# Save locally
train_df.to_csv(
    "data/train_prepared.csv",
    index=False
)

test_df.to_csv(
    "data/test_prepared.csv",
    index=False
)

print("\nSaved:")
print("  data/train_prepared.csv")
print("  data/test_prepared.csv")