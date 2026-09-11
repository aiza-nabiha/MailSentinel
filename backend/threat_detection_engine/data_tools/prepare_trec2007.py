import pandas as pd

INPUT_PATH = "data/trec2007.csv"
OUTPUT_PATH = "data/trec2007_prepared.csv"


print("Loading TREC-2007 dataset...")

df = pd.read_csv(INPUT_PATH)

print("Original rows:", len(df))


# --------------------------------------------------
# REMOVE EMAILS WITH NO MESSAGE
# --------------------------------------------------

df["message"] = df["message"].fillna("").astype(str)
df["subject"] = df["subject"].fillna("").astype(str)

df = df[df["message"].str.strip() != ""].copy()

print("After removing empty messages:", len(df))


# --------------------------------------------------
# CREATE SAME TEXT FORMAT AS OUR MAIN DATASET
# --------------------------------------------------

df["combined_text"] = (
    "SUBJECT: "
    + df["subject"]
    + "\nBODY: "
    + df["message"]
)


# --------------------------------------------------
# KEEP ONLY WHAT WE NEED
# --------------------------------------------------

df = df[
    [
        "combined_text",
        "label",
        "email_from",
        "email_to"
    ]
]


# --------------------------------------------------
# REMOVE EXACT DUPLICATES
# --------------------------------------------------

before = len(df)

df = df.drop_duplicates(
    subset=["combined_text", "label"]
).copy()

removed = before - len(df)

print("Duplicate rows removed:", removed)
print("Final rows:", len(df))


# --------------------------------------------------
# LABEL DISTRIBUTION
# --------------------------------------------------

print("\nLabel distribution:")

print(
    df["label"]
    .value_counts()
    .sort_index()
)


# --------------------------------------------------
# SAVE
# --------------------------------------------------

df.to_csv(
    OUTPUT_PATH,
    index=False
)

print("\nSaved:")
print(OUTPUT_PATH)