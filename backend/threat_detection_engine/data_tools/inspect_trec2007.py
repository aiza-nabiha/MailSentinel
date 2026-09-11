import pandas as pd

DATA_PATH = "data/trec2007.csv"

print("Loading TREC-2007 dataset...")

df = pd.read_csv(DATA_PATH)

print("\n" + "=" * 60)
print("DATASET OVERVIEW")
print("=" * 60)

print("Rows:", len(df))
print("Columns:", list(df.columns))

print("\nColumn data types:")
print(df.dtypes)

print("\nMissing values:")
print(df.isnull().sum())

print("\nDuplicate rows:", df.duplicated().sum())

print("\n" + "=" * 60)
print("SAMPLE DATA")
print("=" * 60)

print(df.head(3).to_string())

print("\n" + "=" * 60)
print("POSSIBLE LABEL DISTRIBUTION")
print("=" * 60)

for column in df.columns:
    if df[column].nunique() <= 10:
        print(f"\nColumn: {column}")
        print(df[column].value_counts(dropna=False))

print("\n" + "=" * 60)
print("TEXT COLUMN INFORMATION")
print("=" * 60)

for column in df.columns:
    if df[column].dtype == "object":
        print(
            f"{column}: "
            f"average length = "
            f"{df[column].fillna('').astype(str).str.len().mean():.1f}"
        )