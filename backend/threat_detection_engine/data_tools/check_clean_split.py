import pandas as pd


TRAIN_PATH = "data/train_clean.csv"
TEST_PATH = "data/test_clean.csv"


train_df = pd.read_csv(TRAIN_PATH)
test_df = pd.read_csv(TEST_PATH)


print("=" * 55)
print("TRAIN DATASET")
print("=" * 55)

print("Rows:", len(train_df))

print("\nSource distribution:")
print(train_df["dataset_name"].value_counts())


print("\nSource-wise label distribution:")
print(
    pd.crosstab(
        train_df["dataset_name"],
        train_df["label"]
    )
)


print("\n" + "=" * 55)
print("TEST DATASET")
print("=" * 55)

print("Rows:", len(test_df))

print("\nSource distribution:")
print(test_df["dataset_name"].value_counts())


print("\nSource-wise label distribution:")
print(
    pd.crosstab(
        test_df["dataset_name"],
        test_df["label"]
    )
)