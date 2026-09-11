from datasets import load_dataset
from collections import Counter

DATASET_NAME = "puyang2025/seven-phishing-email-datasets"

print("Loading dataset...")
ds = load_dataset(DATASET_NAME)

for split_name, split in ds.items():

    print(f"\n{'=' * 50}")
    print(f"SPLIT: {split_name}")
    print(f"{'=' * 50}")

    print("Rows:", len(split))
    print("Columns:", split.column_names)

    # Overall label counts
    labels = split["label"]
    label_counts = Counter(labels)

    print("\nLabel counts:")
    for label, count in sorted(label_counts.items()):
        print(f"  {label}: {count}")

    # Source dataset counts
    sources = Counter(split["dataset_name"])

    print("\nSource dataset counts:")
    for source, count in sources.most_common():
        print(f"  {source}: {count}")

    # Source + label counts
    print("\nSource-wise label counts:")

    source_label_counts = {}

    for source, label in zip(split["dataset_name"], split["label"]):
        if source not in source_label_counts:
            source_label_counts[source] = Counter()

        source_label_counts[source][label] += 1

    for source in sorted(source_label_counts):
        counts = source_label_counts[source]

        print(
            f"  {source}: "
            f"label 0 = {counts.get(0, 0)}, "
            f"label 1 = {counts.get(1, 0)}"
        )

    # Missing values
    print("\nMissing values:")

    for column in split.column_names:
        values = split[column]

        missing = sum(
            value is None
            for value in values
        )

        print(f"  {column}: {missing}")

    # Empty text
    empty_text = sum(
        not value or not str(value).strip()
        for value in split["text"]
    )

    print("\nEmpty text rows:", empty_text)