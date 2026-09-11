import os
import sys

sys.path.append(
    os.path.dirname(os.path.abspath(__file__))
)

from ..core.email_content_extractor import extract_email_content
from ..core.email_features import extract_email_features

TEST_DIR = "data/test_emails"

def main():

    print("=" * 70)
    print("CONTENT FEATURE TEST")
    print("=" * 70)

    eml_files = sorted(
        file_name
        for file_name in os.listdir(TEST_DIR)
        if file_name.lower().endswith(".eml")
    )

    for file_name in eml_files:

        path = os.path.join(
            TEST_DIR,
            file_name
        )

        content = extract_email_content(path)

        combined_text = (
            content["subject"]
            + "\n"
            + content["combined_text"]
        )

        features = extract_email_features(
            combined_text,
            urls=content["urls"],
            attachments=content["attachments"],
            html_source=content["html_source"],
            mailto_links=content["mailto_links"],
            html_links=content["html_links"]
        )

        sender_features = content["sender_features"]

        print("\n" + "=" * 70)
        print(file_name)
        print("=" * 70)

        print("\nSubject:")
        print(content["subject"])

        print("\nURLs:", len(content["urls"]))

        print("Mailto links:", len(content["mailto_links"]))

        print("Attachments:", len(content["attachments"]))

        print("\nSender information:")

        print(
            "- From:",
            sender_features["from_address"]
        )

        print(
            "- From domain:",
            sender_features["from_domain"]
        )

        print(
            "- Reply-To:",
            sender_features["reply_to_address"]
        )

        print(
            "- Reply-To domain:",
            sender_features["reply_to_domain"]
        )

        print(
            "- Return-Path:",
            sender_features["return_path_address"]
        )

        print(
            "- Return-Path domain:",
            sender_features["return_path_domain"]
        )

        print(
            "- Reply-To mismatch:",
            sender_features["reply_to_mismatch"]
        )

        print(
            "- Return-Path mismatch:",
            sender_features["return_path_mismatch"]
        )

        print("\nFeatures:")

        for name, value in features.items():
            print(f"- {name}: {value}")


if __name__ == "__main__":
    main()