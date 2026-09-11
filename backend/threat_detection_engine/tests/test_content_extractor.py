import os
import sys

sys.path.append(
    os.path.dirname(os.path.abspath(__file__))
)

from ..core.email_content_extractor import extract_email_content


TEST_DIR = "data/test_emails"


def main():

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

        result = extract_email_content(path)

        print("\n" + "=" * 70)
        print(file_name)
        print("=" * 70)

        print("\nSubject:")
        print(result["subject"])

        print("\nPlain text length:")
        print(len(result["plain_text"]))

        print("\nHTML text length:")
        print(len(result["html_text"]))

        print("\nCombined text length:")
        print(len(result["combined_text"]))

        print("\nURLs:")
        for url in result["urls"]:
            print("-", url)

        print("\nAttachments:")
        for attachment in result["attachments"]:
            print(
                "-",
                attachment["filename"],
                "(",
                attachment["content_type"],
                ")"
            )


if __name__ == "__main__":
    main()