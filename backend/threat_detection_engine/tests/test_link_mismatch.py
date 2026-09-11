from ..core.email_content_extractor import extract_html_links
from ..core.email_features import count_link_mismatches

html = """
<html>
<body>

<a href="https://evil-example.com/login">
    https://www.microsoft.com/account
</a>

<a href="https://www.google.com">
    https://www.google.com
</a>

</body>
</html>
"""

links = extract_html_links(html)

print("=" * 60)
print("LINK MISMATCH TEST")
print("=" * 60)

for link in links:
    print("\nDisplay text:")
    print(link["display_text"])

    print("Actual href:")
    print(link["href"])

print("\nMismatch count:")
print(count_link_mismatches(links))