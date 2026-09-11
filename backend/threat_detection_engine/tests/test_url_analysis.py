from ..core.email_features import analyze_urls


test_cases = [
    {
        "name": "Normal URL",
        "urls": [
            "https://example.com/login"
        ]
    },
    {
        "name": "Tracking URL",
        "urls": [
            "https://example.com/page?utm_source=email&utm_campaign=test"
        ]
    },
    {
        "name": "Redirect URL",
        "urls": [
            "https://example.com/redirect?url=https%3A%2F%2Fgoogle.com"
        ]
    },
    {
        "name": "Encoded redirect URL",
        "urls": [
            "https://example.com/login?next=https%3A%2F%2Fevil.com"
        ]
    },
    {
        "name": "Tracking and redirect URL",
        "urls": [
            "https://example.com/click?utm_source=email&url=https%3A%2F%2Fgoogle.com"
        ]
    },
    {
        "name": "Fake redirect parameter - numeric value",
        "urls": [
            "https://example.com/page?url=12345"
        ]
    },
    {
        "name": "Fake redirect parameter - internal path",
        "urls": [
            "https://example.com/page?next=dashboard"
        ]
    },
    {
        "name": "Fake redirect parameter - home",
        "urls": [
            "https://example.com/page?return=home"
        ]
    },
    {
        "name": "IP-based URL",
        "urls": [
            "http://192.168.1.10/login"
        ]
    },
    {
        "name": "URL shortener",
        "urls": [
            "https://bit.ly/example"
        ]
    },
    {
        "name": "Long URL",
        "urls": [
            "https://example.com/" + "a" * 160
        ]
    }
]


for test in test_cases:

    result = analyze_urls(
        test["urls"]
    )

    print("=" * 70)
    print(test["name"])
    print("URLs:", test["urls"])
    print("Result:", result)