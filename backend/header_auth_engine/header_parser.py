from email import policy
from email.parser import BytesParser
import re
import json
from .received_parser import parse_received_chain

def parse_email(eml_path):
    with open(eml_path, "rb") as file:
        message = BytesParser(policy=policy.default).parse(file)
    return message

def extract_basic_headers(message):
    return {
        "from": message.get("From"),
        "to": message.get("To"),
        "reply_to": message.get("Reply-To"),
        "return_path": message.get("Return-Path"),
        "subject": message.get("Subject"),
        "date": message.get("Date"),
        "message_id": message.get("Message-ID")
    }

def extract_received_headers(message):
    return message.get_all("Received", [])

def extract_authentication_results(message):
    return message.get_all("Authentication-Results", [])

def parse_authentication_results(auth_results):
    authentication = {
        "spf": {
            "result": None,
            "domain": None
        },
        "dkim": [],
        "dmarc": {
            "result": None,
            "domain": None,
            "policy": None,
            "subdomain_policy": None,
            "disposition": None
        }
    }
    combined_results = " ".join(auth_results).lower()

    spf_match = re.search(
        r"\bspf=(pass|fail|softfail|neutral|none|temperror|permerror)\b"
        r".*?smtp\.mailfrom=\"?([^\";\s]+)",
        combined_results
    )

    if spf_match:
        authentication["spf"]["result"] = spf_match.group(1)
        mail_from = spf_match.group(2)
        if "@" in mail_from:
            authentication["spf"]["domain"] = mail_from.split("@")[-1]

    dkim_matches = re.finditer(
        r"\bdkim=(pass|fail|neutral|none|temperror|permerror)\b"
        r"(?:\s+header\.i=@([^\s;]+))?",
        combined_results
    )
    for match in dkim_matches:
        authentication["dkim"].append({
            "result": match.group(1),
            "domain": match.group(2)
        })

    dmarc_match = re.search(
        r"\bdmarc=(pass|fail|bestguesspass|none|temperror|permerror)\b",
        combined_results
    )

    if dmarc_match:
        authentication["dmarc"]["result"] = dmarc_match.group(1)

    dmarc_domain_match = re.search(
        r"\bheader\.from=([^\s;]+)",
        combined_results
    )

    if dmarc_domain_match:
        authentication["dmarc"]["domain"] = dmarc_domain_match.group(1)

    policy_match = re.search(
        r"\bp=(none|quarantine|reject)\b",
        combined_results
    )

    if policy_match:
        authentication["dmarc"]["policy"] = policy_match.group(1)

    subdomain_policy_match = re.search(
        r"\bsp=(none|quarantine|reject)\b",
        combined_results
    )

    if subdomain_policy_match:
        authentication["dmarc"]["subdomain_policy"] = subdomain_policy_match.group(1)

    disposition_match = re.search(
        r"\bdis=([a-z]+)\b",
        combined_results
    )

    if disposition_match:
        authentication["dmarc"]["disposition"] = disposition_match.group(1)

    return authentication

def build_email_data(eml_path):
    message = parse_email(eml_path)

    received_headers = extract_received_headers(message)
    authentication_results = extract_authentication_results(message)

    return {
        "email_metadata": extract_basic_headers(message),
        "received_chain": parse_received_chain(received_headers),
        "authentication_results": authentication_results,
        "authentication": parse_authentication_results(authentication_results)
    }

if __name__ == "__main__":
    email_data = build_email_data("data/test_emails/example.eml")

    print(json.dumps(email_data, indent=4))