import re
import json
from pathlib import Path

# These lines of code are meant to detect unsafe patterns in user input.

HOSTILE_PATTERNS: list[re.Pattern] = [
    # SQL Injection attempts — require SQL context to avoid false positives on -- dividers
    re.compile(r"(DROP\s+TABLE|SELECT\s+\*\s+FROM|INSERT\s+INTO|DELETE\s+FROM|;\s*DROP|UNION\s+SELECT)", re.IGNORECASE),
    # XSS / Script injection
    re.compile(r"(<script[\s>]|onerror\s*=|javascript\s*:|on\w+\s*=\s*[\"'])", re.IGNORECASE),
    # Path traversal
    re.compile(r"\.\./|\.\.\\"),
    # Template injection
    re.compile(r"\$\{.*\}|\{\{.*\}\}"),
    # Null bytes
    re.compile(r"\x00"),
]

FLAGGED_LINES: list[dict] = []
def is_hostile(text: str) -> bool:
    """Check if the input string contains any hostile patterns."""
    for pattern in HOSTILE_PATTERNS:
        if pattern.search(text):
            FLAGGED_LINES.append({"input": text[:80], "pattern": pattern.pattern})
            return True
    return False

# Masking functions for emails and credit cards

def mask_card(number: str) -> str:
    digits = re.sub(r"\D", "", number)   
    
    # Mask all but last 4 digits, or entire number if less than 4 digits
    return f"****-****-****-{digits[-4:]}" if len(digits) >= 4 else "****" 


def mask_email(email: str) -> str:
    local, domain = email.split("@")
    # Show first 2 characters of local part, mask the rest, and keep domain intact
    return f"{local[:2]}***@{domain}" 

# Finding email addresses in the input text
# This regex makes sure the email starts and ends with an letter or number before the @ and the domain should also only start with a letter or nmber, and a

EMAIL_PATTERN = re.compile(r"\b[a-zA-Z0-9][a-zA-Z0-9._%+\-]*[a-zA-Z0-9]@[a-zA-Z0-9][a-zA-Z0-9.\-]*\.[a-zA-Z]{2,}\b")

# Finding ALU-specific emails in the input text

ALU_OFFICIAL_PATTERN = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9._%+\-]*@alueducation\.com$")
ALU_ALUMNI_PATTERN = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9._%+\-]*@alumni\.alueducation\.com$")
ALU_SI_PATTERN = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9._%+\-]*@si\.alueducation\.com$")

def classify_email(email: str) -> str:
    if ALU_OFFICIAL_PATTERN.match(email):
        return "alu_official"
    if ALU_ALUMNI_PATTERN.match(email):
        return "alu_alumni"
    if ALU_SI_PATTERN.match(email):
        return "alu_si"
    return "external"

# Finding URLs in the input text
# Accepts http or https, followed by ://, then a valid domain name (with letters, numbers, hyphens, dots), and optional path/query parameters. 

URL_PATTERN = re.compile(r"https?://[a-zA-Z0-9\-._~:/?#\[\]@!$&'()*+,;=%]+")

def validate_url(url: str) -> bool:
   
    # Strip trailing punctuation that may have been captured
    url = url.rstrip(".,;)")
    try:
        # Must contain at least one dot after scheme
        without_scheme = re.sub(r"^https?://", "", url)
        return "." in without_scheme.split("/")[0]
    except Exception:
        return False
    
# Finding Phone numbers in the input text
# Covers: +250 784 083 162, 0784-083-162, 0784083162, +250784083162, etc.
PHONE_PATTERN = re.compile(r'(\+250|0)[\s\-]?7[2389]\d[\s\-]?\d{3}[\s\-]?\d{3}')

def validate_phone(raw: str) -> bool:
    digits = re.sub(r"\D", "", raw)
    return len(digits) in (10, 12)   

# Finding Credit Card numbers in the input text
CARD_PATTERN = re.compile(
    r"\b(?:\d{4}[\s\-]){3}\d{3,4}\b"   # For Visa or Mastercard with spaces or dashes
    r"|\b\d{13,16}\b")                    # For Visa or Mastercard without spaces

# Luhn algorithm for validating credit card numbers
def luhn_check(number: str) -> bool:
    digits = [int(d) for d in re.sub(r"\D", "", number)]
    if len(digits) < 13:
        return False
    for i in range(len(digits) - 2, -1, -2):
        digits[i] *= 2
        if digits[i] > 9:
            digits[i] -= 9
    return sum(digits) % 10 == 0

#Identify credit card type used 
def identify_card_type(number: str) -> str:
    digits = re.sub(r"\D", "", number)
    if re.match(r"^4", digits):
        return "Visa"
    elif re.match(r"^5[1-5]|^2[2-7]", digits):
        return "Mastercard"
    else:
        return "Unknown"
    
# Extraction function that gets stuff from the input text

def extract_all(text: str) -> dict:
    
    results = {
        "emails": {
            "alu_official": [],
            "alu_alumni":   [],
            "alu_si":       [],
            "external":     [],
            "rejected":     []
        },
        "urls":          [],
        "phone_numbers": [],
        "credit_cards":  [],
        "security": {
            "hostile_lines_flagged": 0,
            "hostile_snippets":      []
        }
    }

    # This is so nothing appears twice
    
    seen_emails = set()
    seen_urls   = set()
    seen_cards  = set()

    lines = text.splitlines()

    for line in lines:

        # Final Hostile check
        if is_hostile(line):
            results["security"]["hostile_lines_flagged"] += 1
            results["security"]["hostile_snippets"].append(
                line.strip()[:80] + ("..." if len(line.strip()) > 80 else "")
            )
            continue  

        # Finding emails in the line
        for match in EMAIL_PATTERN.finditer(line):
            email = match.group(0).lower().strip(".,;")

            if email in seen_emails:
                continue

            # Reject emails that start or end with a dot
            local = email.split("@")[0]
            if ".." in local or local.startswith(".") or local.endswith("."):
                results["emails"]["rejected"].append(email)
                continue

            seen_emails.add(email)
            category = classify_email(email)
            results["emails"][category].append(email)

        # Finding URLs in the line
        for match in URL_PATTERN.finditer(line):
            url = match.group(0).rstrip(".,;)")  
            if url in seen_urls:
                continue
            if validate_url(url):
                seen_urls.add(url)
                results["urls"].append(url)

        # Finding phone numbers in the line
        for match in PHONE_PATTERN.finditer(line):
            phone = match.group(0).strip()
            if validate_phone(phone):
                results["phone_numbers"].append(phone)

        # Finding credit card numbers in the line
        for match in CARD_PATTERN.finditer(line):
            raw     = match.group(0)
            digits  = re.sub(r"\D", "", raw) 
            if digits in seen_cards:
                continue

            # Luhn check before storing the credit card number 
            if luhn_check(digits):
                seen_cards.add(digits)
                results["credit_cards"].append({
                    "masked": mask_card(digits),
                    "type":   identify_card_type(digits),
                })

    # Make sure phone numbers dont repeat themselves.
    results["phone_numbers"] = list(dict.fromkeys(results["phone_numbers"]))

    return results

# Summary for console output

def build_summary(results: dict) -> dict:
    emails = results["emails"]
    total_emails = (
        len(emails["alu_official"]) +
        len(emails["alu_alumni"])   +
        len(emails["alu_si"])       +
        len(emails["external"])
    )
    return {
        "total_emails_found":    total_emails,
        "alu_official_emails":   len(emails["alu_official"]),
        "alu_alumni_emails":     len(emails["alu_alumni"]),
        "alu_si_emails":         len(emails["alu_si"]),
        "external_emails":       len(emails["external"]),
        "rejected_emails":       len(emails["rejected"]),
        "urls_found":            len(results["urls"]),
        "phone_numbers_found":   len(results["phone_numbers"]),
        "valid_credit_cards":    len(results["credit_cards"]),
        "hostile_lines_blocked": results["security"]["hostile_lines_flagged"]
    }

# Main function to run the program
def main():
    input_path = Path(__file__).parent.parent / "input" / "raw-text.txt"
    output_path = Path(__file__).parent.parent / "output" / "sample-output.json"
    if not input_path.exists():
        print("Input file not found. Please make sure 'input/raw-text.txt' exists.")
        return

    with input_path.open("r", encoding="utf-8") as f:
        text = f.read()

    results = extract_all(text)
    summary = build_summary(results)

    print(json.dumps(summary, indent=4))

    with output_path.open("w", encoding="utf-8") as f:
        json.dump({"summary": summary, "extracted": results}, f, indent=4)

if __name__ == "__main__":    
    main()