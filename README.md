# ALU Regex Data Extraction & Secure Validation

A Python program that reads raw, messy text and extracts structured data from it using regular expressions. It also detects and blocks hostile input before any extraction runs.

---

## Project Structure

```
alu-regex-data-extraction/
├── input/
│   └── raw-text.txt          # The raw text the program reads from
├── src/
│   └── main.py               # The main program
├── output/
│   └── sample-output.json    # The extracted results saved as JSON
└── README.md
```

---

## How to Run

**Requirements:** Python 3.8 or higher — no external libraries needed.

**Step 1 — Open your terminal and navigate to the project folder:**
```bash
cd path/to/alu-regex-data-extraction
```

**Step 2 — Run the program:**
```bash
python3 src/main.py
```

**Step 3 — Check the results:**

The summary will print in your terminal. The full results will be saved to:
```
output/sample-output.json
```

You can view it with:
```bash
cat output/sample-output.json
```

---

## What It Extracts

### 1. Email Addresses
Emails are extracted and sorted into four categories:
| Category | Domain |
|----------|--------|
| `alu_official` | `@alueducation.com` |
| `alu_alumni` | `@alumni.alueducation.com` |
| `alu_si` | `@si.alueducation.com` |
| `external` | anything else |

Emails with double dots, or dots at the start or end of the local part, are rejected.

### 2. URLs
Only `http://` and `https://` URLs are accepted. This means the following are automatically rejected:
- `javascript:alert(1)` — XSS vector
- `ftp://old-server.com` — wrong protocol
- `//no-scheme.com` — missing scheme

### 3. Phone Numbers (Rwanda only)
Only Rwandan phone numbers are accepted. They must start with `+250` or `0`, followed by `7` and a valid network digit:


| Digit | Network |
|-------|---------|
| `8`, `9` | MTN |
| `2`, `3` | Airtel |

Examples accepted:
```
+250 788 123 456
0789000111
078-812-3456
```

### 4. Credit Card Numbers
Visa and Mastercard numbers are extracted in multiple formats:
```
4111 1111 1111 1111     # spaces
4111-1111-1111-1111     # dashes
4111111111111111        # no separator
```

Every card number passes a **Luhn algorithm** checksum before being saved. This rejects random digit strings that just happen to be 16 digits long.

Card numbers are **never stored in full** — only the last 4 digits are kept:
```
Input:   4916338506082832
Saved:   ****-****-****-2832
```

---

## Security

### Hostile Input Detection
Every line is checked for dangerous content before any extraction runs. Lines matching any of the following are blocked entirely:

| Threat | Example |
|--------|---------|
| SQL Injection | `'; DROP TABLE students; --` |
| XSS | `<script>alert(1)</script>` |
| Path Traversal | `../../../etc/passwd` |
| Template Injection | `${7*7}` or `{{config}}` |
| Null bytes | hidden `\x00` characters |

If a line is hostile, the program skips it and records how many lines were blocked. The full hostile content is never stored — only the first 80 characters are logged.

### Sensitive Data Masking
- **Credit cards** — only last 4 digits stored: `****-****-****-2832`
- **Emails** — first 2 characters shown, rest hidden: `gr***@alueducation.com`

---

## Sample Output

When you run the program, your terminal will show:
```json
{
    "total_emails_found": 18,
    "alu_official_emails": 10,
    "alu_alumni_emails": 3,
    "alu_si_emails": 3,
    "external_emails": 2,
    "rejected_emails": 1,
    "urls_found": 8,
    "phone_numbers_found": 4,
    "valid_credit_cards": 3,
    "hostile_lines_blocked": 7
}
```
---

## How the Code is Organized

| Section | What it does |
|---------|-------------|
| `HOSTILE_PATTERNS` + `is_hostile()` | Detects and blocks dangerous input |
| `mask_card()` + `mask_email()` | Hides sensitive data before saving |
| `EMAIL_PATTERN` + `classify_email()` | Finds and sorts emails by ALU category |
| `URL_PATTERN` + `validate_url()` | Finds valid http/https URLs |
| `PHONE_PATTERN` + `validate_phone()` | Finds Rwandan phone numbers |
| `CARD_PATTERN` + `luhn_check()` | Finds and validates credit card numbers |
| `extract_all()` | Runs all patterns line by line on the input text |
| `build_summary()` | Counts all the results for the console output |
| `main()` | Reads the file, runs extraction, saves the JSON |

## Author : Joel Mucyo
