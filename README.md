ALU Regex Data Extraction & Secure Validation
A Python program that reads raw, messy text and extracts structured data from it using regular expressions. It also detects and blocks hostile input before any extraction runs.

Project Structure
alu-regex-data-extraction/
├── input/
│   └── raw-text.txt          # The raw text the program reads from
├── src/
│   └── main.py               # The main program
├── output/
│   └── sample-output.json    # The extracted results saved as JSON
└── README.md

How to Run
Requirements: Python 3.8 or higher — no external libraries needed.
Step 1 — Open your terminal and navigate to the project folder:
bashcd path/to/alu-regex-data-extraction
Step 2 — Run the program:
bashpython3 src/main.py
Step 3 — Check the results:
The summary will print in your terminal. The full results will be saved to:
output/sample-output.json
You can view it with:
bashcat output/sample-output.json

What It Extracts
1. Email Addresses
Emails are extracted and sorted into four categories:
CategoryDomainalu_official@alueducation.comalu_alumni@alumni.alueducation.comalu_si@si.alueducation.comexternalanything else
Emails with double dots, or dots at the start or end of the local part, are rejected.
2. URLs
Only http:// and https:// URLs are accepted. This means the following are automatically rejected:

javascript:alert(1) — XSS vector
ftp://old-server.com — wrong protocol
//no-scheme.com — missing scheme

3. Phone Numbers (Rwanda only)
Only Rwandan phone numbers are accepted. They must start with +250 or 0, followed by 7 and a valid network digit:
DigitNetwork8, 9MTN2, 3Airtel
Examples accepted:
+250 788 123 456
0789000111
078-812-3456
4. Credit Card Numbers
Visa and Mastercard numbers are extracted in multiple formats:
4111 1111 1111 1111     # spaces
4111-1111-1111-1111     # dashes
4111111111111111        # no separator
Every card number passes a Luhn algorithm checksum before being saved. This rejects random digit strings that just happen to be 16 digits long.
Card numbers are never stored in full — only the last 4 digits are kept:
Input:   4916338506082832
Saved:   ****-****-****-2832

Security
Hostile Input Detection
Every line is checked for dangerous content before any extraction runs. Lines matching any of the following are blocked entirely:
ThreatExampleSQL Injection'; DROP TABLE students; --XSS<script>alert(1)</script>Path Traversal../../../etc/passwdTemplate Injection${7*7} or {{config}}Null byteshidden \x00 characters
If a line is hostile, the program skips it and records how many lines were blocked. The full hostile content is never stored — only the first 80 characters are logged.
Sensitive Data Masking

Credit cards — only last 4 digits stored: ****-****-****-2832
Emails — first 2 characters shown, rest hidden: gr***@alueducation.com


Sample Output
When you run the program, your terminal will show:
json{
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

How the Code is Organized
SectionWhat it doesHOSTILE_PATTERNS + is_hostile()Detects and blocks dangerous inputmask_card() + mask_email()Hides sensitive data before savingEMAIL_PATTERN + classify_email()Finds and sorts emails by ALU categoryURL_PATTERN + validate_url()Finds valid http/https URLsPHONE_PATTERN + validate_phone()Finds Rwandan phone numbersCARD_PATTERN + luhn_check()Finds and validates credit card numbersextract_all()Runs all patterns line by line on the input textbuild_summary()Counts all the results for the console outputmain()Reads the file, runs extraction, saves the JSON

Author
Joel Mucyo