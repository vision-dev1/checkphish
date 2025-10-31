# Phishing Awareness Tool (Python)

A simple, modular tool to analyze URLs and email text for phishing indicators.

## Features
- URL Analysis
  - HTTPS check
  - Suspicious domain heuristics (typosquatting patterns, long/random-looking labels, uncommon TLDs)
  - Check against a small known phishing domain list
- Email Analysis
  - Extract suspicious links (from HTML or plain text)
  - Flag mismatched sender vs link domains
  - Detect common phishing keywords (optional)
- Reporting
  - Console report with Safe / Suspicious / Dangerous verdict and reasons
- Optional GUI
  - Streamlit app for easy use

## Install from GitHub

```bash
git clone https://github.com/vision-dev1/checkphish.git
cd checkphish
```

## Quickstart

1) Create and activate a virtual environment (recommended)

```bash
python3 -m venv .venv
source .venv/bin/activate
```

2) Install dependencies

```bash
pip install -r requirements.txt
```

3) Run the CLI

```bash
# Analyze a URL
python3 main.py --mode url --input "https://example.com/login"

# Analyze an email from a file
# Create a file first (example):
echo "From: Support <support@example.com>\nSubject: Verify your account\nClick here: https://example-login-secure.com" > email.txt
python3 main.py --mode email --input-file ./email.txt

# Or interactively (no args) — you can paste the email text when prompted
python3 main.py
```

4) Optional: Run the GUI

```bash
streamlit run streamlit_app.py
```

## Project Structure

```
.
├── phishing_tool/
│   ├── __init__.py
│   └── analyzer.py
├── main.py              # CLI entrypoint
├── streamlit_app.py     # Optional GUI
├── requirements.txt
└── README.md
```

## Notes
- Network access is not required. If available, the tool may attempt a lightweight HEAD request for URL reachability, but it will never fail the analysis if the request errors.
- Heuristics are intentionally conservative and rule-based. They are not foolproof. Always use multiple signals and common sense.
- This is a starter project meant to be extended.

## License
This project uses the Apache 2.0 license. You are not required to release your modified or derivative works under the Apache 2.0 license. Please comply with Apache 2.0 terms (e.g., include required notices).

## Author
Vision KC
