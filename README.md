# CyberGuard — Personal Cyber Defence

CyberGuard is a Flask-based cybersecurity awareness and checking website. It helps users review suspicious email content, inspect URLs for common warning signs, look up existing VirusTotal reports for URLs and file hashes, and learn safer online habits through interactive quizzes.

> **Important:** CyberGuard is an educational aid, not a guarantee that a message, website, or file is safe. A clean result does not prove safety. Do not upload confidential files or paste passwords, one-time codes, or private information.

## Main features

- **Home dashboard:** navigation to the security tools and learning area.
- **Email scanner:** rule-based checks for urgency, sensitive-information requests, reward lures, and suspicious links in pasted email text.
- **URL scanner:** validates and inspects URL structure without opening the destination, then checks an existing VirusTotal URL report when an API key is configured.
- **File checker:** calculates a SHA-256 fingerprint locally and looks up an existing VirusTotal report by hash. The application does not upload the file to VirusTotal.
- **AI explanations:** optionally uses Google Gemini to explain the evidence and practical next steps. The application sends scanner findings to Gemini, not the original uploaded file.
- **Daily Shield learning area:** five quiz modes (email, URL, file, password/account security, and mixed questions), with scoring, explanations, and hints.
- **Input validation and error handling:** validates user input, limits uploads to 10 MB, and provides friendly 404, 413, and 500 pages.
- **Browser security headers:** adds basic security headers to application responses.

## Technologies

- Python 3
- Flask
- HTML5, CSS3, JavaScript, Jinja templates
- Google Gemini API (`google-genai`)
- VirusTotal API v3
- Requests, python-dotenv, Markdown, Bleach
- Pytest for automated tests

## Requirements

- Python 3.10 or newer (Python 3.11+ recommended)
- Internet connection for Gemini and VirusTotal API lookups
- A Google Gemini API key (optional; enables AI explanations)
- A VirusTotal API key (optional; enables reputation lookups)

The website can still run without API keys. AI explanations and VirusTotal lookups will report that the service is unavailable or not configured.

## Installation (Windows PowerShell)

1. Extract the project ZIP.
2. Open PowerShell in the project folder (the folder containing `app.py`).
3. Create and activate a virtual environment:

   ```powershell
   py -m venv .venv
   .\.venv\Scripts\Activate.ps1
   ```

4. Install dependencies:

   ```powershell
   python -m pip install --upgrade pip
   pip install -r requirements.txt
   ```

5. Create your local environment file:

   ```powershell
   Copy-Item .env.example .env
   ```

6. Open `.env` and replace the placeholders with your own keys:

   ```env
   GEMINI_API_KEY=your_real_gemini_key
   VIRUSTOTAL_API_KEY=your_real_virustotal_key
   ```

7. Start the website:

   ```powershell
   python app.py
   ```

8. Open `http://127.0.0.1:5000` in your browser.

### macOS / Linux

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
pip install -r requirements.txt
cp .env.example .env
# Edit .env and add your API keys
python app.py
```

## API setup

### Google Gemini

Create an API key through Google AI Studio and add it as `GEMINI_API_KEY` in `.env`. CyberGuard uses the Google Gen AI Python SDK. If the key is missing, the app shows a fallback explanation rather than stopping the scan.

### VirusTotal

Create an API key in your VirusTotal account and add it as `VIRUSTOTAL_API_KEY` in `.env`. The app uses VirusTotal API v3 to look up existing URL and file-hash reports. A missing report is not proof that a resource is safe. API quotas and account permissions may limit lookups.

## Tests

Install the requirements, then run:

```powershell
python -m pytest -q
```

## Project structure

```text
CyberGuard/
├── app.py
├── requirements.txt
├── .env.example
├── .gitignore
├── README.md
├── scanners/
│   ├── email_scanner.py
│   ├── url_scanner.py
│   ├── file_scanner.py
│   ├── virus_total.py
│   └── gemini_explainer.py
├── static/
│   ├── css/style.css
│   ├── images/
│   └── videos/
├── templates/
│   ├── base.html
│   ├── index.html
│   ├── email_scan.html
│   ├── url_scan.html
│   ├── file_scan.html
│   ├── daily_shield.html
│   └── error.html
└── tests/
    └── test_scanners.py
```

## Limitations and responsible use

- Email analysis is based on explainable text patterns; it does not authenticate the sender or inspect attachments.
- URL checks inspect the address and an existing reputation report; the app does not crawl or execute the destination website.
- File analysis calculates a SHA-256 hash and looks up an existing report; it does not execute, sandbox, or upload the file.
- Gemini explanations are generated from scanner findings and may be unavailable because of network, model, quota, or API-key issues.
- Do not treat a low score or a missing threat report as a clean bill of health.
- For public deployment, use HTTPS, a production WSGI server, a secure secret-management service, rate limiting, and deployment-specific security review. Do not run Flask's development server with debug mode enabled in production.

## Internship challenge alignment

This project provides more than three distinct pages/sections, clear navigation, interactive scanning forms and quizzes, responsive CSS breakpoints, input validation, error handling, and API integrations. GitHub repository creation, collaborator invitations, and a clean-clone installation test must still be completed by the candidate.
