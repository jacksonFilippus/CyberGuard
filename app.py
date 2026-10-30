
from flask import Flask, render_template, request
from dotenv import load_dotenv

import markdown
import bleach

from datetime import date
from scanners.email_scanner import analyse_email
from scanners.url_scanner import analyse_url
from scanners.file_scanner import analyse_file
from scanners.gemini_explainer import explain_security_findings
from scanners.virus_total import (
    lookup_file_hash,
    lookup_url,
)
from scanners.safe_browsing import lookup_safe_browsing

load_dotenv()




def format_ai_explanation(text):
    import re
    import html

    text = html.unescape(text or "")
    text = text.replace("\u00a0", " ").strip()

    # Remove escaped Markdown punctuation.
    text = re.sub(r"\\([.!*#_`])", r"\1", text)

    # Remove the main heading if Gemini includes it.
    text = re.sub(
        r"^\s*#{1,3}\s*AI Security Explanation\s*",
        "",
        text,
        flags=re.IGNORECASE
    )

    # Convert the three numbered section titles into Markdown headings.
    headings = {
        "1": r"What the findings mean",
        "2": r"What could happen if the threat indicators represent a real threat",
        "3": r"What the user should do next"
    }

    for number, heading in headings.items():
        pattern = rf"{number}\s*[.)]\s*{heading}\.?"

        text = re.sub(
            pattern,
            f"\n\n### {number}. {heading}\n\n",
            text,
            flags=re.IGNORECASE
        )

    # Put bullet points on separate lines.
    text = re.sub(r"(?<!\S)-\s+", "\n- ", text)

    # Clean excessive whitespace.
    text = re.sub(r"[ \t]+", " ", text)
    text = re.sub(r"\n{3,}", "\n\n", text)

    return text.strip()

def create_ai_explanation_html(text):
    allowed_tags = [
        "p", "br", "strong", "em",
        "ul", "ol", "li",
        "h1", "h2", "h3", "h4",
        "blockquote", "code", "pre", "hr"
    ]

    formatted_text = format_ai_explanation(text)

    ai_html = markdown.markdown(
        formatted_text,
        extensions=["extra", "sane_lists"]
    )

    return bleach.clean(
        ai_html,
        tags=allowed_tags,
        attributes={},
        strip=True
    )












app = Flask(__name__)
app.config.update(
    MAX_CONTENT_LENGTH=11 * 1024 * 1024,
    MAX_FORM_MEMORY_SIZE=256 * 1024,
    MAX_FORM_PARTS=30,
)

@app.after_request
def add_security_headers(response):
    """Apply sensible browser security headers to every response."""
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
    response.headers.setdefault(
        "Permissions-Policy",
        "camera=(), microphone=(), geolocation=()"
    )
    response.headers.setdefault(
        "Content-Security-Policy",
        "default-src 'self' https: data: blob:; "
        "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
        "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com https://cdn.jsdelivr.net; "
        "font-src 'self' https://fonts.gstatic.com https://cdn.jsdelivr.net data:; "
        "img-src 'self' https: data:; media-src 'self' https:; "
        "connect-src 'self' https:;"
    )
    return response

@app.errorhandler(413)
def request_too_large(_error):
    return render_template(
        "error.html",
        code=413,
        title="Upload too large",
        message="Your request or file is larger than the 10 MB limit."
    ), 413

@app.errorhandler(404)
def page_not_found(_error):
    return render_template(
        "error.html",
        code=404,
        title="Page not found",
        message="The page you requested does not exist."
    ), 404

@app.errorhandler(500)
def internal_error(_error):
    app.logger.exception("Unhandled application error")
    return render_template(
        "error.html",
        code=500,
        title="Something went wrong",
        message="The application could not complete your request. Please try again."
    ), 500



QUIZ_CATEGORIES = {
    "email": {
        "title": "Email Security Quiz",
        "category": "Email Security",
        "questions": [
            {
                "question": "An email urgently asks for your password. What should you do?",
                "options": ["Reply with your password", "Verify the request independently", "Click its link", "Forward it to friends"],
                "answer": "B",
                "explanation": "Verify unexpected requests through a trusted channel. Never send your password by email.",
                "hint": "Think about how you can confirm whether the request is genuine without trusting the email itself."
            },
            {
                "question": "Which can be a sign of a phishing email?",
                "options": ["Unexpected urgency", "A message you were expecting", "A known sender you verified", "A scheduled reminder"],
                "answer": "A",
                "explanation": "Unexpected urgency can pressure people into making unsafe decisions.",
                "hint": "Think about which message characteristic might pressure you into acting before checking the facts."
            },
            {
                "question": "An unknown sender attaches an unexpected executable file. What is safest?",
                "options": ["Open it immediately", "Run it as administrator", "Do not open it; verify the sender", "Forward it to everyone"],
                "answer": "C",
                "explanation": "Unexpected executable attachments may contain malware. Verify them before opening.",
                "hint": "Consider what could happen when you run a program from someone whose identity you haven't verified."
            },
            {
                "question": "How should you check a suspicious email claiming to be from your bank?",
                "options": ["Reply and ask if it is real", "Use the contact details in the email", "Click its login link", "Contact the bank using its official website or number"],
                "answer": "D",
                "explanation": "Use independently verified contact details instead of details supplied in a suspicious message.",
                "hint": "If the email itself might be fraudulent, where else could you find reliable contact information?"
            },
            {
                "question": "What is email spoofing?",
                "options": ["Encrypting an email", "Faking sender information to appear trustworthy", "Deleting old messages", "Blocking spam"],
                "answer": "B",
                "explanation": "Spoofing makes a message appear to come from a different sender.",
                "hint": "Think about how an attacker might make a message appear to come from someone else."
            },
            {
                "question": "An email asks you to pay an invoice, but the bank details have changed. What should you do?",
                "options": ["Pay immediately", "Trust the email logo", "Confirm the change using a known phone number", "Reply with your banking password"],
                "answer": "C",
                "explanation": "Payment-detail changes should be verified through a previously trusted contact method.",
                "hint": "A changed payment destination could be a warning sign. How could you verify the change independently?"
            },
            {
                "question": "Which information should you avoid sending in response to an unexpected email?",
                "options": ["Your password or one-time login code", "A public company address", "A public website link", "A general product question"],
                "answer": "A",
                "explanation": "Passwords and one-time codes can allow someone to access your account.",
                "hint": "Which type of information could let another person enter your account?"
            },
            {
                "question": "What is a safer way to handle a suspicious email?",
                "options": ["Send it to all contacts", "Download every attachment", "Reply with personal details", "Report it using your organisation's approved process"],
                "answer": "D",
                "explanation": "Reporting suspicious messages helps the appropriate team investigate them.",
                "hint": "Think about the responsible way to alert the people who handle security in your organisation."
            },
            {
                "question": "An email uses your name. Does that prove it is genuine?",
                "options": ["Yes, always", "No, attackers can know or obtain your name", "Yes, if it has a logo", "Yes, if it has an attachment"],
                "answer": "B",
                "explanation": "Personalised messages can still be fraudulent; check the sender and request independently.",
                "hint": "Consider whether someone could learn your name without being a trusted person."
            },
            {
                "question": "What should you do if you entered your password on a suspected phishing page?",
                "options": ["Ignore it", "Delete your browser", "Change the password using the official site and report it", "Send the password to the sender"],
                "answer": "C",
                "explanation": "Change the exposed password promptly from the genuine site and notify the relevant support team. Change it anywhere else it was reused.",
                "hint": "Assume someone might have obtained the password. What action would help protect the affected account?"
            }
        ]
    },

    "url": {
        "title": "URL & Link Safety Quiz",
        "category": "URL & Link Safety",
        "questions": [
            {
                "question": "Does HTTPS guarantee that a website is trustworthy?",
                "options": ["Yes, always", "Yes, if it has a logo", "No, HTTPS alone does not prove legitimacy", "No, HTTPS never encrypts data"],
                "answer": "C",
                "explanation": "HTTPS encrypts data in transit, but malicious websites can also use HTTPS.",
                "hint": "Think about what HTTPS protects during a connection and what it cannot tell you about the website owner."
            },
            {
                "question": "A message says your account will close unless you click a link. What is safer?",
                "options": ["Visit the official website directly", "Click the link immediately", "Enter your password to check", "Download its attachment"],
                "answer": "A",
                "explanation": "Visiting the official site directly avoids relying on a potentially deceptive link.",
                "hint": "How could you check your account without depending on a link supplied in a threatening message?"
            },
            {
                "question": "What part of a URL is especially important to inspect?",
                "options": ["The colour of the page", "The number of images", "The length of the page title", "The actual domain name"],
                "answer": "D",
                "explanation": "Inspect the domain carefully because deceptive addresses can resemble legitimate ones.",
                "hint": "Look at the web address itself. Which part tells you which domain you are actually visiting?"
            },
            {
                "question": "What is a risk of a URL shortener?",
                "options": ["It always installs malware", "It can hide the final destination", "It guarantees a safe website", "It disables encryption"],
                "answer": "B",
                "explanation": "Shortened links can conceal their destination, so verify them before opening.",
                "hint": "Before a shortened link redirects you, can you easily tell where it will take you?"
            },
            {
                "question": "Which URL is most suspicious for a bank called Example Bank?",
                "options": ["The bank's verified official domain", "A bookmark you saved from its official site", "example-bank-login.security-check.example", "The official mobile app"],
                "answer": "C",
                "explanation": "The domain shown is under security-check.example, not necessarily the bank's genuine domain. Check the actual registered domain.",
                "hint": "Read the address from right to left. Which domain does it actually belong to?"
            },
            {
                "question": "A website has a padlock icon. What does that primarily indicate?",
                "options": ["The connection is encrypted", "The business is legitimate", "The page contains no scams", "The downloads are all safe"],
                "answer": "A",
                "explanation": "The padlock indicates an encrypted connection, not that the website's owner is trustworthy.",
                "hint": "Think about what the padlock says about the connection, rather than the honesty of the website."
            },
            {
                "question": "What should you do with a suspicious link from an unknown sender?",
                "options": ["Open it in every browser", "Enter fake login details", "Share it with friends", "Avoid opening it and verify the message"],
                "answer": "D",
                "explanation": "Avoid interacting with unexpected links until you can verify their legitimacy.",
                "hint": "What should you establish before interacting with a link sent by someone you don't know?"
            },
            {
                "question": "Why can a misspelled domain be dangerous?",
                "options": ["It always slows your computer", "It may imitate a legitimate website", "It proves the site is encrypted", "It prevents all downloads"],
                "answer": "B",
                "explanation": "Attackers can use lookalike domains to trick visitors into trusting a fake site.",
                "hint": "Imagine an attacker changing just one letter in a familiar website's name. What could that trick you into believing?"
            },
            {
                "question": "What does a URL scanner that checks reputation usually assess?",
                "options": ["Your typing speed", "Your computer's battery", "Available indicators and reputation reports", "The identity of every website owner with certainty"],
                "answer": "C",
                "explanation": "Scanners evaluate available indicators and reports, but cannot guarantee a URL is safe.",
                "hint": "Think about the information a scanner can collect from security services and available threat reports."
            },
            {
                "question": "A URL scanner finds no known threats. What does that mean?",
                "options": ["The URL is guaranteed safe", "The site cannot change", "You should enter your password", "No threats were identified by that check; caution is still needed"],
                "answer": "D",
                "explanation": "A clean result is not proof of safety. New or unreported threats may be missed.",
                "hint": "Could a new or previously unreported threat exist even if a scanner has not detected it?"
            }
        ]
    },

    "file": {
        "title": "File Security Quiz",
        "category": "File Security",
        "questions": [
            {
                "question": "An unexpected email attachment is an executable file. What should you do?",
                "options": ["Run it immediately", "Avoid opening it and verify the sender", "Disable your antivirus", "Share it online"],
                "answer": "B",
                "explanation": "Unexpected executable files may contain malware. Verify the source before opening them.",
                "hint": "Before running a program, consider whether you trust its source and expected to receive it."
            },
            {
                "question": "What is malware?",
                "options": ["Software designed to cause harm or perform unwanted actions", "A type of monitor", "A secure backup", "A normal operating system update"],
                "answer": "A",
                "explanation": "Malware is software designed to harm systems, steal information, or perform unauthorised actions.",
                "hint": "Think about software created to do something harmful rather than to perform a legitimate, intended task."
            },
            {
                "question": "What does a SHA-256 hash provide for a file?",
                "options": ["A guarantee the file is harmless", "The author's identity", "A file fingerprint useful for comparison", "Automatic malware removal"],
                "answer": "C",
                "explanation": "A SHA-256 hash identifies file content for comparison; it does not prove that the file is safe.",
                "hint": "Imagine a digital fingerprint that helps you compare file contents. What could that fingerprint help you identify?"
            },
            {
                "question": "A file scanner finds no known detections. What should you conclude?",
                "options": ["The file is definitely safe", "All future scans will be clean", "The file cannot be malware", "No known detections were reported by that check"],
                "answer": "D",
                "explanation": "Undetected files can still be harmful, especially if the threat is new or not recognised.",
                "hint": "Does a scanner's failure to detect a threat prove that no threat exists?"
            },
            {
                "question": "What is a sensible way to reduce the risk of malicious downloads?",
                "options": ["Download from any pop-up", "Use trusted sources and scan unexpected files", "Disable security updates", "Run every file as administrator"],
                "answer": "B",
                "explanation": "Trusted download sources and security scanning reduce risk, although neither guarantees safety.",
                "hint": "Consider both where a file comes from and what you can do to check it before using it."
            },
            {
                "question": "Why should software updates be installed from trusted sources?",
                "options": ["Updates always remove every threat", "They make passwords unnecessary", "Updates can fix known security vulnerabilities", "They guarantee no future attacks"],
                "answer": "C",
                "explanation": "Security updates often fix vulnerabilities that attackers could otherwise exploit.",
                "hint": "Software can contain weaknesses. Think about what developers release updates to repair."
            },
            {
                "question": "What should you do if your antivirus flags a downloaded file?",
                "options": ["Follow security guidance and avoid running the file", "Disable antivirus to open it", "Rename it to hide the warning", "Email it to everyone"],
                "answer": "A",
                "explanation": "Do not run a flagged file just to bypass the warning. Follow your security tool's recommended response.",
                "hint": "If your security tool warns you about a file, think about whether bypassing the warning makes the risk better or worse."
            },
            {
                "question": "What is a backup useful for after a ransomware incident?",
                "options": ["Identifying every attacker", "Preventing every phishing email", "Replacing multi-factor authentication", "Recovering data if a clean backup is available"],
                "answer": "D",
                "explanation": "A reliable, separate backup can help restore data, but it must be checked to ensure it is clean.",
                "hint": "If your files become encrypted or unavailable, what earlier copy could help you restore them?"
            },
            {
                "question": "What does a file extension such as .pdf or .exe indicate?",
                "options": ["The file is definitely safe", "The apparent file type, which can still be misleading", "The file has been virus-scanned", "The author is verified"],
                "answer": "B",
                "explanation": "Extensions suggest a file type, but can be misleading and do not establish safety.",
                "hint": "Think about what the letters after a filename's final dot suggest—and whether that alone proves the file's contents are safe."
            },
            {
                "question": "Why should you avoid uploading confidential files to an unknown online scanner?",
                "options": ["It always damages the file", "It disables your firewall", "The service may retain or share submitted files", "It changes every password"],
                "answer": "C",
                "explanation": "Review a service's privacy and sharing policies before submitting sensitive files.",
                "hint": "Before sending a confidential document to a third party, consider what might happen to a copy of that document."
            }
        ]
    },

    "password": {
        "title": "Password & Account Security Quiz",
        "category": "Password & Account Security",
        "questions": [
            {
                "question": "What is a good password habit?",
                "options": ["Reuse one password everywhere", "Use unique passwords for each account", "Share passwords with friends", "Use your name for every account"],
                "answer": "B",
                "explanation": "Unique passwords limit the damage if one account is compromised.",
                "hint": "Think about what could happen to your other accounts if one website suffers a data breach."
            },
            {
                "question": "What does multi-factor authentication add?",
                "options": ["Another verification factor", "A guarantee against every attack", "Automatic backups", "A replacement for all updates"],
                "answer": "A",
                "explanation": "MFA adds another verification step, making unauthorised access harder.",
                "hint": "The word 'multi' is a clue. Consider what happens when logging in requires more than one kind of proof."
            },
            {
                "question": "Why use a password manager?",
                "options": ["It guarantees no account can be hacked", "It removes the need to update software", "It lets everyone share your passwords", "It helps generate and store unique passwords"],
                "answer": "D",
                "explanation": "A reputable password manager helps you maintain unique passwords without memorising every one.",
                "hint": "Imagine having many different, strong passwords. What tool could help you keep them organised securely?"
            },
            {
                "question": "Someone calls claiming to be IT support and asks for your one-time login code. What should you do?",
                "options": ["Give it to them immediately", "Post it in a chat", "Do not share it; verify the request through an official channel", "Send it by email"],
                "answer": "C",
                "explanation": "One-time codes can authorise account access. Never disclose them to an unexpected caller.",
                "hint": "Consider what the caller could do if they obtained the temporary code needed to access your account."
            },
            {
                "question": "What should you do after receiving an unexpected login approval prompt?",
                "options": ["Approve it to make it disappear", "Deny it and investigate the unexpected request", "Share your code with the requester", "Ignore repeated prompts forever"],
                "answer": "B",
                "explanation": "Deny unexpected prompts. Repeated prompts can indicate someone is trying to access your account.",
                "hint": "If you did not initiate a login, ask yourself who might have triggered the request."
            },
            {
                "question": "Which is a safer way to recover an account?",
                "options": ["Use the service's official recovery process", "Pay a stranger who promises recovery", "Share your password publicly", "Download a recovery tool from an unknown site"],
                "answer": "A",
                "explanation": "Use official account recovery and avoid giving credentials to unverified people or tools.",
                "hint": "When you need access to an account, consider which source can verify your identity legitimately."
            },
            {
                "question": "Why is reusing a password risky?",
                "options": ["It makes the screen brighter", "It stops software updates", "It guarantees a lockout", "A breach at one service may expose other accounts"],
                "answer": "D",
                "explanation": "Attackers may try leaked credentials on other services.",
                "hint": "If the same key opened several doors and someone copied it, how many places could be at risk?"
            },
            {
                "question": "What should you do if you suspect your account has been compromised?",
                "options": ["Ignore all alerts", "Delete your security software", "Use the official service to secure the account and change the password", "Send your current password to support"],
                "answer": "C",
                "explanation": "Secure the account through the official service, review active sessions, and contact support if needed.",
                "hint": "Think about how to regain control using the genuine service and prevent further unauthorised access."
            },
            {
                "question": "Which is the safest way to share access to a work system?",
                "options": ["Send your personal password to a colleague", "Use approved individual accounts and access permissions", "Create one shared password for everyone", "Write credentials on a public noticeboard"],
                "answer": "B",
                "explanation": "Individual accounts and approved permissions improve accountability and limit access.",
                "hint": "Consider how a workplace can give each person access without making everyone share the same secret."
            },
            {
                "question": "What should you do with a security alert you did not trigger?",
                "options": ["Investigate it through the official service and secure the account if needed", "Assume it is harmless", "Send your password to the alert sender", "Disable MFA permanently"],
                "answer": "A",
                "explanation": "An unexpected alert may indicate an attempted or successful login. Verify it using the official service.",
                "hint": "Think about how you can check whether the alert is genuine without trusting links or contact details in the message."
            }
        ]
    }
}
 
@app.route("/")
def home():
    return render_template("index.html")



@app.route("/email", methods=["GET", "POST"])
def email_scan():
    result = None
    error = None
    sender = ""
    subject = ""
    body = ""

    if request.method == "POST":
        sender = request.form.get("sender", "").strip()
        subject = request.form.get("subject", "").strip()
        body = request.form.get("body", "").strip()

        if not body:
            error = "Please enter the email message."
        elif len(sender) > 254 or len(subject) > 300 or len(body) > 10000:
            error = "Please keep the sender under 255 characters, subject under 301 characters, and message under 10,001 characters."
        else:
            try:
                result = analyse_email(sender, subject, body)

                # Ask Gemini to explain the scanner findings.
                result["ai_explanation"] = explain_security_findings(
                    scan_type="email",
                    findings=[
                        f"{item['type']}: {item['evidence']}"
                        for item in result["findings"]
                    ],
                    verdict=result["verdict"]
                )
                result["ai_explanation_html"] = create_ai_explanation_html(
                    result["ai_explanation"]
                )
            except Exception:
                app.logger.exception("Email analysis failed")
                error = "An unexpected error occurred. Please try again."

    return render_template(
        "email_scan.html",
        result=result,
        error=error,
        sender=sender,
        subject=subject,
        body=body,
    )






@app.route("/url", methods=["GET", "POST"])
def url_scan():
    result = None
    error = None
    submitted_url = ""

    if request.method == "POST":
        submitted_url = request.form.get("url", "").strip()

        if not submitted_url:
            error = "Please enter a URL."

        elif len(submitted_url) > 2048:
            error = "The URL is too long."

        else:
            try:
                # 1. Run local URL checks.
                result = analyse_url(submitted_url)

                if result.get("valid"):
                    # 2. Check VirusTotal.
                    result["threat_report"] = lookup_url(
                        result["url"]
                    )

                    # 3. Check Google Safe Browsing.
                    result["safe_browsing"] = lookup_safe_browsing(
                        result["url"]
                    )

                    vt = result["threat_report"]
                    sb = result["safe_browsing"]

                    vt_status = vt.get("status")
                    sb_status = sb.get("status")
                    vt_severity = vt.get("severity")

                    # 4. Determine an appropriately cautious verdict.
                    if sb_status == "flagged":
                        result["overall_verdict"] = (
                            "Google Safe Browsing threat match"
                        )

                    elif vt_severity == "strong_threat_signal":
                        result["overall_verdict"] = (
                            "Multiple VirusTotal engines report a threat"
                        )

                    elif vt_severity == "multiple_engine_warning":
                        result["overall_verdict"] = (
                            "Multiple VirusTotal engine warnings"
                        )

                    elif vt_severity == "single_engine_warning":
                        result["overall_verdict"] = (
                            "Single VirusTotal engine warning – investigate"
                        )

                    elif vt_status == "flagged":
                        result["overall_verdict"] = (
                            "VirusTotal threat report requires investigation"
                        )

                    elif vt_status == "suspicious":
                        result["overall_verdict"] = (
                            "Suspicious reputation reported"
                        )

                    elif result.get("findings"):
                        result["overall_verdict"] = (
                            "Local warning signs found"
                        )

                    elif (
                        vt_status == "no_known_detection"
                        and sb_status == "no_known_detection"
                    ):
                        result["overall_verdict"] = (
                            "No known threat-list detections"
                        )

                    else:
                        result["overall_verdict"] = (
                            "Incomplete security assessment"
                        )

                    # 5. Prepare evidence for Gemini.
                    security_context = {
                        "local_analysis": {
                            "verdict": result.get("verdict"),
                            "score": result.get("score"),
                            "findings": result.get("findings", []),
                        },
                        "virustotal": vt,
                        "google_safe_browsing": sb,
                    }

                    # 6. Generate AI explanation.
                    result["ai_explanation"] = explain_security_findings(
                        scan_type="URL",
                        findings=result.get("findings", []),
                        verdict=result["overall_verdict"],
                        security_context=security_context,
                    )

                    result["ai_explanation_html"] = (
                        create_ai_explanation_html(
                            result["ai_explanation"]
                        )
                    )

                else:
                    result["threat_report"] = None
                    result["safe_browsing"] = None
                    result["overall_verdict"] = "Invalid URL"

            except Exception:
                app.logger.exception("URL analysis failed")
                error = (
                    "An unexpected error occurred during URL analysis. "
                    "Please try again."
                )

    return render_template(
        "url_scan.html",
        result=result,
        error=error,
        submitted_url=submitted_url,
    )


@app.route("/file", methods=["GET", "POST"])
def file_scan():
    result = None
    error = None

    if request.method == "POST":
        uploaded_file = request.files.get("file")

        try:
            result = analyse_file(uploaded_file)

            # Look up the file's existing VirusTotal report.
            result["threat_report"] = lookup_file_hash(
                result["sha256"]
            )

            # Prepare evidence for Gemini.
            report = result["threat_report"]

            ai_findings = [
                f"VirusTotal status: {report.get('status', 'unknown')}",
                f"VirusTotal report: {report.get('message', 'No report details available.')}",
            ]

            # Include detection counts only when available.
            for field in (
                "malicious",
                "suspicious",
                "harmless",
                "undetected",
                "total",
            ):
                if field in report:
                    ai_findings.append(
                        f"{field.capitalize()} detections: {report[field]}"
                    )

            # Ask Gemini to explain the available evidence.
            result["ai_explanation"] = explain_security_findings(
                scan_type="file",
                findings=ai_findings,
                verdict=report.get("status", "unknown"),
            )

            result["ai_explanation_html"] = create_ai_explanation_html(
                result["ai_explanation"]
            )
        except ValueError as exc:
            error = str(exc)

        except Exception:
            app.logger.exception("File analysis failed")
            error = "An unexpected error occurred. Please try again."

    return render_template(
        "file_scan.html",
        result=result,
        error=error,
    )





@app.route("/learn", methods=["GET", "POST"])
def learn():
    category_key = request.args.get("category", "").strip().lower()

    if not category_key:
        return render_template(
            "daily_shield.html",
            categories=QUIZ_CATEGORIES,
            selected_category=None
        )

    if category_key == "mixed":
        # Ten questions covering all four categories.
        raw_questions = (
            QUIZ_CATEGORIES["email"]["questions"][:3]
            + QUIZ_CATEGORIES["url"]["questions"][:3]
            + QUIZ_CATEGORIES["file"]["questions"][:2]
            + QUIZ_CATEGORIES["password"]["questions"][:2]
        )

        quiz_title = "Mixed Cybersecurity Quiz"
        quiz_category = "All Topics"

    elif category_key in QUIZ_CATEGORIES:
        selected_quiz = QUIZ_CATEGORIES[category_key]
        raw_questions = selected_quiz["questions"]
        quiz_title = selected_quiz["title"]
        quiz_category = selected_quiz["category"]

    else:
        return render_template(
            "daily_shield.html",
            categories=QUIZ_CATEGORIES,
            selected_category=None,
            error="Please choose a valid quiz category."
        )

    # Give each displayed question a unique ID.
    questions = [
        {**question, "id": f"q{index + 1}"}
        for index, question in enumerate(raw_questions)
    ]

    submitted = request.method == "POST"
    score = 0
    feedback = {}
    selected_answers = {}

    quiz_error = None
    if submitted:
        selected_answers = request.form.to_dict()
        missing_answers = [
            question["id"] for question in questions
            if selected_answers.get(question["id"]) not in {"A", "B", "C", "D"}
        ]
        if missing_answers:
            quiz_error = f"Please answer all {len(questions)} questions before submitting. {len(missing_answers)} answer(s) are missing or invalid."
            submitted = False
            selected_answers = {}
        for question in questions if submitted else []:
            question_id = question["id"]
            selected = selected_answers.get(question_id)
            correct = selected == question["answer"]

            if correct:
                score += 1

            feedback[question_id] = {
                "correct": correct,
                "message": question["explanation"],
                "hint": question.get(
                    "hint",
                    "Think carefully about the safest action before choosing."
                )
            }

    return render_template(
        "daily_shield.html",
        categories=QUIZ_CATEGORIES,
        selected_category=category_key,
        quiz_title=quiz_title,
        quiz_category=quiz_category,
        questions=questions,
        submitted=submitted,
        quiz_error=quiz_error,
        score=score,
        feedback=feedback,
        selected_answers=selected_answers
    )






if __name__ == "__main__":
    # Allow other devices on the same network to access CyberGuard.
    import os
    app.run(
        host=os.getenv("FLASK_HOST", "0.0.0.0"),
        port=int(os.getenv("PORT", "5000")),
        debug=os.getenv("FLASK_DEBUG", "false").lower() == "true"
    )