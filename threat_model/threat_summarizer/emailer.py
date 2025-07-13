import os
import smtplib
import time
from datetime import datetime
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.application import MIMEApplication
from dotenv import load_dotenv
from threat_summarizer.pdf_generator import generate_pdf

# Load credentials and config from .env
load_dotenv()

EMAIL_HOST = os.getenv("EMAIL_HOST")
EMAIL_PORT = int(os.getenv("EMAIL_PORT", 587))
EMAIL_USER = os.getenv("EMAIL_USER")
EMAIL_PASS = os.getenv("EMAIL_PASS")
EMAIL_TO = os.getenv("EMAIL_TO")

# Log file paths (adjusted to be absolute, safe for attachments)
BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
CSV_PATH = os.path.join(BASE_DIR, "logs", "summaries.csv")
JSON_PATH = os.path.join(BASE_DIR, "logs", "summaries.json")

# Format threat summaries as HTML
def format_summary_html(summaries):
    html = f"""
    <html>
    <body>
    <h2>🚨 High Severity Threat Summary Report</h2>
    <p>Generated at: {datetime.utcnow().isoformat()}</p>
    <hr>
    """
    for s in summaries:
        html += f"""
        <div style="margin-bottom:20px;">
            <h3 style="margin-bottom:0;">🆔 {s['input']}</h3>
            <p><strong>Time:</strong> {s['timestamp']}<br>
            <strong>Severity:</strong> <span style="color:red;">{s['severity']}</span>{' (Corrected)' if s.get('corrected') else ''}</p>
            <pre style="background:#f4f4f4;padding:10px;border-left:4px solid #999;">{s['summary']}</pre>
        </div>
        <hr>
        """
    html += "</body></html>"
    return html

# Attach CSV or JSON files to email
def attach_file(msg, path, name):
    if os.path.exists(path):
        with open(path, "rb") as f:
            part = MIMEApplication(f.read(), Name=name)
            part['Content-Disposition'] = f'attachment; filename="{name}"'
            msg.attach(part)

# Send batched email with summaries and attachments
def send_batch_email(summaries):
    if not summaries:
        return

    msg = MIMEMultipart("mixed")
    msg["Subject"] = f"[ALERT] {len(summaries)} High Severity Threats Detected"
    msg["From"] = EMAIL_USER
    msg["To"] = EMAIL_TO

    # HTML body
    html = format_summary_html(summaries)
    msg.attach(MIMEText(html, "html"))

    # Attach logs
    attach_file(msg, CSV_PATH, "threat_summaries.csv")
    attach_file(msg, JSON_PATH, "threat_summaries.json")

    # ✅ Generate and attach PDF
    pdf_path = generate_pdf(summaries)
    attach_file(msg, pdf_path, "threat_summary_report.pdf")

    try:
        with smtplib.SMTP(EMAIL_HOST, EMAIL_PORT) as server:
            server.starttls()
            server.login(EMAIL_USER, EMAIL_PASS)
            server.send_message(msg)
            print(f"[📧 Email sent with {len(summaries)} high severity threats]")
    except Exception as e:
        print(f"[⚠️ Email failed: {type(e).__name__}] {e}")

# Time-based trigger (used in watch_and_run)
last_email_time = time.time()

def should_send_by_timer(interval_minutes=10):
    global last_email_time
    now = time.time()
    if now - last_email_time >= interval_minutes * 60:
        last_email_time = now
        return True
    return False
