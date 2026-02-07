"""
Email alerting for high-severity threat summaries.
Sends HTML emails with PDF, CSV, and JSON attachments.
"""
import os
import smtplib
import time
import ssl
from datetime import datetime
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.application import MIMEApplication
from pathlib import Path
from typing import List, Dict, Any, Optional

from dotenv import load_dotenv

from .pdf_generator import generate_pdf


# Load credentials from .env
load_dotenv()


# Email configuration
EMAIL_HOST = os.getenv("EMAIL_HOST", "smtp.gmail.com")
EMAIL_PORT = int(os.getenv("EMAIL_PORT", "587"))
EMAIL_USER = os.getenv("EMAIL_USER")
EMAIL_PASS = os.getenv("EMAIL_PASS")
EMAIL_TO = os.getenv("EMAIL_TO")
EMAIL_USE_TLS = os.getenv("EMAIL_USE_TLS", "true").lower() == "true"

# Log file paths
BASE_DIR = Path(__file__).parent.parent
LOG_DIR = BASE_DIR / "logs"
CSV_PATH = LOG_DIR / "summaries.csv"
JSON_PATH = LOG_DIR / "summaries.json"

# Email timing state
_last_email_time: float = time.time()


def is_email_configured() -> bool:
    """Check if email credentials are configured."""
    return all([EMAIL_HOST, EMAIL_USER, EMAIL_PASS, EMAIL_TO])


def get_severity_color(severity: str) -> str:
    """Get HTML color for severity level."""
    colors = {
        "Critical": "#e74c3c",
        "High": "#c0392b",
        "Medium": "#f39c12",
        "Low": "#27ae60",
    }
    return colors.get(severity, "#7f8c8d")


def format_summary_html(summaries: List[Dict[str, Any]]) -> str:
    """
    Format threat summaries as a professional HTML email.
    
    Args:
        summaries: List of threat summary dictionaries.
        
    Returns:
        HTML string for email body.
    """
    # Count by severity
    severity_counts = {}
    for s in summaries:
        sev = s.get("severity", "Unknown")
        severity_counts[sev] = severity_counts.get(sev, 0) + 1
    
    stats_html = " | ".join([f"{sev}: {count}" for sev, count in severity_counts.items()])
    
    html = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <meta charset="utf-8">
        <style>
            body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; margin: 0; padding: 20px; background: #f5f5f5; }}
            .container {{ max-width: 800px; margin: 0 auto; background: white; border-radius: 8px; overflow: hidden; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }}
            .header {{ background: linear-gradient(135deg, #2c3e50, #3498db); color: white; padding: 20px 30px; }}
            .header h1 {{ margin: 0 0 5px 0; font-size: 24px; }}
            .header p {{ margin: 0; opacity: 0.9; font-size: 14px; }}
            .stats {{ background: #ecf0f1; padding: 15px 30px; font-size: 14px; color: #7f8c8d; }}
            .content {{ padding: 20px 30px; }}
            .threat {{ border-left: 4px solid #e74c3c; margin-bottom: 20px; padding: 15px; background: #fafafa; border-radius: 0 4px 4px 0; }}
            .threat-header {{ display: flex; justify-content: space-between; align-items: center; margin-bottom: 10px; }}
            .threat-ioc {{ font-family: monospace; font-weight: bold; font-size: 14px; color: #2c3e50; }}
            .severity {{ padding: 3px 10px; border-radius: 12px; font-size: 12px; font-weight: bold; color: white; }}
            .threat-meta {{ font-size: 12px; color: #7f8c8d; margin-bottom: 10px; }}
            .threat-summary {{ font-size: 14px; line-height: 1.6; color: #34495e; white-space: pre-wrap; }}
            .mitre {{ font-size: 12px; color: #3498db; margin-top: 10px; }}
            .footer {{ background: #ecf0f1; padding: 15px 30px; font-size: 12px; color: #7f8c8d; text-align: center; }}
        </style>
    </head>
    <body>
        <div class="container">
            <div class="header">
                <h1>🚨 Threat Intelligence Alert</h1>
                <p>Generated: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}</p>
            </div>
            <div class="stats">
                <strong>{len(summaries)} threats detected</strong> — {stats_html}
            </div>
            <div class="content">
    """
    
    for s in summaries:
        severity = s.get("severity", "Unknown")
        color = get_severity_color(severity)
        corrected = " (Auto-corrected)" if s.get("corrected") else ""
        
        # Truncate summary for email
        summary_text = s.get("summary", "No summary available.")
        if len(summary_text) > 500:
            summary_text = summary_text[:500] + "..."
        
        # MITRE tactics
        mitre_html = ""
        if s.get("mitre_tactics"):
            mitre_html = f'<div class="mitre">MITRE ATT&CK: {", ".join(s["mitre_tactics"])}</div>'
        
        html += f"""
            <div class="threat" style="border-left-color: {color};">
                <div class="threat-header">
                    <span class="threat-ioc">{s.get('input', 'Unknown IOC')}</span>
                    <span class="severity" style="background: {color};">{severity}{corrected}</span>
                </div>
                <div class="threat-meta">
                    {s.get('timestamp', 'N/A')}
                    {f" — {s.get('enrichment', '')[:80]}" if s.get('enrichment') else ""}
                </div>
                <div class="threat-summary">{summary_text}</div>
                {mitre_html}
            </div>
        """
    
    html += """
            </div>
            <div class="footer">
                AI Threat Intelligence Platform — See attached PDF for full report
            </div>
        </div>
    </body>
    </html>
    """
    
    return html


def attach_file(msg: MIMEMultipart, path: Path, name: str) -> bool:
    """
    Attach a file to the email message.
    
    Args:
        msg: The email message to attach to.
        path: Path to the file.
        name: Filename to use in the attachment.
        
    Returns:
        True if attached successfully, False otherwise.
    """
    if not path.exists():
        return False
        
    try:
        with open(path, "rb") as f:
            part = MIMEApplication(f.read(), Name=name)
            part['Content-Disposition'] = f'attachment; filename="{name}"'
            msg.attach(part)
        return True
    except Exception:
        return False


def send_batch_email(
    summaries: List[Dict[str, Any]],
    subject: Optional[str] = None
) -> bool:
    """
    Send a batched email with threat summaries and attachments.
    
    Args:
        summaries: List of threat summary dictionaries.
        subject: Optional custom subject line.
        
    Returns:
        True if email sent successfully, False otherwise.
    """
    if not summaries:
        return False
    
    if not is_email_configured():
        print("[⚠️ Email not configured - check EMAIL_USER, EMAIL_PASS, EMAIL_TO in .env]")
        return False

    # Build message
    msg = MIMEMultipart("mixed")
    msg["Subject"] = subject or f"[ALERT] {len(summaries)} High Severity Threats Detected"
    msg["From"] = EMAIL_USER
    msg["To"] = EMAIL_TO

    # HTML body
    html = format_summary_html(summaries)
    msg.attach(MIMEText(html, "html"))

    # Attach logs
    attach_file(msg, CSV_PATH, "threat_summaries.csv")
    attach_file(msg, JSON_PATH, "threat_summaries.json")

    # Generate and attach PDF
    try:
        pdf_path = generate_pdf(summaries)
        attach_file(msg, Path(pdf_path), "threat_summary_report.pdf")
    except Exception as e:
        print(f"[⚠️ PDF generation failed] {e}")

    # Send email
    try:
        if EMAIL_USE_TLS:
            with smtplib.SMTP(EMAIL_HOST, EMAIL_PORT, timeout=30) as server:
                server.starttls()
                server.login(EMAIL_USER, EMAIL_PASS)
                server.send_message(msg)
        else:
            # SSL connection (port 465)
            context = ssl.create_default_context()
            with smtplib.SMTP_SSL(EMAIL_HOST, EMAIL_PORT, context=context, timeout=30) as server:
                server.login(EMAIL_USER, EMAIL_PASS)
                server.send_message(msg)
                
        print(f"[📧 Email sent with {len(summaries)} threats to {EMAIL_TO}]")
        return True
        
    except smtplib.SMTPAuthenticationError:
        print("[❌ Email auth failed - check EMAIL_USER/EMAIL_PASS]")
    except smtplib.SMTPConnectError:
        print(f"[❌ Could not connect to {EMAIL_HOST}:{EMAIL_PORT}]")
    except Exception as e:
        print(f"[⚠️ Email failed: {type(e).__name__}] {e}")
    
    return False


def should_send_by_timer(interval_minutes: int = 10) -> bool:
    """
    Check if enough time has passed to send another email.
    
    Args:
        interval_minutes: Minimum minutes between emails.
        
    Returns:
        True if timer has elapsed.
    """
    global _last_email_time
    now = time.time()
    
    if now - _last_email_time >= interval_minutes * 60:
        _last_email_time = now
        return True
    return False


def reset_email_timer() -> None:
    """Reset the email timer to now."""
    global _last_email_time
    _last_email_time = time.time()
