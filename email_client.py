import os
import smtplib
import ssl
from datetime import datetime
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from dotenv import load_dotenv

load_dotenv()

SMTP_HOST     = os.getenv("SMTP_HOST",     "smtp.gmail.com")
SMTP_PORT     = int(os.getenv("SMTP_PORT", "465"))
SMTP_USER     = os.getenv("SMTP_USER")
SMTP_PASSWORD = os.getenv("SMTP_PASSWORD")
SMTP_FROM     = os.getenv("SMTP_FROM", SMTP_USER)
SMTP_USE_SSL  = os.getenv("SMTP_USE_SSL", "true").lower()  == "true"
SMTP_USE_TLS  = os.getenv("SMTP_USE_TLS", "false").lower() == "true"

URGENCY_COLOR = {
    "CRITICAL": "#dc2626",
    "HIGH":     "#ea580c",
    "MEDIUM":   "#ca8a04",
    "LOW":      "#2563eb",
}


# ── Core send ─────────────────────────────────────────────────────────────────

def send_email(
    to:        str | list,
    subject:   str,
    body_text: str,
    body_html: str = None,
    cc:        str | list = None,
    reply_to:  str = None,
) -> dict:
    """
    Send an email via configured SMTP.
    Returns {"success": True/False, ...details}
    """
    try:
        to_list = [to] if isinstance(to, str) else to
        cc_list = ([cc] if isinstance(cc, str) else cc) if cc else []

        msg            = MIMEMultipart("alternative")
        msg["Subject"] = subject
        msg["From"]    = f"Vulnerability Scanner <{SMTP_FROM}>"
        msg["To"]      = ", ".join(to_list)
        if cc_list:   msg["Cc"]       = ", ".join(cc_list)
        if reply_to:  msg["Reply-To"] = reply_to

        msg.attach(MIMEText(body_text, "plain"))
        if body_html:
            msg.attach(MIMEText(body_html, "html"))

        recipients = to_list + cc_list

        if SMTP_USE_SSL:
            with smtplib.SMTP_SSL(SMTP_HOST, SMTP_PORT, context=ssl.create_default_context()) as s:
                s.login(SMTP_USER, SMTP_PASSWORD)
                s.sendmail(SMTP_FROM, recipients, msg.as_string())
        elif SMTP_USE_TLS:
            with smtplib.SMTP(SMTP_HOST, SMTP_PORT) as s:
                s.ehlo(); s.starttls()
                s.login(SMTP_USER, SMTP_PASSWORD)
                s.sendmail(SMTP_FROM, recipients, msg.as_string())
        else:
            with smtplib.SMTP(SMTP_HOST, SMTP_PORT) as s:
                s.sendmail(SMTP_FROM, recipients, msg.as_string())

        return {"success": True, "to": to_list, "cc": cc_list,
                "subject": subject, "sent_at": datetime.now().isoformat()}

    except smtplib.SMTPAuthenticationError:
        return {"success": False, "error": "Auth failed — check SMTP_USER/SMTP_PASSWORD in .env"}
    except smtplib.SMTPRecipientsRefused:
        return {"success": False, "error": f"Recipient refused: {to}"}
    except smtplib.SMTPException as e:
        return {"success": False, "error": f"SMTP error: {e}"}
    except Exception as e:
        return {"success": False, "error": str(e)}


# ── Templates ─────────────────────────────────────────────────────────────────

def build_owner_email(
    owner_name:    str,
    hostname:      str,
    ip:            str,
    findings_text: str,
    urgency:       str = "HIGH",
) -> tuple[str, str, str]:
    """
    Build (subject, plain_text, html) email for an asset owner.
    urgency: CRITICAL | HIGH | MEDIUM | LOW
    """
    color     = URGENCY_COLOR.get(urgency, URGENCY_COLOR["HIGH"])
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M")
    subject   = f"[{urgency}] Vulnerability Report — {hostname} ({ip})"

    body_text = f"""Dear {owner_name},

Automated security alert for: {hostname} ({ip})
Urgency:   {urgency}
Generated: {timestamp}

{findings_text}

Remediation Timelines:
  CRITICAL / KEV : 24-48 hours
  HIGH           : 1 week
  MEDIUM         : 1 month

--
Automated Security Scanner — Vulnerability Management Team
Do not reply to this email."""

    body_html = f"""<!DOCTYPE html>
<html>
<body style="font-family:Arial,sans-serif;max-width:680px;margin:0 auto;padding:20px;color:#1f2937;">

  <div style="background:{color};color:white;padding:16px 20px;border-radius:6px 6px 0 0;">
    <h2 style="margin:0;font-size:18px;">⚠️ [{urgency}] Security Alert — {hostname}</h2>
    <p style="margin:4px 0 0;font-size:12px;opacity:.85;">Generated: {timestamp}</p>
  </div>

  <div style="background:#f9fafb;border:1px solid #e5e7eb;border-top:none;padding:20px;border-radius:0 0 6px 6px;">
    <p>Dear <strong>{owner_name}</strong>,</p>
    <p>Vulnerabilities detected on <strong>{hostname}</strong>
       (<code style="background:#f3f4f6;padding:1px 4px;border-radius:3px;">{ip}</code>).</p>

    <div style="background:white;border:1px solid #e5e7eb;border-left:4px solid {color};
                border-radius:4px;padding:16px;margin:16px 0;">
      <pre style="font-family:monospace;font-size:12px;white-space:pre-wrap;margin:0;color:#374151;">{findings_text}</pre>
    </div>

    <table style="width:100%;border-collapse:collapse;font-size:13px;margin-top:12px;">
      <thead>
        <tr style="background:#f3f4f6;">
          <th style="padding:8px;text-align:left;border:1px solid #e5e7eb;">Severity</th>
          <th style="padding:8px;text-align:left;border:1px solid #e5e7eb;">Required Timeline</th>
        </tr>
      </thead>
      <tbody>
        <tr>
          <td style="padding:8px;border:1px solid #e5e7eb;color:#dc2626;"><strong>Critical / KEV</strong></td>
          <td style="padding:8px;border:1px solid #e5e7eb;">24–48 hours</td>
        </tr>
        <tr style="background:#f9fafb;">
          <td style="padding:8px;border:1px solid #e5e7eb;color:#ea580c;"><strong>High</strong></td>
          <td style="padding:8px;border:1px solid #e5e7eb;">1 week</td>
        </tr>
        <tr>
          <td style="padding:8px;border:1px solid #e5e7eb;color:#ca8a04;"><strong>Medium</strong></td>
          <td style="padding:8px;border:1px solid #e5e7eb;">1 month</td>
        </tr>
      </tbody>
    </table>

    <p style="margin-top:20px;font-size:11px;color:#9ca3af;">
      Automated Security Scanner — Vulnerability Management System<br>
      Do not reply to this email.
    </p>
  </div>
</body>
</html>"""

    return subject, body_text, body_html


def test_connection() -> dict:
    """Test SMTP credentials without sending an email."""
    try:
        if SMTP_USE_SSL:
            with smtplib.SMTP_SSL(SMTP_HOST, SMTP_PORT, context=ssl.create_default_context()) as s:
                s.login(SMTP_USER, SMTP_PASSWORD)
        elif SMTP_USE_TLS:
            with smtplib.SMTP(SMTP_HOST, SMTP_PORT) as s:
                s.starttls(); s.login(SMTP_USER, SMTP_PASSWORD)
        return {"success": True, "host": SMTP_HOST, "port": SMTP_PORT,
                "user": SMTP_USER, "ssl": SMTP_USE_SSL, "tls": SMTP_USE_TLS}
    except Exception as e:
        return {"success": False, "error": str(e)}


if __name__ == "__main__":
    print("Testing SMTP connection...")
    r = test_connection()
    if r["success"]:
        print(f"✅ Connected to {r['host']}:{r['port']} as {r['user']}")
    else:
        print(f"❌ {r['error']}")
