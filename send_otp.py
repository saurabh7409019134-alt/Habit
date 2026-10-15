"""
Gmail SMTP Email Delivery & 6-Digit OTP Verification Script
Configuration:
  - Host: smtp.gmail.com
  - Port: 587
  - Security: STARTTLS
  - Authenticated User: aipluslabs@gmail.com (or via GMAIL_USER env var)
  - Google App Password: borahyhecgkvvrbo (or via GMAIL_APP_PASSWORD env var)
"""

import os
import secrets
import smtplib
import ssl
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

# --- 1. SMTP & Credentials Configuration ---
SMTP_HOST = os.environ.get("SMTP_HOST", "smtp.gmail.com")
SMTP_PORT = int(os.environ.get("SMTP_PORT", 587))
GMAIL_USER = os.environ.get("GMAIL_USER", "aipluslabs@gmail.com").strip()
GMAIL_APP_PASSWORD = os.environ.get("GMAIL_APP_PASSWORD", "borahyhecgkvvrbo").replace(" ", "").strip()


def generate_secure_otp(length: int = 6) -> str:
    """Generate a cryptographically secure numeric OTP."""
    # Using secrets to avoid predictable pseudo-random sequences
    return f"{secrets.randbelow(10**length):0{length}d}"


def send_otp(user_email: str) -> dict:
    """
    Generates a secure 6-digit verification code and dispatches it
    via Gmail SMTP (Port 587 + STARTTLS) inside a clean, modern HTML layout.
    """
    if not user_email or "@" not in user_email:
        raise ValueError(f"Invalid recipient email address: '{user_email}'")

    recipient = user_email.strip().lower()
    otp_code = generate_secure_otp(6)

    # --- Construct Multipart Email ---
    message = MIMEMultipart("alternative")
    message["Subject"] = f"{otp_code} is your KeepIt verification code"
    message["From"] = f"KeepIt Habit Tracker <{GMAIL_USER}>"
    message["To"] = recipient

    # Plain-text fallback for non-HTML mail clients
    text_content = (
        f"KeepIt Habit Tracker\n\n"
        f"Your verification code is: {otp_code}\n\n"
        f"This code will expire in 10 minutes.\n"
        f"If you did not request this verification code, please ignore this email.\n"
    )

    # Clean, modern, responsive HTML template
    html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Verification Code</title>
</head>
<body style="margin: 0; padding: 24px; background-color: #0b0f19; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; color: #f3f4f6;">
  <table role="presentation" width="100%" border="0" cellspacing="0" cellpadding="0" style="max-width: 520px; margin: 0 auto; background-color: #111827; border-radius: 16px; border: 1px solid #1f2937; overflow: hidden; box-shadow: 0 10px 25px -5px rgba(0, 0, 0, 0.5);">
    <!-- Header -->
    <tr>
      <td style="padding: 32px 32px 16px; text-align: center;">
        <div style="font-size: 28px; font-weight: 800; color: #10b981; letter-spacing: -0.5px;">KeepIt</div>
        <div style="font-size: 11px; color: #9ca3af; text-transform: uppercase; letter-spacing: 1.5px; margin-top: 4px;">Build Habits &bull; Keep Promises</div>
      </td>
    </tr>

    <!-- Card Body -->
    <tr>
      <td style="padding: 0 32px 24px;">
        <table role="presentation" width="100%" border="0" cellspacing="0" cellpadding="0" style="background-color: #1f2937; border-radius: 12px; border: 1px solid #374151;">
          <tr>
            <td style="padding: 24px; text-align: center;">
              <h2 style="margin: 0 0 10px; font-size: 18px; font-weight: 600; color: #ffffff;">Confirm your email address</h2>
              <p style="margin: 0 0 24px; font-size: 14px; color: #9ca3af; line-height: 1.5;">
                Enter the 6-digit verification code below to activate your account and start tracking your habits:
              </p>

              <!-- OTP Box -->
              <div style="display: inline-block; background-color: #064e3b; border: 1px solid #059669; border-radius: 10px; padding: 14px 28px; margin-bottom: 20px;">
                <span style="font-family: 'SFMono-Regular', Consolas, 'Liberation Mono', Menlo, monospace; font-size: 32px; font-weight: 800; letter-spacing: 8px; color: #34d399; display: inline-block;">
                  {otp_code}
                </span>
              </div>

              <p style="margin: 0; font-size: 12px; color: #6b7280;">
                &#9201; This verification code expires in <strong style="color: #9ca3af;">10 minutes</strong>.
              </p>
            </td>
          </tr>
        </table>
      </td>
    </tr>

    <!-- Footer -->
    <tr>
      <td style="padding: 0 32px 32px; text-align: center;">
        <p style="margin: 0 0 6px; font-size: 12px; color: #6b7280;">
          If you did not request this email, you can safely ignore it.
        </p>
        <p style="margin: 0; font-size: 11px; color: #4b5563;">
          &copy; KeepIt Habit Tracker &bull; All rights reserved.
        </p>
      </td>
    </tr>
  </table>
</body>
</html>"""

    # Attach both plain text and HTML versions
    message.attach(MIMEText(text_content, "plain"))
    message.attach(MIMEText(html_content, "html"))

    # --- Connect via SMTP Port 587 with STARTTLS ---
    print(f"Connecting to SMTP server at {SMTP_HOST}:{SMTP_PORT}...")
    context = ssl.create_default_context()

    with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=20) as server:
        # Greet SMTP server
        server.ehlo()
        # Secure the connection with STARTTLS
        print("Enabling STARTTLS encryption...")
        server.starttls(context=context)
        server.ehlo()

        # Authenticate with credentials
        print(f"Authenticating as {GMAIL_USER}...")
        server.login(GMAIL_USER, GMAIL_APP_PASSWORD)

        # Dispatch the message
        print(f"Sending 6-digit OTP [{otp_code}] to {recipient}...")
        server.sendmail(GMAIL_USER, [recipient], message.as_string())
        print(f"✅ OTP email successfully dispatched to {recipient}!")

    return {
        "success": True,
        "recipient": recipient,
        "otp": otp_code,
        "message": f"Verification code successfully sent to {recipient}"
    }


# Test line: Send sample OTP email to aipluslabs@gmail.com to verify SMTP connection
if __name__ == "__main__":
    result = send_otp("aipluslabs@gmail.com")
    print(f"Execution result: {result}")
