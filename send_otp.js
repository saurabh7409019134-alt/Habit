/**
 * Gmail SMTP Email Delivery & 6-Digit OTP Verification Script (Node.js)
 * Configuration:
 *   - Host: smtp.gmail.com
 *   - Port: 587
 *   - Security: STARTTLS (secure: false, requireTLS: true)
 *   - Authenticated User: aipluslabs@gmail.com
 *   - Google App Password: borahyhecgkvvrbo
 */

const nodemailer = require('nodemailer');
const crypto = require('crypto');

// --- 1. SMTP & Credentials Configuration ---
const SMTP_HOST = process.env.SMTP_HOST || 'smtp.gmail.com';
const SMTP_PORT = parseInt(process.env.SMTP_PORT || '587', 10);
const GMAIL_USER = (process.env.GMAIL_USER || 'aipluslabs@gmail.com').trim();
const GMAIL_APP_PASSWORD = (process.env.GMAIL_APP_PASSWORD || 'borahyhecgkvvrbo').replace(/\s+/g, '');

// --- 2. 6-Digit OTP Generator ---
function generateSecureOtp() {
  return crypto.randomInt(100000, 999999).toString();
}

// --- 3. send_otp Function ---
async function send_otp(user_email) {
  if (!user_email || typeof user_email !== 'string' || !user_email.includes('@')) {
    throw new Error(`Invalid email address: ${user_email}`);
  }

  const recipient = user_email.trim().toLowerCase();
  const otp = generateSecureOtp();

  console.log(`Connecting to SMTP server at ${SMTP_HOST}:${SMTP_PORT}...`);
  console.log('Enabling STARTTLS encryption...');

  const transporter = nodemailer.createTransport({
    host: SMTP_HOST,
    port: SMTP_PORT,
    secure: false, // true for 465, false for 587 with STARTTLS
    requireTLS: true,
    auth: {
      user: GMAIL_USER,
      pass: GMAIL_APP_PASSWORD,
    },
  });

  const mailOptions = {
    from: `"KeepIt Habit Tracker" <${GMAIL_USER}>`,
    to: recipient,
    subject: `${otp} is your KeepIt verification code`,
    text: `KeepIt Habit Tracker\n\nYour verification code is: ${otp}\n\nThis code will expire in 10 minutes.\nIf you did not request this verification code, please ignore this email.`,
    html: `
      <div style="font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Helvetica,Arial,sans-serif;max-width:520px;margin:0 auto;background:#111827;color:#f3f4f6;border-radius:16px;padding:32px;border:1px solid #374151;">
        <div style="text-align:center;margin-bottom:24px;">
          <div style="font-size:28px;font-weight:800;color:#10b981;letter-spacing:-0.5px;">KeepIt</div>
          <div style="font-size:12px;color:#9ca3af;text-transform:uppercase;letter-spacing:1px;margin-top:4px;">Build Habits &bull; Keep Promises</div>
        </div>
        <div style="background:#1f2937;border-radius:12px;padding:24px;border:1px solid #374151;text-align:center;">
          <h2 style="font-size:18px;margin:0 0 8px;color:#ffffff;font-weight:600;">Confirm your email address</h2>
          <p style="font-size:14px;color:#9ca3af;margin:0 0 20px;line-height:1.5;">Enter the 6-digit verification code below to activate your account and start tracking:</p>
          <div style="display:inline-block;letter-spacing:10px;font-size:32px;font-weight:800;color:#10b981;background:#064e3b;padding:12px 24px;border-radius:10px;border:1px solid #059669;font-family:monospace;margin-bottom:16px;">
            ${otp}
          </div>
          <p style="font-size:12px;color:#6b7280;margin:0;">This verification code will expire in 10 minutes.</p>
        </div>
        <p style="font-size:12px;color:#6b7280;text-align:center;margin:24px 0 0;">If you didn't request this code, you can safely ignore this email.</p>
      </div>
    `,
  };

  console.log(`Authenticating as ${GMAIL_USER}...`);
  console.log(`Sending 6-digit OTP [${otp}] to ${recipient}...`);
  const info = await transporter.sendMail(mailOptions);
  console.log(`✅ OTP email successfully dispatched to ${recipient}! Message ID: ${info.messageId}`);

  return {
    success: true,
    recipient: recipient,
    otp: otp,
    messageId: info.messageId,
  };
}

// 4. Test line: Send sample OTP email to aipluslabs@gmail.com
if (require.main === module) {
  send_otp('aipluslabs@gmail.com')
    .then(res => console.log('Execution result:', res))
    .catch(err => {
      console.error('SMTP Error:', err);
      process.exit(1);
    });
}

module.exports = { send_otp };
