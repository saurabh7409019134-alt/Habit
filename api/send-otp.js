const nodemailer = require('nodemailer');
const { createClient } = require('@supabase/supabase-js');

const SUPABASE_URL = process.env.SUPABASE_URL || 'https://zfpcfibranwzzbpydgxp.supabase.co';
const SUPABASE_KEY = process.env.SUPABASE_SERVICE_ROLE_KEY || process.env.SUPABASE_ANON_KEY || 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6InpmcGNmaWJyYW53enpicHlkZ3hwIiwicm9sZSI6ImFub24iLCJpYXQiOjE3NjAzOTAzMjgsImV4cCI6MjA3NTk2NjMyOH0.6t7rE76rYgCqW0i7h5yV3F1sY3UqN5m4vY0v7g3R7qA';

const supabase = createClient(SUPABASE_URL, SUPABASE_KEY);

module.exports = async function handler(req, res) {
  // Enable CORS
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

  if (req.method === 'OPTIONS') {
    return res.status(200).end();
  }

  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'Method not allowed' });
  }

  try {
    const { email, otp: clientOtp } = req.body || {};
    if (!email || typeof email !== 'string' || !email.includes('@')) {
      return res.status(400).json({ error: 'A valid email address is required.' });
    }

    const normEmail = email.trim().toLowerCase();
    
    // Generate secure 6-digit OTP if not provided
    const otp = clientOtp && /^\d{6}$/.test(clientOtp)
      ? clientOtp
      : Math.floor(100000 + Math.random() * 900000).toString();

    const expiresAt = new Date(Date.now() + 10 * 60 * 1000).toISOString();

    // 1. Store OTP record in Supabase email_otps table
    try {
      await supabase.from('email_otps').upsert({
        email: normEmail,
        otp: otp,
        created_at: new Date().toISOString(),
        expires_at: expiresAt
      }, { onConflict: 'email' });
    } catch (dbErr) {
      console.warn('Warning storing OTP in database:', dbErr);
    }

    // 2. Validate Gmail environment credentials
    const gmailUser = (process.env.GMAIL_USER || 'aipluslabs@gmail.com').trim();
    const gmailPass = (process.env.GMAIL_APP_PASSWORD || 'borahyhecgkvvrbo').replace(/\s+/g, '');

    if (!gmailUser || !gmailPass) {
      return res.status(200).json({
        success: true,
        sent: false,
        message: 'Gmail credentials not configured in environment variables. OTP stored in database.',
        otp: otp
      });
    }

    // 3. Initialize mail server connection (Gmail SMTP Port 587 + STARTTLS)
    const transporter = nodemailer.createTransport({
      host: 'smtp.gmail.com',
      port: 587,
      secure: false, // true for 465, false for other ports
      requireTLS: true,
      auth: {
        user: gmailUser,
        pass: gmailPass
      }
    });

    // 4. Send rich HTML verification email
    const mailOptions = {
      from: `"KeepIt Habit Tracker" <${gmailUser}>`,
      to: normEmail,
      subject: `${otp} is your KeepIt verification code`,
      text: `Your KeepIt verification code is: ${otp}. This code expires in 10 minutes.`,
      html: `
        <div style="font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Helvetica,Arial,sans-serif;max-width:520px;margin:0 auto;background:#111827;color:#f3f4f6;border-radius:16px;padding:32px;border:1px solid #374151;">
          <div style="text-align:center;margin-bottom:24px;">
            <div style="font-size:28px;font-weight:800;color:#10b981;letter-spacing:-0.5px;">KeepIt</div>
            <div style="font-size:12px;color:#9ca3af;text-transform:uppercase;letter-spacing:1px;margin-top:4px;">Build Habits. Keep Promises.</div>
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
      `
    };

    await transporter.sendMail(mailOptions);

    return res.status(200).json({
      success: true,
      sent: true,
      message: 'Verification code sent to ' + normEmail
    });

  } catch (err) {
    console.error('Error sending OTP email:', err);
    return res.status(500).json({
      error: 'Failed to dispatch email',
      details: err.message
    });
  }
};
