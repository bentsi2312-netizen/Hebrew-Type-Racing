require('dotenv').config();
const express = require('express');
const path = require('path');
const crypto = require('crypto');
const nodemailer = require('nodemailer');

const app = express();
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

const otpStore = new Map();

const isIsraeliPhone = (phone) => /^(05\d{8}|\+9725\d{8})$/.test(phone || '');
const isEmail = (email) => /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email || '');
const normalizePhone = (phone) => phone.startsWith('+972') ? phone : '+972' + phone.slice(1);

function code() {
  return Math.floor(100000 + Math.random() * 900000).toString();
}
function saveOtp(key, otp) {
  otpStore.set(key, { otp, expiresAt: Date.now() + 10 * 60 * 1000 });
}
function readOtp(key) {
  const item = otpStore.get(key);
  if (!item) return null;
  if (Date.now() > item.expiresAt) {
    otpStore.delete(key);
    return null;
  }
  return item.otp;
}

let twilioClient = null;
if (process.env.TWILIO_ACCOUNT_SID && process.env.TWILIO_AUTH_TOKEN) {
  try {
    const twilio = require('twilio');
    twilioClient = twilio(process.env.TWILIO_ACCOUNT_SID, process.env.TWILIO_AUTH_TOKEN);
  } catch (e) {}
}

let mailer = null;
if (process.env.SMTP_HOST && process.env.SMTP_USER && process.env.SMTP_PASS) {
  mailer = nodemailer.createTransport({
    host: process.env.SMTP_HOST,
    port: Number(process.env.SMTP_PORT || 587),
    secure: String(process.env.SMTP_SECURE || 'false') === 'true',
    auth: { user: process.env.SMTP_USER, pass: process.env.SMTP_PASS }
  });
}

app.post('/api/send-sms', async (req, res) => {
  try {
    const phone = String(req.body.phone || '').trim();
    if (!isIsraeliPhone(phone)) {
      return res.status(400).json({ error: 'אנא הזן מספר טלפון ישראלי תקין.' });
    }

    const otp = code();
    const normalized = normalizePhone(phone);

    if (process.env.TWILIO_VERIFY_SERVICE_SID && twilioClient) {
      await twilioClient.verify.v2
        .services(process.env.TWILIO_VERIFY_SERVICE_SID)
        .verifications.create({ channel: 'sms', to: normalized });
      return res.json({ message: 'נשלח קוד אימות לטלפון שלך.' });
    }

    if (twilioClient && process.env.TWILIO_PHONE_NUMBER) {
      saveOtp(normalized, otp);
      await twilioClient.messages.create({
        body: `קוד האימות שלך הוא: ${otp}`,
        to: normalized,
        from: process.env.TWILIO_PHONE_NUMBER
      });
      return res.json({ message: 'נשלח קוד אימות לטלפון שלך.' });
    }

    saveOtp(normalized, otp);
    return res.json({
      message: 'אין כרגע חיבור ל-SMS אמיתי. לצורך בדיקה בלבד, הקוד נשמר בשרת.',
      debugCode: process.env.ALLOW_DEBUG_CODES === 'true' ? otp : undefined
    });
  } catch (err) {
    return res.status(500).json({ error: 'שגיאה בשליחת ה-SMS.' });
  }
});

app.post('/api/verify-sms', async (req, res) => {
  try {
    const phone = String(req.body.phone || '').trim();
    const entered = String(req.body.code || '').trim();
    if (!isIsraeliPhone(phone) || !entered) {
      return res.status(400).json({ error: 'פרטים חסרים.' });
    }

    const normalized = normalizePhone(phone);

    if (process.env.TWILIO_VERIFY_SERVICE_SID && twilioClient) {
      const check = await twilioClient.verify.v2
        .services(process.env.TWILIO_VERIFY_SERVICE_SID)
        .verificationChecks.create({ to: normalized, code: entered });

      if (check.status === 'approved' || check.valid) {
        return res.json({ message: 'הטלפון אומת בהצלחה!' });
      }
      return res.status(400).json({ error: 'קוד שגוי או שפג תוקפו.' });
    }

    const saved = readOtp(normalized);
    if (!saved) return res.status(400).json({ error: 'לא נמצא קוד פעיל או שפג תוקפו.' });
    if (saved !== entered) return res.status(400).json({ error: 'קוד שגוי.' });

    otpStore.delete(normalized);
    return res.json({ message: 'הטלפון אומת בהצלחה!' });
  } catch (err) {
    return res.status(500).json({ error: 'שגיאה באימות הקוד.' });
  }
});

app.post('/api/send-email', async (req, res) => {
  try {
    const email = String(req.body.email || '').trim().toLowerCase();
    if (!isEmail(email)) {
      return res.status(400).json({ error: 'אנא הזן כתובת אימייל תקינה.' });
    }

    const otp = code();
    saveOtp(email, otp);

    if (mailer) {
      await mailer.sendMail({
        from: process.env.MAIL_FROM || process.env.SMTP_USER,
        to: email,
        subject: 'קוד אימות - הקלדת מילים בעברית',
        text: `קוד האימות שלך הוא: ${otp}\nהקוד תקף ל-10 דקות.`,
        html: `<div dir="rtl" style="font-family:Arial,sans-serif">
          <h2>קוד אימות</h2>
          <p>קוד האימות שלך הוא:</p>
          <div style="font-size:32px;font-weight:bold">${otp}</div>
          <p>הקוד תקף ל-10 דקות.</p>
        </div>`
      });
      return res.json({ message: 'נשלח קוד אימות לאימייל שלך.' });
    }

    return res.json({
      message: 'אין כרגע חיבור לאימייל אמיתי. לצורך בדיקה בלבד, הקוד נשמר בשרת.',
      debugCode: process.env.ALLOW_DEBUG_CODES === 'true' ? otp : undefined
    });
  } catch (err) {
    return res.status(500).json({ error: 'שגיאה בשליחת האימייל.' });
  }
});

app.post('/api/verify-email', async (req, res) => {
  try {
    const email = String(req.body.email || '').trim().toLowerCase();
    const entered = String(req.body.code || '').trim();
    if (!isEmail(email) || !entered) {
      return res.status(400).json({ error: 'פרטים חסרים.' });
    }

    const saved = readOtp(email);
    if (!saved) return res.status(400).json({ error: 'לא נמצא קוד פעיל או שפג תוקפו.' });
    if (saved !== entered) return res.status(400).json({ error: 'קוד שגוי.' });

    otpStore.delete(email);
    return res.json({ message: 'האימייל אומת בהצלחה!' });
  } catch (err) {
    return res.status(500).json({ error: 'שגיאה באימות האימייל.' });
  }
});

app.get('/health', (_req, res) => res.json({ ok: true }));

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});
