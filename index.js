
const express = require('express');
const cors = require('cors');
const axios = require('axios');
const dotenv = require('dotenv');
const rateLimit = require('express-rate-limit');
const admin = require('firebase-admin');
const { z } = require('zod');
const nodemailer = require('nodemailer');
const multer = require('multer');
const upload = multer({ storage: multer.memoryStorage(), limits: { fileSize: 10 * 1024 * 1024 } });
// NOTE: We intentionally avoid X-Frame-Options (deprecated in favour of CSP frame-ancestors)
dotenv.config();

const app = express();
const PORT = process.env.PORT || 3001;

// Middleware
// If behind a proxy (e.g., Render), trust it so correct proto/host are detected
app.set('trust proxy', 1);

// Configure CORS to properly respond to preflight requests
const allowedOrigins = [
  'http://localhost:3000',
  'http://localhost:3001',
  'http://localhost:3002',
  'http://192.168.1.138:3001',
  'https://wiseglobalresearch-services.web.app',
  'https://wiseglobalresearch.com',
];

const corsOptions = {
  origin: function (origin, callback) {
    // Allow requests with no origin (like mobile apps, curl) or from allowed list
    if (!origin || allowedOrigins.includes(origin) || /onrender\.com$/.test(new URL(origin).hostname)) {
      callback(null, true);
    } else {
      callback(new Error('Not allowed by CORS'));
    }
  },
  methods: ['GET', 'POST', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization'],
  credentials: false,
  optionsSuccessStatus: 204,
};

app.use(cors(corsOptions));
app.options('*', cors(corsOptions));
app.use(express.json());

// ---------------------------------------------------------------------------
// Security & Compatibility Headers Middleware
// ---------------------------------------------------------------------------
app.use((req, res, next) => {
  // Content negotiation is handled by express.json / res.json; ensure charset for any text/html responses
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  res.setHeader('Permissions-Policy', "camera=(), microphone=(), geolocation=(), fullscreen=* ");
  // A pragmatic CSP allowing required third‑party embeds; tighten further if possible
  const csp = [
    "default-src 'self'",
    "script-src 'self' https://www.googletagmanager.com https://s3.tradingview.com 'unsafe-inline'",
    "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com",
    "font-src 'self' https://fonts.gstatic.com data:",
    "img-src 'self' data: https:",
  "connect-src 'self' https://www.googletagmanager.com https://s3.tradingview.com https://widget.myfxbook.com https://fonts.googleapis.com https://fonts.gstatic.com",
    "frame-src https://www.youtube-nocookie.com https://www.tradingview.com https://s.tradingview.com https://widget.myfxbook.com",
    "frame-ancestors 'self'",
    "object-src 'none'",
    "base-uri 'self'",
    "form-action 'self'"
  ].join('; ');
  res.setHeader('Content-Security-Policy', csp);
  // Avoid deprecated headers flagged by audit (no P3P, Pragma, X-Frame-Options etc.)

  // Cache policy: shorter max-age for API, allow revalidation; health always no-store
  if (req.path === '/health') {
    res.setHeader('Cache-Control', 'no-store');
  } else if (req.path.startsWith('/api/')) {
    res.setHeader('Cache-Control', 'private, max-age=0, no-cache, no-store, must-revalidate');
  } else {
    // Allow modest caching with revalidation for any future static HTML served via this server
    res.setHeader('Cache-Control', 'public, max-age=300, stale-while-revalidate=60');
  }
  next();
});

// Rate limiter: limit each IP to 100 requests per 15 minutes
const limiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 100 });
app.use(limiter);

// Initialize Firebase Admin for verifying ID tokens
if (!admin.apps.length) {
  // Ensure a databaseURL is provided; fall back to the client firebase config
  // value if the environment variable is missing. This is safe because the
  // client config is public info (API key + database URL) and allows the
  // Admin SDK to operate locally without requiring the env var during dev.
  const fallbackDbUrl = 'https://wiseglobalresearch-services-default-rtdb.asia-southeast1.firebasedatabase.app/';
  admin.initializeApp({
    credential: admin.credential.applicationDefault(),
    databaseURL: process.env.FIREBASE_DATABASE_URL || fallbackDbUrl,
  });
}

// Middleware to require a valid Firebase ID token; restrict to admin users
const requireAdminAuth = async (req, res, next) => {
  try {
    const authHeader = req.header('Authorization') || '';
    const token = authHeader.startsWith('Bearer ') ? authHeader.slice(7) : null;
    if (!token) return res.status(401).json({ success: false, error: { message: 'Missing bearer token' } });
    const decoded = await admin.auth().verifyIdToken(token);
    let isAdmin = decoded.admin === true;
    if (!isAdmin) {
      try {
        const snap = await admin.database().ref(`admins/${decoded.uid}`).get();
        isAdmin = snap.exists() && snap.val() === true;
      } catch (_) {
        isAdmin = false;
      }
    }
    if (!isAdmin) return res.status(403).json({ success: false, error: { message: 'Admin only' } });
    req.user = decoded;
    next();
  } catch (e) {
    return res.status(401).json({ success: false, error: { message: 'Invalid token' } });
  }
};

// Digio API Configuration
const DIGIO_API_URL = process.env.DIGIO_API_URL;
const DIGIO_API_KEY = process.env.DIGIO_API_KEY;

// Schema for client form payload
const clientFormSchema = z.object({
  clientName: z.string().min(1),
  address: z.string().min(1),
  dob: z.string().min(1),
  pan: z.string().min(1),
  email: z.string().email(),
  clientId: z.string().optional(),
});

// API Route (admin-only)
app.post('/api/submit-client-form', requireAdminAuth, async (req, res) => {
  try {
    const parse = clientFormSchema.safeParse(req.body);
    if (!parse.success) {
      return res.status(400).json({ success: false, error: { message: 'Invalid payload', issues: parse.error.flatten() } });
    }
    const formData = parse.data;

    // Prepare payload for Digio API
    const postData = {
      signers: [
        {
          identifier: formData.email,
          name: formData.clientName,
          sign_type: "aadhaar"
        }
      ],
      expire_in_days: 10,
      send_sign_link: true,
      notify_signers: true,
      will_self_sign: false,
      display_on_page: "custom",
      file_name: `${formData.clientName}.pdf`,
      templates: [
        {
          template_key: "TMP250409085749067X19LUJRRQRYTGK",
          template_values: {
            "client full name": formData.clientName,
            "clientId": formData.clientId || "NA",
            "address": formData.address,
            "dob": formData.dob,
            "pan": formData.pan,
            "email": formData.email
          }
        }
      ]
    };

    // Make request to Digio API
    const response = await axios.post(DIGIO_API_URL, postData, {
      headers: {
        'Accept': 'application/json',
        'Authorization': DIGIO_API_KEY,
        'Content-Type': 'application/json'
      }
    });

    // Send success response
    res.json({
      success: true,
      data: response.data
    });
  } catch (error) {
    console.error('API Error:', error.response?.data || error.message);
    // Send error response
    res.status(error.response?.status || 500).json({
      success: false,
      error: error.response?.data || { message: 'Server error' }
    });
  }
});

// Simple health check
app.get('/health', (req, res) => {
  // Explicit content-type / charset for consistency with audit expectations
  res.setHeader('Content-Type', 'application/json; charset=utf-8');
  res.json({ status: 'ok' });
});

// ----------------------------
// Email sending endpoint
// ----------------------------
// Uses SMTP credentials provided via environment variables.
// Required env vars: SMTP_SERVER, SMTP_PORT, SMTP_USER, SMTP_PASS, EMAIL_FROM, EMAIL_TO
const emailSchema = z.object({
  name: z.string().min(1),
  mobile: z.string().optional(),
  city: z.string().optional(),
  interest: z.string().optional(),
  email: z.string().optional(),
  message: z.string().optional(),
  source: z.string().optional(),
});

// Accept both JSON and multipart/form-data (with optional file named 'resume')
app.post('/send-email', upload.single('resume'), async (req, res) => {
  try {
    // If multipart, fields are in req.body and file in req.file
    const incoming = Object.keys(req.body).length ? req.body : req.body || {};
    // Validate fields using zod by constructing an object similar to expected shape
    const parse = emailSchema.safeParse(incoming);
    if (!parse.success) {
      console.warn('Invalid /send-email payload:', parse.error.format());
      return res.status(400).json({ success: false, error: { message: 'Invalid payload', issues: parse.error.flatten() } });
    }
    const {
      name,
      mobile = '',
      city = '',
      interest = '',
      email: userEmail = '',
      message = '',
      source = ''
    } = parse.data;

    // Create transporter from env when available; otherwise use Ethereal in non-production
    let transporter;
    let usedEthereal = false;

    const smtpHost = process.env.SMTP_SERVER;
    const smtpPort = parseInt(process.env.SMTP_PORT || '587', 10);
    const smtpUser = process.env.SMTP_USER;
    const smtpPass = process.env.SMTP_PASS;

    if (smtpHost && smtpUser && smtpPass) {
      transporter = nodemailer.createTransport({
        host: smtpHost,
        port: smtpPort,
        secure: String(process.env.SMTP_PORT || '587') === '465',
        auth: { user: smtpUser, pass: smtpPass },
      });
    } else if (process.env.NODE_ENV !== 'production') {
      // Local dev: create an Ethereal test account to avoid ECONNREFUSED when real SMTP not configured
      console.warn('SMTP not configured, creating Ethereal test account for development email preview');
      const testAccount = await nodemailer.createTestAccount();
      transporter = nodemailer.createTransport({
        host: 'smtp.ethereal.email',
        port: 587,
        secure: false,
        auth: { user: testAccount.user, pass: testAccount.pass },
      });
      usedEthereal = true;
    } else {
      return res.status(500).json({ success: false, error: { message: 'SMTP configuration missing on server' } });
    }

    const from = process.env.EMAIL_FROM || smtpUser || 'no-reply@example.com';
    const infoEmail = process.env.INFO_EMAIL_TO || process.env.EMAIL_TO || 'hemraj8087@gmail.com';
    const supportEmail = process.env.SUPPORT_EMAIL_TO || 'support@wiseglobalresearch.com';
    const careerEmail = process.env.CAREER_EMAIL || 'career@wiseglobalresearch.com';

    // Build recipients depending on source/interest.
    let recipients = [];
    const isCareerSubmission = String(source).toLowerCase() === 'career' || String(interest).toLowerCase().includes('career');

    if (isCareerSubmission) {
      // For career submissions, send only to the career mailbox
      recipients.push(careerEmail);
    } else if (source === 'Complaints') {
      // For complaints, send to support
      recipients.push(supportEmail);
    } else {
      // For all other submissions, send to the general info mailbox
      recipients.push(infoEmail);
    }

    if (source === 'ContactPage') {
      recipients.push('hemraj@wiseglobalresearch.com');
    }
    // Deduplicate
    recipients = Array.from(new Set(recipients.filter(Boolean)));
    const to = recipients.join(',');

    console.debug('Sending notification email to:', to);

    const subject = `New website submission: ${interest || 'Interest'}${source ? ` (${source})` : ''}`;
    const textParts = [
      `You have a new submission from the website:`,
      `Name: ${name}`,
      `Email: ${userEmail || ''}`,
      `Mobile: ${mobile}`,
      `City: ${city}`,
      `Interest: ${interest}`,
    ];
    if (message) textParts.push(`Message: ${message}`);
    if (source) textParts.push(`Source: ${source}`);
    textParts.push('\n-- End of message');
    const text = textParts.join('\n');

    const html = `
      <p>You have a new submission from the website:</p>
      <ul>
        <li><strong>Name:</strong> ${name}</li>
        <li><strong>Email:</strong> ${userEmail || ''}</li>
        <li><strong>Mobile:</strong> ${mobile}</li>
        <li><strong>City:</strong> ${city}</li>
        <li><strong>Interest:</strong> ${interest}</li>
        ${message ? `<li><strong>Message:</strong> ${String(message)}</li>` : ''}
        ${source ? `<li><strong>Source:</strong> ${source}</li>` : ''}
      </ul>
    `;

    const mailOptions = {
      from,
      to,
      subject,
      text,
      html,
    };

    // If a resume file was included in multipart, attach it
    if (req.file && req.file.buffer) {
      mailOptions.attachments = [
        {
          filename: req.file.originalname || 'resume',
          content: req.file.buffer,
          contentType: req.file.mimetype || 'application/octet-stream',
        },
      ];
    }

    const info = await transporter.sendMail(mailOptions);

    // Helpful debug logging so we can see transport results during local testing
    console.debug('Email sent:', { messageId: info.messageId, envelope: info.envelope || null });

    const response = { success: true, messageId: info.messageId };
    if (usedEthereal) {
      response.previewUrl = nodemailer.getTestMessageUrl(info) || null;
    }
    res.json(response);
  } catch (error) {
    console.error('Email send error:', error);
    const message = error && error.message ? error.message : String(error);
    res.status(500).json({ success: false, error: { message } });
  }
});

// Basic economic events endpoint (mock data or pass-through when url is provided and whitelisted server-side)
app.get('/api/economic', async (req, res) => {
  try {
    const { url } = req.query;
    // If you later add whitelist + fetch real data, do it here. For now return mock events.
    const now = Date.now();
    const countries = ['IN', 'US', 'EU', 'GB', 'JP'];
    const titles = ['CPI (YoY)', 'GDP Growth Rate', 'Retail Sales MoM', 'Unemployment Rate', 'Trade Balance'];
    const out = Array.from({ length: 10 }).map((_, i) => {
      const t = new Date(now + (i + 1) * (30 + Math.floor(Math.random() * 90)) * 60000);
      const prev = (Math.random() * 5).toFixed(1) + '%';
      const consensus = (parseFloat(prev) + (Math.random() * 2 - 1)).toFixed(1) + '%';
      const actual = (parseFloat(consensus) + (Math.random() * 2 - 1)).toFixed(1) + '%';
      return {
        id: `srv-${now}-${i}`,
        date: t.toLocaleDateString(undefined, { month: 'short', day: 'numeric' }),
        time: t.toLocaleTimeString(undefined, { hour: '2-digit', minute: '2-digit' }),
        isoTime: t.toISOString(),
        country: countries[i % countries.length],
        title: titles[i % titles.length],
        impact: Math.ceil(Math.random() * 3),
        previous: prev,
        consensus,
        actual,
      };
    });
    res.json(out);
  } catch (e) {
    res.status(500).json({ error: 'failed to load economic data' });
  }
});

app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});

// Endpoint to accept popup form submissions from the client and persist
// them server-side using the Admin SDK. This avoids client-side permission
// issues when RTDB rules restrict unauthenticated or anonymous writes.
const popupSchema = z.object({
  name: z.string().optional(),
  mobile: z.string().optional(),
  city: z.string().optional(),
  interest: z.string().optional(),
  honeypot: z.string().optional(),
  timestamp: z.number().optional(),
});

app.post('/submit-popup', async (req, res) => {
  try {
    const parse = popupSchema.safeParse(req.body);
    if (!parse.success) {
      return res.status(400).json({ success: false, error: { message: 'Invalid payload', issues: parse.error.flatten() } });
    }
    const data = parse.data;

    // Basic bot protection: reject if honeypot filled
    if (data.honeypot && String(data.honeypot).trim().length > 0) {
      return res.status(400).json({ success: false, error: { message: 'Bot detected' } });
    }

    // Ensure timestamp
    const payload = Object.assign({ timestamp: Date.now() }, data);

    // Use Admin SDK to write to RTDB (bypasses client rules)
    const refPath = 'popupFormSubmissions';
    const pushRef = await admin.database().ref(refPath).push(payload);

    // Send notification email for popup submission (also send to career mailbox)
    try {
      // Create transporter from env when available; otherwise use Ethereal in non-production
      let transporter;
      let usedEthereal = false;

      const smtpHost = process.env.SMTP_SERVER;
      const smtpPort = parseInt(process.env.SMTP_PORT || '587', 10);
      const smtpUser = process.env.SMTP_USER;
      const smtpPass = process.env.SMTP_PASS;

      if (smtpHost && smtpUser && smtpPass) {
        transporter = nodemailer.createTransport({
          host: smtpHost,
          port: smtpPort,
          secure: String(process.env.SMTP_PORT || '587') === '465',
          auth: { user: smtpUser, pass: smtpPass },
        });
      } else if (process.env.NODE_ENV !== 'production') {
        const testAccount = await nodemailer.createTestAccount();
        transporter = nodemailer.createTransport({
          host: 'smtp.ethereal.email',
          port: 587,
          secure: false,
          auth: { user: testAccount.user, pass: testAccount.pass },
        });
        usedEthereal = true;
      } else {
        console.warn('/submit-popup email skipped: SMTP not configured');
      }

      if (transporter) {
        const from = process.env.EMAIL_FROM || smtpUser || 'no-reply@example.com';
  const infoEmail = process.env.INFO_EMAIL_TO || process.env.EMAIL_TO || 'info@mrxads.com';
  const supportEmail = process.env.SUPPORT_EMAIL_TO || 'support@wiseglobalresearch.com';
  const careerEmail = process.env.CAREER_EMAIL || 'career@wiseglobalresearch.com';

        // Build recipients: include career plus existing info/support
        const recipients = [careerEmail, infoEmail, supportEmail].filter(Boolean).join(',');

        const subject = `New popup submission: ${payload.interest || 'Interest'}`;
        const textParts = [
          'New popup submission received:',
          `Name: ${payload.name || ''}`,
          `Mobile: ${payload.mobile || ''}`,
          `City: ${payload.city || ''}`,
          `Interest: ${payload.interest || ''}`,
          `Timestamp: ${new Date(payload.timestamp).toISOString()}`,
          `RTDB Key: ${pushRef.key}`,
        ];

        const html = `
          <p>A new popup submission was received and persisted (key: <strong>${pushRef.key}</strong>):</p>
          <ul>
            <li><strong>Name:</strong> ${payload.name || ''}</li>
            <li><strong>Mobile:</strong> ${payload.mobile || ''}</li>
            <li><strong>City:</strong> ${payload.city || ''}</li>
            <li><strong>Interest:</strong> ${payload.interest || ''}</li>
            <li><strong>Timestamp:</strong> ${new Date(payload.timestamp).toISOString()}</li>
          </ul>
        `;

        const info = await transporter.sendMail({
          from,
          to: recipients,
          subject,
          text: textParts.join('\n'),
          html,
        });

        console.debug('/submit-popup email sent', { messageId: info.messageId, envelope: info.envelope || null });

        const response = { success: true, key: pushRef.key, messageId: info.messageId };
        if (usedEthereal) response.previewUrl = nodemailer.getTestMessageUrl(info) || null;
        return res.json(response);
      }

    } catch (mailErr) {
      console.error('/submit-popup email error:', mailErr);
      // Fall through to return success for DB write but include warning
      return res.json({ success: true, key: pushRef.key, warning: 'email_failed', details: mailErr.message || String(mailErr) });
    }

    // If email wasn't attempted (no transporter) still return DB success
    return res.json({ success: true, key: pushRef.key });
  } catch (error) {
    console.error('/submit-popup error:', error);
    res.status(500).json({ success: false, error: { message: error.message || String(error) } });
  }
});