/**
 * server.js — Clean, complete implementation (Groq AI + Cloudinary + Google Auth + Stripe Checkout/Webhook + simple JSON DB)
 *
 * Notes:
 * - Put real credentials in environment variables (CLOUDINARY_*, STRIPE_*, GOOGLE_*, MAIL_*, GROQ_API_KEY, SESSION_SECRET, DOMAIN, etc.)
 * - This uses a simple file-backed JSON DB at /data/db.json for quick prototyping (works on Render free).
 * - Webhook endpoint uses raw body for signature verification.
 * - Puppeteer is used to render HTML -> PDF (ensure Render supports headless Chromium in your plan).
 *
 * Environment variables used:
 * - CLOUDINARY_CLOUD_NAME, CLOUDINARY_API_KEY, CLOUDINARY_API_SECRET
 * - STRIPE_SECRET_KEY, STRIPE_PRICE_ID, STRIPE_WEBHOOK_SECRET
 * - GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET
 * - GROQ_API_KEY, GROQ_MODEL
 * - MAIL_HOST, MAIL_PORT, MAIL_SECURE, MAIL_USER, MAIL_PASS, MAIL_FROM
 * - SESSION_SECRET
 * - DOMAIN (public-facing URL, e.g. https://job-fit-smv4.onrender.com)
 */

require('dotenv').config();

const express = require('express');
const bodyParser = require('body-parser'); // used for webhook raw body
const app = express();
const path = require('path');
const fs = require('fs');
const multer = require('multer');
const session = require('express-session');
const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const nodemailer = require('nodemailer');
const cloudinary = require('cloudinary').v2;
const puppeteer = require('puppeteer');
const pdfParse = require('pdf-parse');
const mammoth = require('mammoth');

// Stripe
const stripe = require('stripe')(process.env.STRIPE_SECRET_KEY || 'sk_test_PLACEHOLDER');

// GROQ (AI)
const Groq = require('groq-sdk');
const groq = new Groq({ apiKey: process.env.GROQ_API_KEY || '' });

// Node 18+ global fetch fallback
const fetch = (...args) => import('node-fetch').then(({ default: fetch }) => fetch(...args));

// Directories & DB file
const publicPath = path.join(__dirname, 'public');
const uploadDir = path.join(__dirname, 'uploads');
const generatedDir = path.join(__dirname, 'generated');
const dataDir = path.join(__dirname, 'data');
const dbPath = path.join(dataDir, 'db.json');

for (const d of [uploadDir, generatedDir, dataDir]) {
  if (!fs.existsSync(d)) fs.mkdirSync(d, { recursive: true });
}

function ensureDb() {
  if (!fs.existsSync(dbPath)) {
    const initial = { users: {}, saved: [], optimizations: [], payments: [], subscriptions: [] };
    fs.writeFileSync(dbPath, JSON.stringify(initial, null, 2), 'utf8');
  }
}
ensureDb();

function readDb() {
  try {
    ensureDb();
    return JSON.parse(fs.readFileSync(dbPath, 'utf8'));
  } catch (e) {
    console.error('readDb error', e);
    return { users: {}, saved: [], optimizations: [], payments: [], subscriptions: [] };
  }
}
function writeDb(obj) {
  fs.writeFileSync(dbPath, JSON.stringify(obj, null, 2), 'utf8');
}

// Cloudinary config
cloudinary.config({
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME || '',
  api_key: process.env.CLOUDINARY_API_KEY || '',
  api_secret: process.env.CLOUDINARY_API_SECRET || '',
});

// --- Middleware ---
// Use raw body only for webhook; other routes use JSON
app.use((req, res, next) => {
  if (req.originalUrl === '/webhook') return next();
  bodyParser.json({ limit: '10mb' })(req, res, next);
});
app.use(bodyParser.urlencoded({ extended: true }));

app.use(
  session({
    secret: process.env.SESSION_SECRET || 'dev_secret',
    resave: false,
    saveUninitialized: false,
    cookie: { maxAge: 24 * 60 * 60 * 1000 },
  })
);

// passport (Google)
app.use(passport.initialize());
app.use(passport.session());

passport.use(
  new GoogleStrategy(
    {
      clientID: process.env.GOOGLE_CLIENT_ID || '',
      clientSecret: process.env.GOOGLE_CLIENT_SECRET || '',
      callbackURL: '/auth/google/callback',
    },
    (accessToken, refreshToken, profile, done) => {
      const user = {
        id: profile.id,
        name: profile.displayName,
        email: profile.emails?.[0]?.value,
        photo: profile.photos?.[0]?.value,
      };
      done(null, user);
    }
  )
);

passport.serializeUser((user, done) => done(null, user));
passport.deserializeUser((obj, done) => done(null, obj));

// static folders
app.use(express.static(publicPath));
app.use('/uploads', express.static(uploadDir));
app.use('/generated', express.static(generatedDir));

// multer
const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, uploadDir),
  filename: (req, file, cb) => {
    const safe = file.originalname.replace(/\s+/g, '_').replace(/[^a-zA-Z0-9._-]/g, '');
    cb(null, `${Date.now()}-${safe}`);
  },
});
const upload = multer({ storage });

// --- Helpers ---
function escapeHtml(str) {
  return String(str).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
}

function stripHtmlToText(html) {
  if (!html) return '';
  return String(html).replace(/<\/?[^>]+(>|$)/g, ' ').replace(/\s{2,}/g, ' ').trim();
}

function removeAiExtraSections(html) {
  if (!html) return '';
  return html
    .replace(/<h2>Quick tips<\/h2>[\s\S]*?(?=<h2|<\/div>)/gi, '')
    .replace(/<h2>Extracted keywords<\/h2>[\s\S]*?(?=<h2|<\/div>)/gi, '')
    .replace(/Generated by Job-Fit — optimized using AI/gi, '')
    .replace(/\s{2,}/g, ' ')
    .trim();
}

async function extractTextFromFile(absPath) {
  try {
    const ext = path.extname(absPath).toLowerCase();
    if (ext === '.pdf') {
      const data = fs.readFileSync(absPath);
      const parsed = await pdfParse(data);
      return parsed?.text || '';
    }
    if (ext === '.docx') {
      const result = await mammoth.extractRawText({ path: absPath });
      return result?.value || '';
    }
    return fs.readFileSync(absPath, 'utf8');
  } catch (err) {
    console.warn('extractTextFromFile error:', err?.message || err);
    return '';
  }
}

async function fetchJobPostingText(url) {
  if (!url) return '';
  try {
    const r = await fetch(url, { timeout: 10000 });
    const html = await r.text();
    const ogDesc = html.match(/<meta[^>]+property=["']og:description["'][^>]*content=["']([^"']+)["']/i);
    const metaDesc = html.match(/<meta[^>]+name=["']description["'][^>]*content=["']([^"']+)["']/i);
    const candidate = ogDesc?.[1] || metaDesc?.[1];
    if (candidate) return candidate.slice(0, 2000);
    const cleaned = html
      .replace(/<script[\s\S]*?>[\s\S]*?<\/script>/gi, '')
      .replace(/<style[\s\S]*?>[\s\S]*?<\/style>/gi, '')
      .replace(/<\/?[^>]+(>|$)/g, ' ')
      .replace(/\s{2,}/g, ' ')
      .trim();
    return cleaned.slice(0, 3000);
  } catch (err) {
    console.warn('fetchJobPostingText error:', err?.message || err);
    return '';
  }
}

async function createTransporter() {
  if (!process.env.MAIL_HOST) return null;
  return nodemailer.createTransport({
    host: process.env.MAIL_HOST,
    port: Number(process.env.MAIL_PORT || 587),
    secure: (process.env.MAIL_SECURE === 'true'),
    auth: {
      user: process.env.MAIL_USER,
      pass: process.env.MAIL_PASS,
    },
  });
}

// --- Routes: Auth & basic ---
app.get('/', (req, res) => res.sendFile(path.join(publicPath, 'index.html')));
app.get('/auth/google', passport.authenticate('google', { scope: ['profile', 'email'] }));
app.get(
  '/auth/google/callback',
  passport.authenticate('google', { failureRedirect: '/' }),
  (req, res) => {
    req.session.user = req.user;

    // ensure user record in db
    try {
      const db = readDb();
      db.users = db.users || {};
      db.users[req.user.id] = db.users[req.user.id] || { id: req.user.id, name: req.user.name, email: req.user.email };
      writeDb(db);
    } catch (e) {
      console.warn('failed to persist user', e);
    }

    res.redirect('/dashboard.html');
  }
);

app.get('/logout', (req, res) => {
  req.logout(() => {
    req.session.destroy(() => res.redirect('/'));
  });
});

app.get('/api/user', (req, res) => {
  if (req.session.user) return res.json({ loggedIn: true, user: req.session.user });
  return res.json({ loggedIn: false });
});

// --- Upload original CV (local + Cloudinary) ---
app.post('/upload-cv', upload.single('file'), async (req, res) => {
  try {
    if (!req.file) return res.status(400).json({ success: false, message: 'No file uploaded.' });

    const localPath = path.join(uploadDir, req.file.filename);
    let cloudResult = null;
    try {
      cloudResult = await cloudinary.uploader.upload(localPath, {
        resource_type: 'auto',
        folder: `jobfit/uploads/${req.session.user?.id || 'anonymous'}`,
      });
    } catch (e) {
      console.warn('cloud upload failed', e?.message || e);
    }

    if (req.session.user) {
      const db = readDb();
      db.saved = db.saved || [];
      db.saved.push({
        id: `saved_${Date.now()}`,
        userId: req.session.user.id,
        originalName: req.file.originalname,
        localPath: `/uploads/${req.file.filename}`,
        cloudUrl: cloudResult?.secure_url || null,
        uploadedAt: new Date().toISOString(),
      });
      writeDb(db);
    }

    res.json({ success: true, filename: req.file.filename, filePath: `/uploads/${req.file.filename}`, cloudUrl: cloudResult?.secure_url || null });
  } catch (err) {
    console.error('upload-cv error', err);
    res.status(500).json({ success: false, message: 'Upload failed', error: String(err) });
  }
});

// --- Optimize CV (AI) -> preview HTML + generate PDF -> upload to Cloudinary -> save optimization record ---
app.post('/optimize-cv', upload.none(), async (req, res) => {
  try {
    const { filePath, jobURL } = req.body || {};
    if (!filePath) return res.status(400).json({ success: false, message: 'filePath required.' });

    const abs = path.join(__dirname, filePath);
    if (!fs.existsSync(abs)) return res.status(400).json({ success: false, message: 'Uploaded file not found.' });

    const originalText = await extractTextFromFile(abs);
    const jobText = await fetchJobPostingText(jobURL || '');

    // prompts
    const systemPrompt = `You are an expert resume writer and career coach. Do NOT add sections like "Quick tips", "Extracted keywords", or any footer. Focus on ATS optimization and human readability.`;
    const userPrompt = `
I want the resume to pass ATS filters and still read well to human recruiters.
Rewrite or restructure work history to align with core skills and qualifications.
Include a technical skills and tools section extracted from the job description.
Write a Career Objective/Professional Summary that:
- is max 4 lines,
- captivating, human-readable,
- tailored to the job description,
- single paragraph.
Job posting excerpt:
${jobText?.slice(0,4000)}
CV text:
${originalText?.slice(0,12000)}
Return only clean HTML (no explanations or extra notes).
`;

    const MODEL = process.env.GROQ_MODEL || 'llama-3.3-70b-versatile';
    let optimizedHTML = '<p>No AI output.</p>';
    try {
      const completion = await groq.chat.completions.create({
        model: MODEL,
        messages: [
          { role: 'system', content: systemPrompt },
          { role: 'user', content: userPrompt },
        ],
        temperature: 0.2,
        max_tokens: 1800,
      });
      optimizedHTML =
        completion?.choices?.[0]?.message?.content ||
        completion?.choices?.[0]?.text ||
        optimizedHTML;
    } catch (aiErr) {
      console.error('GROQ error', aiErr?.message || aiErr);
      return res.status(500).json({ success: false, message: 'AI model error', error: String(aiErr) });
    }

    optimizedHTML = removeAiExtraSections(optimizedHTML);
    const looksLikeHtml = /<\/?[a-z][\s\S]*>/i.test(optimizedHTML);
    const previewSnippet = looksLikeHtml ? optimizedHTML : `<div><pre>${escapeHtml(optimizedHTML)}</pre></div>`;

    // wrap in simple HTML for preview and PDF rendering
    const fullHtml = `
<!doctype html>
<html>
<head>
<meta charset="utf-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1"/>
<style>
body{font-family:Inter,system-ui,-apple-system,"Helvetica Neue",Arial;color:#111;padding:24px;background:#fff;}
.resume{max-width:900px;margin:0 auto;background:#fff;border-radius:8px;box-shadow:0 8px 30px rgba(0,0,0,0.08);overflow:hidden;}
.content{padding:22px}
h2{color:#0b74da;margin-top:0;font-size:15px}
ul{margin:6px 0 12px 18px}
pre{white-space:pre-wrap;word-break:break-word}
</style>
</head>
<body>
  <div class="resume"><div class="content">${previewSnippet}</div></div>
</body>
</html>`.trim();

    const previewFile = `preview-${Date.now()}.html`;
    const previewPath = path.join(generatedDir, previewFile);
    fs.writeFileSync(previewPath, fullHtml, 'utf8');

    // generate PDF
    const pdfFile = `optimized-${Date.now()}.pdf`;
    const pdfPath = path.join(generatedDir, pdfFile);
    const browser = await puppeteer.launch({ args: ['--no-sandbox', '--disable-setuid-sandbox'] });
    const page = await browser.newPage();
    await page.setContent(fullHtml, { waitUntil: 'networkidle0' });
    await page.pdf({ path: pdfPath, format: 'A4', printBackground: true, margin: { top: '18mm', bottom: '18mm' } });
    await browser.close();

    // upload PDF to Cloudinary
    let cloudPdf = null;
    try {
      cloudPdf = await cloudinary.uploader.upload(pdfPath, {
        resource_type: 'auto',
        folder: `jobfit/optimized/${req.session.user?.id || 'anonymous'}`,
        use_filename: true,
        unique_filename: true,
      });
    } catch (e) {
      console.warn('cloud upload pdf failed', e?.message || e);
    }

    // persist optimization record
    if (req.session.user) {
      const db = readDb();
      db.optimizations = db.optimizations || [];
      db.optimizations.push({
        id: `opt_${Date.now()}`,
        userId: req.session.user.id,
        previewLocal: `/generated/${previewFile}`,
        pdfLocal: `/generated/${pdfFile}`,
        pdfUrl: cloudPdf?.secure_url || null,
        jobURL: jobURL || null,
        createdAt: new Date().toISOString(),
      });
      writeDb(db);
    }

    const optimizedText = stripHtmlToText(previewSnippet).slice(0, 20000);

    return res.json({
      success: true,
      previewHTML: previewSnippet,
      previewUrl: `/generated/${previewFile}`,
      downloadUrl: cloudPdf?.secure_url || `/generated/${pdfFile}`,
      pdfFilename: pdfFile,
      optimizedText,
    });
  } catch (err) {
    console.error('optimize-cv error', err);
    return res.status(500).json({ success: false, message: 'Optimization failed.', error: String(err) });
  }
});

// --- Send email with PDF (prefers cloud URL if present) ---
app.post('/send-email', bodyParser.json(), async (req, res) => {
  try {
    const { pdfFilename } = req.body || {};
    if (!pdfFilename) return res.status(400).json({ success: false, message: 'pdfFilename required' });

    const db = readDb();
    const userId = req.session.user?.id;
    const opt = (db.optimizations || []).find(o => o.userId === userId && (o.pdfLocal?.endsWith(pdfFilename) || o.pdfLocal === `/generated/${pdfFilename}`));

    // local path fallback
    const pdfPathLocal = path.join(generatedDir, pdfFilename);

    if (!fs.existsSync(pdfPathLocal) && !opt?.pdfUrl) {
      return res.status(404).json({ success: false, message: 'File not found' });
    }

    const userEmail = req.session.user?.email;
    if (!userEmail) return res.status(400).json({ success: false, message: 'No logged-in user to email to' });

    const transporter = await createTransporter();
    if (!transporter) return res.status(500).json({ success: false, message: 'Email not configured on server' });

    const attachments = [];
    if (opt?.pdfUrl) attachments.push({ filename: pdfFilename, path: opt.pdfUrl });
    else attachments.push({ filename: pdfFilename, path: pdfPathLocal });

    await transporter.sendMail({
      from: process.env.MAIL_FROM || process.env.MAIL_USER,
      to: userEmail,
      subject: 'Your Optimized CV from Job-Fit',
      text: 'Attached is the optimized CV generated by Job-Fit. Good luck with your application!',
      attachments,
    });

    res.json({ success: true, message: 'Email sent' });
  } catch (err) {
    console.error('send-email error', err);
    res.status(500).json({ success: false, message: 'Failed to send email', error: String(err) });
  }
});

/********************************
 * Stripe: Create Checkout Session
 ********************************/
app.post('/create-checkout-session', bodyParser.json(), async (req, res) => {
  try {
    const { email, metadata } = req.body || {};
    const user = req.session.user;
    const PRICE_ID = process.env.STRIPE_PRICE_ID || 'price_test_placeholder';
    const DOMAIN = process.env.DOMAIN || `http://localhost:${process.env.PORT || 4242}`;

    const sessionObj = {
      mode: 'subscription',
      payment_method_types: ['card'],
      line_items: [{ price: PRICE_ID, quantity: 1 }],
      success_url: `${DOMAIN}/dashboard.html?checkout=success&session_id={CHECKOUT_SESSION_ID}`,
      cancel_url: `${DOMAIN}/dashboard.html?checkout=cancel`,
      subscription_data: {
        metadata: {
          ... (metadata || {}),
          userId: user?.id || 'anonymous',
          email: email || user?.email || null,
        }
      },
      customer_email: email || user?.email || undefined,
    };

    const checkoutSession = await stripe.checkout.sessions.create(sessionObj);

    // persist pending payment
    try {
      const db = readDb();
      db.payments = db.payments || [];
      db.payments.push({
        id: `pending_${Date.now()}`,
        userId: user?.id || null,
        email: email || user?.email || null,
        checkoutSessionId: checkoutSession.id,
        status: 'created',
        createdAt: new Date().toISOString(),
      });
      writeDb(db);
    } catch (e) {
      console.warn('failed to write pending payment', e);
    }

    res.json({ url: checkoutSession.url });
  } catch (err) {
    console.error('create-checkout-session error', err);
    res.status(500).json({ message: err.message || 'Stripe error' });
  }
});

/********************************
 * Stripe Webhook (raw body)
 ********************************/
app.post('/webhook', bodyParser.raw({ type: 'application/json' }), (req, res) => {
  const sig = req.headers['stripe-signature'];
  const webhookSecret = process.env.STRIPE_WEBHOOK_SECRET || '';
  let event;

  try {
    if (webhookSecret) {
      event = stripe.webhooks.constructEvent(req.body, sig, webhookSecret);
    } else {
      // DEV mode: parse without verification (not recommended in production)
      event = JSON.parse(req.body.toString('utf8'));
    }
  } catch (err) {
    console.error('Webhook verification failed:', err.message);
    return res.status(400).send(`Webhook Error: ${err.message}`);
  }

  (async () => {
    try {
      const db = readDb();
      db.payments = db.payments || [];
      db.subscriptions = db.subscriptions || [];

      switch (event.type) {
        case 'checkout.session.completed': {
          const session = event.data.object;
          const meta = session.metadata || {};
          db.payments.push({
            id: `pay_${Date.now()}`,
            userId: meta.userId || null,
            checkoutSessionId: session.id,
            customer: session.customer || null,
            payment_status: session.payment_status || null,
            mode: session.mode || null,
            status: 'completed',
            raw: session,
            createdAt: new Date().toISOString(),
          });
          writeDb(db);
          console.log('Recorded checkout.session.completed', session.id);
          break;
        }

        case 'invoice.paid': {
          const invoice = event.data.object;
          const subId = invoice.subscription;
          const userId = invoice.customer || null;
          db.subscriptions.push({
            id: subId || `sub_${Date.now()}`,
            userId,
            status: 'active',
            raw: invoice,
            updatedAt: new Date().toISOString(),
          });
          writeDb(db);
          console.log('Recorded invoice.paid', subId);
          break;
        }

        case 'customer.subscription.updated':
        case 'customer.subscription.created': {
          const sub = event.data.object;
          const metadata = sub.metadata || {};
          const userId = metadata.userId || sub.customer || null;
          const existing = (db.subscriptions || []).findIndex(s => s.id === sub.id);
          const rec = {
            id: sub.id,
            userId,
            status: sub.status,
            raw: sub,
            updatedAt: new Date().toISOString(),
          };
          if (existing >= 0) db.subscriptions[existing] = rec;
          else db.subscriptions.push(rec);
          writeDb(db);
          console.log('Upserted subscription', sub.id);
          break;
        }

        case 'invoice.payment_failed': {
          const invoice = event.data.object;
          const subId = invoice.subscription;
          const idx = (db.subscriptions || []).findIndex(s => s.id === subId);
          if (idx >= 0) {
            db.subscriptions[idx].status = 'past_due';
            db.subscriptions[idx].updatedAt = new Date().toISOString();
          }
          db.payments.push({
            id: `failed_${Date.now()}`,
            checkoutSessionId: invoice.checkout_session || null,
            userId: invoice.customer || null,
            status: 'failed',
            raw: invoice,
            createdAt: new Date().toISOString(),
          });
          writeDb(db);
          console.log('invoice.payment_failed recorded', subId);
          break;
        }

        default:
          console.log('Unhandled event type', event.type);
      }
    } catch (e) {
      console.error('Error processing webhook event', e);
    }
  })();

  res.json({ received: true });
});

/***********************
 * Dashboard API routes *
 ***********************/

// Saved CVs (per-user)
app.get('/api/saved-cvs', (req, res) => {
  if (!req.session.user) return res.status(401).json([]);
  const db = readDb();
  const files = (db.saved || []).filter(f => f.userId === req.session.user.id).map(f => ({ ...f }));
  res.json(files);
});

// Past optimizations (per-user)
app.get('/api/past-optimizations', (req, res) => {
  if (!req.session.user) return res.status(401).json([]);
  const db = readDb();
  const files = (db.optimizations || []).filter(f => f.userId === req.session.user.id).map(f => ({ ...f }));
  res.json(files);
});

// Subscription status
app.get('/api/subscription-status', (req, res) => {
  if (!req.session.user) return res.status(401).json({ active: false });
  try {
    const db = readDb();
    const subs = (db.subscriptions || []).filter(s => s.userId === req.session.user.id);
    const active = subs.some(s => ['active', 'trialing'].includes((s.status || '').toLowerCase()));
    res.json({ active, subscriptions: subs });
  } catch (e) {
    console.error('subscription-status error', e);
    res.json({ active: false });
  }
});

// Save profile updates
app.post('/api/profile', bodyParser.json(), (req, res) => {
  if (!req.session.user) return res.status(401).json({ success: false, message: 'Not logged in' });
  try {
    const db = readDb();
    db.users = db.users || {};
    const id = req.session.user.id;
    db.users[id] = db.users[id] || {};
    db.users[id].name = req.body.name || req.session.user.name;
    db.users[id].email = req.body.email || req.session.user.email;
    writeDb(db);
    req.session.user.name = db.users[id].name;
    req.session.user.email = db.users[id].email;
    res.json({ success: true, user: req.session.user });
  } catch (e) {
    console.error('profile update error', e);
    res.status(500).json({ success: false, message: 'Failed to update profile' });
  }
});

// download (serves local files)
app.get('/download', (req, res) => {
  const file = req.query.file;
  if (!file) return res.send('No file specified.');
  const abs = path.join(generatedDir, path.basename(file));
  if (!fs.existsSync(abs)) return res.send('File missing.');
  res.download(abs);
});

// start server
const PORT = process.env.PORT || 4242;
app.listen(PORT, () => console.log(`🚀 Running ${process.env.DOMAIN || `http://localhost:${PORT}`}`));
