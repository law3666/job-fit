/**
 * server.js — Complete, improved and fixed
 *
 * Features:
 * - Google OAuth
 * - Groq AI (groq-sdk)
 * - Cloudinary uploads
 * - Stripe Checkout + Webhook
 * - Puppeteer-core + @sparticuz/chromium (small footprint)
 * - JSON file DB (data/db.json)
 * - Proper error handling and logging
 * - Fixed dashboard data issues (store filename & ISO dates)
 * - Static routes for uploads & generated files and a direct download route
 *
 * Required environment variables (recommended):
 * - CLOUDINARY_CLOUD_NAME, CLOUDINARY_API_KEY, CLOUDINARY_API_SECRET
 * - STRIPE_SECRET_KEY, STRIPE_PRICE_ID, STRIPE_WEBHOOK_SECRET
 * - GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET
 * - GROQ_API_KEY
 * - SESSION_SECRET
 * - DOMAIN (e.g. https://your-app.example.com)
 *
 * Notes:
 * - This file assumes @sparticuz/chromium + puppeteer-core are installed.
 * - In production, replace the in-memory session with Redis or another store.
 */

require('dotenv').config();

const express = require('express');
const bodyParser = require('body-parser');
const app = express();
const path = require('path');
const fs = require('fs');
const multer = require('multer');
const session = require('express-session');
const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const cloudinary = require('cloudinary').v2;
const puppeteer = require('puppeteer-core');
const chromium = require('@sparticuz/chromium');
const pdfParse = require('pdf-parse');
const mammoth = require('mammoth');
const Stripe = require('stripe');
const Groq = require('groq-sdk');

// ---------- Config & dependencies ----------
const stripe = Stripe(process.env.STRIPE_SECRET_KEY || 'sk_test_PLACEHOLDER');
const groq = new Groq({ apiKey: process.env.GROQ_API_KEY || '' });
const fetch = (...args) => import('node-fetch').then(({ default: fetch }) => fetch(...args));

// ---------- Paths & data ----------
const publicPath = path.join(__dirname, 'public');
const uploadDir = path.join(__dirname, 'uploads');
const generatedDir = path.join(__dirname, 'generated');
const dataDir = path.join(__dirname, 'data');
const dbPath = path.join(dataDir, 'db.json');

// ensure directories
for (const d of [uploadDir, generatedDir, dataDir]) {
  if (!fs.existsSync(d)) fs.mkdirSync(d, { recursive: true });
}

// ---------- Simple JSON DB helpers ----------
function ensureDb() {
  if (!fs.existsSync(dbPath)) {
    fs.writeFileSync(
      dbPath,
      JSON.stringify({ users: {}, saved: [], optimizations: [], payments: [], subscriptions: [] }, null, 2)
    );
  }
}
function readDb() {
  ensureDb();
  try {
    return JSON.parse(fs.readFileSync(dbPath, 'utf8'));
  } catch (e) {
    console.error('readDb parse error', e);
    return { users: {}, saved: [], optimizations: [], payments: [], subscriptions: [] };
  }
}
function writeDb(obj) {
  try {
    fs.writeFileSync(dbPath, JSON.stringify(obj, null, 2), 'utf8');
  } catch (e) {
    console.error('writeDb error', e);
  }
}

// ---------- Cloudinary ----------
cloudinary.config({
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME || '',
  api_key: process.env.CLOUDINARY_API_KEY || '',
  api_secret: process.env.CLOUDINARY_API_SECRET || '',
});

// ---------- Middleware ----------
app.use((req, res, next) => {
  // webhook raw body exception handled at route, otherwise parse JSON normally
  if (req.originalUrl === '/webhook') return next();
  bodyParser.json({ limit: '10mb' })(req, res, next);
});
app.use(bodyParser.urlencoded({ extended: true }));

if (!process.env.SESSION_STORE) {
  console.warn('Warning: connect.session() MemoryStore is not designed for production. Consider adding SESSION_STORE (e.g. Redis).');
}
app.use(
  session({
    secret: process.env.SESSION_SECRET || 'dev_secret',
    resave: false,
    saveUninitialized: false,
    cookie: { maxAge: 24 * 60 * 60 * 1000 },
  })
);

// ---------- Passport (Google OAuth) ----------
app.use(passport.initialize());
app.use(passport.session());

passport.use(
  new GoogleStrategy(
    {
      clientID: process.env.GOOGLE_CLIENT_ID || '',
      clientSecret: process.env.GOOGLE_CLIENT_SECRET || '',
      callbackURL: `${process.env.DOMAIN || ''}/auth/google/callback`,
    },
    (accessToken, refreshToken, profile, done) => {
      done(null, {
        id: profile.id,
        name: profile.displayName,
        email: profile.emails?.[0]?.value,
        photo: profile.photos?.[0]?.value,
      });
    }
  )
);
passport.serializeUser((user, done) => done(null, user));
passport.deserializeUser((obj, done) => done(null, obj));

// ---------- Static & upload ----------
app.use(express.static(publicPath));
app.use('/uploads', express.static(uploadDir));
app.use('/generated', express.static(generatedDir));

const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, uploadDir),
  filename: (req, file, cb) => {
    const safe = file.originalname.replace(/\s+/g, '_').replace(/[^a-zA-Z0-9._-]/g, '');
    cb(null, `${Date.now()}-${safe}`);
  },
});
const upload = multer({ storage });

// ---------- Utility helpers ----------
const escapeHtml = (str) => String(str).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
const stripHtmlToText = (html) => (html ? String(html).replace(/<\/?[^>]+(>|$)/g, ' ').replace(/\s{2,}/g, ' ').trim() : '');
const removeAiExtraSections = (html) =>
  html
    ? html
        .replace(/<h2>Quick tips<\/h2>[\s\S]*?(?=<h2|<\/div>)/gi, '')
        .replace(/<h2>Extracted keywords<\/h2>[\s\S]*?(?=<h2|<\/div>)/gi, '')
        .replace(/Generated by Job-Fit — optimized using AI/gi, '')
        .replace(/\s{2,}/g, ' ')
        .trim()
    : '';

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
    console.warn('extractTextFromFile error', err?.message || err);
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
    console.warn('fetchJobPostingText error', err?.message || err);
    return '';
  }
}

// ---------- Puppeteer launch using sparticuz/chromium ----------
async function launchBrowser(launchOptions = {}) {
  const args = [...(chromium.args || []), '--no-sandbox', '--disable-setuid-sandbox', '--disable-dev-shm-usage', ...(launchOptions.args || [])];
  const executablePath = await chromium.executablePath();
  const opts = {
    args,
    defaultViewport: chromium.defaultViewport,
    executablePath,
    headless: chromium.headless,
    ...launchOptions,
  };
  return await puppeteer.launch(opts);
}

// ---------- Routes ----------

// Home + Auth
app.get('/', (req, res) => res.sendFile(path.join(publicPath, 'index.html')));
app.get('/auth/google', passport.authenticate('google', { scope: ['profile', 'email'] }));
app.get(
  '/auth/google/callback',
  passport.authenticate('google', { failureRedirect: '/' }),
  (req, res) => {
    req.session.user = req.user;
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
  // passport logout signature changed in newer versions, support both
  if (typeof req.logout === 'function') {
    req.logout(() => {});
  } else {
    req.session.destroy();
  }
  req.session.destroy(() => res.redirect('/'));
});
app.get('/api/user', (req, res) => {
  if (req.session.user) return res.json({ loggedIn: true, user: req.session.user });
  return res.json({ loggedIn: false });
});

// Upload CV (store uploaded file info in DB - fixed so dashboard has filename & date)
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

    // Persist information with consistent keys that dashboard expects
    if (req.session.user) {
      try {
        const db = readDb();
        db.saved = db.saved || [];
        db.saved.push({
          id: `saved_${Date.now()}`,
          userId: req.session.user.id,
          originalName: req.file.originalname,
          filename: req.file.filename, // <-- important for dashboard
          localPath: `/uploads/${req.file.filename}`,
          cloudUrl: cloudResult?.secure_url || null,
          uploadedAt: new Date().toISOString(), // ISO date string
        });
        writeDb(db);
      } catch (e) {
        console.warn('failed to write saved CV to DB', e);
      }
    }

    res.json({
      success: true,
      filename: req.file.filename,
      filePath: `/uploads/${req.file.filename}`,
      cloudUrl: cloudResult?.secure_url || null,
    });
  } catch (err) {
    console.error('upload-cv error', err);
    res.status(500).json({ success: false, message: 'Upload failed', error: String(err) });
  }
});

// Optimize CV (AI) -> HTML -> PDF -> Cloud and save optimization metadata (fixed: store filename and ISO date)
app.post('/optimize-cv', upload.none(), async (req, res) => {
  let browser = null;
  try {
    const { filePath, jobURL } = req.body || {};
    if (!filePath) return res.status(400).json({ success: false, message: 'filePath required.' });

    const abs = path.join(__dirname, filePath);
    if (!fs.existsSync(abs)) return res.status(400).json({ success: false, message: 'Uploaded file not found.' });

    const originalText = await extractTextFromFile(abs);
    const jobText = await fetchJobPostingText(jobURL || '');
    const systemPrompt =
      'You are an expert resume writer and career coach. Create a modern, ATS-friendly resume that reads naturally to human recruiters. Use clear section headings, no images, no tables, and standard web-safe fonts. Tailor all content to the job description, emphasizing impact, results, and transferable skills with action verbs and quantifiable outcomes. Do NOT add extra sections like “Tips” or “Keywords.” Return only clean HTML.';
    const userPrompt = `I want the resume to pass ATS filters and still read well to recruiters. Rewrite my work history to match the core skills and qualifications in the job description. Include role-specific technical skills/tools mentioned in the posting. Write a powerful 3-line professional summary that hooks a recruiter in under 10 seconds. Prioritize impact, clarity, and value. Job posting: ${jobText?.slice(0, 4000)} My current CV: ${originalText?.slice(0, 12000)} Return only clean HTML.`;

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
      optimizedHTML = completion?.choices?.[0]?.message?.content || completion?.choices?.[0]?.text || optimizedHTML;
    } catch (aiErr) {
      console.error('GROQ error', aiErr?.message || aiErr);
      return res.status(500).json({ success: false, message: 'AI model error', error: String(aiErr) });
    }

    optimizedHTML = removeAiExtraSections(optimizedHTML);
    const previewSnippet = /<\/?[a-z][\s\S]*>/i.test(optimizedHTML)
      ? optimizedHTML
      : `<div><pre>${escapeHtml(optimizedHTML)}</pre></div>`;

    const fullHtml = `<!doctype html><html><head><meta charset="utf-8"/><meta name="viewport" content="width=device-width,initial-scale=1"/><style>body{font-family:Inter,system-ui,-apple-system,"Helvetica Neue",Arial;color:#111;padding:24px;background:#fff}.resume{max-width:900px;margin:0 auto;background:#fff;border-radius:8px;box-shadow:0 8px 30px rgba(0,0,0,0.08);overflow:hidden}.content{padding:22px}h2{color:#0b74da;margin-top:0;font-size:15px}ul{margin:6px 0 12px 18px}pre{white-space:pre-wrap;word-break:break-word}</style></head><body><div class="resume"><div class="content">${previewSnippet}</div></div></body></html>`.trim();

    const previewFile = `preview-${Date.now()}.html`;
    const previewPath = path.join(generatedDir, previewFile);
    fs.writeFileSync(previewPath, fullHtml, 'utf8');

    const pdfFile = `optimized-${Date.now()}.pdf`;
    const pdfPath = path.join(generatedDir, pdfFile);

    // Launch browser and create PDF
    try {
      browser = await launchBrowser({});
      const page = await browser.newPage();
      await page.setContent(fullHtml, { waitUntil: 'networkidle0' });
      await page.pdf({ path: pdfPath, format: 'A4', printBackground: true, margin: { top: '18mm', bottom: '18mm' } });
      await page.close();
    } catch (puppErr) {
      console.error('Puppeteer generation failed:', puppErr?.message || puppErr);
      const optimizedText = stripHtmlToText(previewSnippet).slice(0, 20000);
      return res.json({
        success: true,
        previewHTML: previewSnippet,
        previewUrl: `/generated/${previewFile}`,
        downloadUrl: null,
        pdfFilename: null,
        optimizedText,
        warning: 'PDF generation failed (Puppeteer). Preview available, but PDF was not created. See server logs.',
        error: String(puppErr),
      });
    } finally {
      if (browser) {
        try {
          await browser.close();
        } catch (e) {
          // ignore
        }
      }
    }

    // upload pdf to cloudinary (optional)
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

    // Save optimization metadata to DB with consistent keys the dashboard expects
    if (req.session.user) {
      try {
        const db = readDb();
        db.optimizations = db.optimizations || [];
        db.optimizations.push({
          id: `opt_${Date.now()}`,
          userId: req.session.user.id,
          filename: pdfFile, // important for dashboard /download links
          previewLocal: `/generated/${previewFile}`,
          pdfLocal: `/generated/${pdfFile}`,
          pdfUrl: cloudPdf?.secure_url || null,
          jobURL: jobURL || null,
          createdAt: new Date().toISOString(),
        });
        writeDb(db);
      } catch (e) {
        console.warn('failed to write optimization record', e);
      }
    }

    const optimizedText = stripHtmlToText(previewSnippet).slice(0, 20000);
    res.json({
      success: true,
      previewHTML: previewSnippet,
      previewUrl: `/generated/${previewFile}`,
      downloadUrl: cloudPdf?.secure_url || `/generated/${pdfFile}`,
      pdfFilename: pdfFile,
      optimizedText,
    });
  } catch (err) {
    console.error('optimize-cv error', err);
    if (browser) {
      try {
        await browser.close();
      } catch (e) {
        // ignore
      }
    }
    res.status(500).json({ success: false, message: 'Optimization failed.', error: String(err) });
  }
});

// ---------- Stripe Checkout & Webhook (robust) ----------
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
      subscription_data: { metadata: { ...(metadata || {}), userId: user?.id || 'anonymous', email: email || user?.email || null } },
      customer_email: email || user?.email || undefined,
    };

    const checkoutSession = await stripe.checkout.sessions.create(sessionObj);

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

app.post('/webhook', bodyParser.raw({ type: 'application/json' }), (req, res) => {
  const sig = req.headers['stripe-signature'];
  const webhookSecret = process.env.STRIPE_WEBHOOK_SECRET || '';

  let event;
  try {
    if (webhookSecret) {
      event = stripe.webhooks.constructEvent(req.body, sig, webhookSecret);
    } else {
      // If webhook secret not set (dev), parse raw body
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
          db.subscriptions.push({
            id: subId || `sub_${Date.now()}`,
            userId: invoice.customer || null,
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
          const existing = (db.subscriptions || []).findIndex((s) => s.id === sub.id);
          const rec = { id: sub.id, userId, status: sub.status, raw: sub, updatedAt: new Date().toISOString() };
          if (existing >= 0) db.subscriptions[existing] = rec;
          else db.subscriptions.push(rec);
          writeDb(db);
          console.log('Upserted subscription', sub.id);
          break;
        }

        case 'invoice.payment_failed': {
          const invoice = event.data.object;
          const subId = invoice.subscription;
          const idx = (db.subscriptions || []).findIndex((s) => s.id === subId);
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

// ---------- Dashboard APIs (saved CVs, optimizations, subscription status) ----------
app.get('/api/saved-cvs', (req, res) => {
  if (!req.session.user) return res.status(401).json([]);
  try {
    const db = readDb();
    const rows = (db.saved || []).filter((f) => f.userId === req.session.user.id).map((f) => ({
      id: f.id,
      originalName: f.originalName,
      filename: f.filename, // dashboard expects filename
      localPath: f.localPath,
      cloudUrl: f.cloudUrl || null,
      uploadedAt: f.uploadedAt || null,
    }));
    res.json(rows);
  } catch (e) {
    console.error('saved-cvs error', e);
    res.status(500).json([]);
  }
});

app.get('/api/past-optimizations', (req, res) => {
  if (!req.session.user) return res.status(401).json([]);
  try {
    const db = readDb();
    const rows = (db.optimizations || []).filter((f) => f.userId === req.session.user.id).map((f) => ({
      id: f.id,
      filename: f.filename,
      previewLocal: f.previewLocal,
      pdfLocal: f.pdfLocal,
      pdfUrl: f.pdfUrl || null,
      jobURL: f.jobURL || null,
      createdAt: f.createdAt || null,
    }));
    res.json(rows);
  } catch (e) {
    console.error('past-optimizations error', e);
    res.status(500).json([]);
  }
});

app.get('/api/subscription-status', (req, res) => {
  if (!req.session.user) return res.status(401).json({ active: false });
  try {
    const db = readDb();
    const subs = (db.subscriptions || []).filter((s) => s.userId === req.session.user.id);
    const active = subs.some((s) => ['active', 'trialing'].includes((s.status || '').toLowerCase()));
    res.json({ active, subscriptions: subs });
  } catch (e) {
    console.error('subscription-status error', e);
    res.json({ active: false });
  }
});

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

// ---------- Download route (explicit, safer) ----------
app.get('/generated/:filename', (req, res) => {
  try {
    const filename = path.basename(req.params.filename || '');
    if (!filename) return res.status(400).send('No filename provided');
    const abs = path.join(generatedDir, filename);
    if (!fs.existsSync(abs)) return res.status(404).send('File not found');
    res.download(abs);
  } catch (e) {
    console.error('generated download error', e);
    res.status(500).send('Download error');
  }
});

// Old query-based download route (kept for backwards compatibility)
app.get('/download', (req, res) => {
  const file = req.query.file;
  if (!file) return res.send('No file specified.');
  const abs = path.join(generatedDir, path.basename(file));
  if (!fs.existsSync(abs)) return res.send('File missing.');
  res.download(abs);
});

// ---------- Start server ----------
const PORT = process.env.PORT || 4242;
app.listen(PORT, () => {
  console.log(`🚀 Running ${process.env.DOMAIN || `http://localhost:${PORT}`}`);
});
