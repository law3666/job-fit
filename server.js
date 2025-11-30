/******************************************************************
 * server.js — Updated: GROQ-based optimization + PDF styling + email + user dashboard + Cloudinary
 * - Cloudinary integration
 * - JSON metadata DB (data/db.json)
 * - Per-user saved CVs & past optimizations
 * - Upload generated PDFs to Cloudinary and save metadata
 ******************************************************************/
require('dotenv').config();
const express = require('express');
const app = express();
const stripe = require('stripe')(process.env.STRIPE_SECRET_KEY || '');
const path = require('path');
const multer = require('multer');
const fs = require('fs');
const session = require('express-session');
const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const nodemailer = require('nodemailer');
const cloudinary = require('cloudinary').v2;

// Node 18+ global fetch exists, but keep fallback
const fetch = (...args) => import('node-fetch').then(({ default: fetch }) => fetch(...args));

// GROQ (AI)
const Groq = require('groq-sdk');
const groq = new Groq({ apiKey: process.env.GROQ_API_KEY || '' });

// Extraction libs
const pdfParse = require('pdf-parse');
const mammoth = require('mammoth');
const puppeteer = require('puppeteer');

// configure Cloudinary from env
cloudinary.config({
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME || '',
  api_key: process.env.CLOUDINARY_API_KEY || '',
  api_secret: process.env.CLOUDINARY_API_SECRET || '',
});

// middleware
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true }));

// sessions
app.use(
  session({
    secret: process.env.SESSION_SECRET || 'mysecret',
    resave: false,
    saveUninitialized: false,
    cookie: { maxAge: 1000 * 60 * 60 * 24 },
  })
);

// passport (google)
app.use(passport.initialize());
app.use(passport.session());

passport.use(
  new GoogleStrategy(
    {
      clientID: process.env.GOOGLE_CLIENT_ID,
      clientSecret: process.env.GOOGLE_CLIENT_SECRET,
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

// folders
const publicPath = path.join(__dirname, 'public');
const uploadDir = path.join(__dirname, 'uploads');
const generatedDir = path.join(__dirname, 'generated');
const dataDir = path.join(__dirname, 'data');
const dbPath = path.join(dataDir, 'db.json');

// ensure directories
for (const d of [uploadDir, generatedDir, dataDir]) {
  if (!fs.existsSync(d)) fs.mkdirSync(d, { recursive: true });
}

// init simple db file if missing
function ensureDb() {
  if (!fs.existsSync(dbPath)) {
    const initial = { users: {}, saved: [], optimizations: [] };
    fs.writeFileSync(dbPath, JSON.stringify(initial, null, 2), 'utf8');
  }
}
ensureDb();

// simple db helpers (file-backed JSON)
function readDb() {
  try {
    ensureDb();
    return JSON.parse(fs.readFileSync(dbPath, 'utf8'));
  } catch (e) {
    console.error('readDb error', e);
    return { users: {}, saved: [], optimizations: [] };
  }
}
function writeDb(obj) {
  fs.writeFileSync(dbPath, JSON.stringify(obj, null, 2), 'utf8');
}

// static
app.use(express.static(publicPath));
app.use('/uploads', express.static(uploadDir));
app.use('/generated', express.static(generatedDir));

// multer for uploads (keeps a local copy before optionally pushing to Cloudinary)
const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, uploadDir),
  filename: (req, file, cb) => {
    const safe = file.originalname.replace(/\s+/g, '_').replace(/[^a-zA-Z0-9._-]/g, '');
    cb(null, `${Date.now()}-${safe}`);
  },
});
const upload = multer({ storage });

// --- Routes: home + auth ---
app.get('/', (req, res) => res.sendFile(path.join(publicPath, 'index.html')));
app.get('/auth/google', passport.authenticate('google', { scope: ['profile', 'email'] }));
app.get(
  '/auth/google/callback',
  passport.authenticate('google', { failureRedirect: '/' }),
  (req, res) => {
    req.session.user = req.user;
    res.redirect('/dashboard.html');
  }
);
app.get('/logout', (req, res) => {
  req.logout(() => req.session.destroy(() => res.redirect('/')));
});
app.get('/api/user', (req, res) => {
  if (req.session.user) return res.json({ loggedIn: true, user: req.session.user });
  return res.json({ loggedIn: false });
});

// === Upload endpoint (file only) ===
// Upload original CV — store locally and upload to Cloudinary for persistence.
// Returns filePath (local) and cloudinary URL
app.post('/upload-cv', upload.single('file'), async (req, res) => {
  try {
    if (!req.file) return res.status(400).json({ success: false, message: 'No file uploaded.' });

    const localPath = path.join(uploadDir, req.file.filename);

    // upload to Cloudinary (resource_type auto to allow pdf/docx)
    let cloudResult = null;
    try {
      cloudResult = await cloudinary.uploader.upload(localPath, {
        resource_type: 'auto',
        folder: `jobfit/uploads/${req.session.user?.id || 'anonymous'}`,
      });
    } catch (e) {
      console.warn('Cloudinary upload failed (continuing with local file):', e?.message || e);
    }

    // save a lightweight saved-cv record in DB if user logged in
    if (req.session.user) {
      const db = readDb();
      const rec = {
        id: `saved_${Date.now()}`,
        userId: req.session.user.id,
        originalName: req.file.originalname,
        localPath: `/uploads/${req.file.filename}`,
        cloudUrl: cloudResult?.secure_url || null,
        uploadedAt: new Date().toISOString(),
      };
      db.saved = db.saved || [];
      db.saved.push(rec);
      writeDb(db);
    }

    return res.json({
      success: true,
      filename: req.file.filename,
      filePath: `/uploads/${req.file.filename}`,
      cloudUrl: cloudResult?.secure_url || null,
    });
  } catch (err) {
    console.error('upload-cv error', err);
    return res.status(500).json({ success: false, message: 'Upload failed', error: String(err) });
  }
});

// === Helpers: file text extraction, job fetching, utils ===
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
    const cleaned = html.replace(/<script[\s\S]*?>[\s\S]*?<\/script>/gi, '')
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

function stripHtmlToText(html) {
  if (!html) return '';
  return String(html).replace(/<\/?[^>]+(>|$)/g, ' ').replace(/\s{2,}/g, ' ').trim();
}

function escapeHtml(str) {
  return String(str).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
}

async function createTransporter() {
  if (!process.env.MAIL_HOST) return null;
  return nodemailer.createTransport({
    host: process.env.MAIL_HOST,
    port: Number(process.env.MAIL_PORT || 587),
    secure: process.env.MAIL_SECURE === 'true',
    auth: {
      user: process.env.MAIL_USER,
      pass: process.env.MAIL_PASS,
    },
  });
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

// === Optimize CV route (core) ===
// This generates the optimized CV HTML, writes a preview and PDF locally, uploads the PDF to Cloudinary,
// then saves an optimization record to data/db.json associated with the logged-in user.
app.post('/optimize-cv', express.json(), async (req, res) => {
  try {
    const { filePath, jobURL } = req.body || {};
    if (!filePath) return res.status(400).json({ success: false, message: 'filePath required.' });

    const abs = path.join(__dirname, filePath);
    if (!fs.existsSync(abs)) return res.status(400).json({ success: false, message: 'Uploaded file not found.' });

    const originalText = await extractTextFromFile(abs);
    const jobText = await fetchJobPostingText(jobURL || '');

    // prompts (as requested)
    const systemPrompt = `
You are an expert resume writer and career coach. 
Do NOT add sections like "Quick tips", "Extracted keywords", or any footer.
Focus on ATS optimization and human readability.
`;

    const userPrompt = `
I want the resume to pass ATS filters and still read well to human recruiters.
Based on this job description, optimize my resume content to include relevant keywords and phrases naturally.

Rewrite or restructure my work history to align with the core skills and qualifications they’re looking for.

Include a technical skills and tools section extracted from the job description and format it to stand out.

Write a Career Objective / Professional Summary that:
- is max 4 lines,
- is captivating, human-readable,
- tailored specifically to the job description and requirements,
- written as a single paragraph.

Job posting excerpt:
${jobText?.slice(0, 4000)}

CV text:
${originalText?.slice(0, 12000)}

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
      console.error('GROQ model error:', aiErr?.error || aiErr?.message || aiErr);
      return res.status(500).json({ success: false, message: 'AI model error', error: aiErr?.error?.message || String(aiErr) });
    }

    // clean AI added sections defensively
    optimizedHTML = removeAiExtraSections(optimizedHTML);
    const looksLikeHtml = /<\/?[a-z][\s\S]*>/i.test(optimizedHTML);
    const previewSnippet = looksLikeHtml ? optimizedHTML : `<div><pre>${escapeHtml(optimizedHTML)}</pre></div>`;

    // full HTML wrapper (clean)
    const fullHtml = `
<!doctype html>
<html>
<head>
<meta charset="utf-8" />
<meta name="viewport" content="width=device-width,initial-scale=1" />
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
<div class="resume">
<div class="content">
${previewSnippet}
</div>
</div>
</body>
</html>
`.trim();

    // save preview html locally
    const previewFile = `preview-${Date.now()}.html`;
    const previewPath = path.join(generatedDir, previewFile);
    fs.writeFileSync(previewPath, fullHtml, 'utf8');

    // generate PDF via puppeteer
    const pdfFile = `optimized-${Date.now()}.pdf`;
    const pdfPath = path.join(generatedDir, pdfFile);
    const browser = await puppeteer.launch({ args: ['--no-sandbox', '--disable-setuid-sandbox'] });
    const page = await browser.newPage();
    await page.setContent(fullHtml, { waitUntil: 'networkidle0' });
    await page.pdf({ path: pdfPath, format: 'A4', printBackground: true, margin: { top: '18mm', bottom: '18mm' } });
    await browser.close();

    // upload PDF to Cloudinary (resource_type auto)
    let cloudPdf = null;
    try {
      cloudPdf = await cloudinary.uploader.upload(pdfPath, {
        resource_type: 'auto',
        folder: `jobfit/optimized/${req.session.user?.id || 'anonymous'}`,
        use_filename: true,
        unique_filename: true,
      });
    } catch (e) {
      console.warn('Cloudinary PDF upload failed:', e?.message || e);
    }

    // save an optimization record in DB for this user
    if (req.session.user) {
      const db = readDb();
      db.optimizations = db.optimizations || [];
      const rec = {
        id: `opt_${Date.now()}`,
        userId: req.session.user.id,
        previewLocal: `/generated/${previewFile}`,
        pdfLocal: `/generated/${pdfFile}`,
        pdfUrl: cloudPdf?.secure_url || null,
        jobURL: jobURL || null,
        createdAt: new Date().toISOString(),
      };
      db.optimizations.push(rec);
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
    console.error('optimize-cv error:', err);
    return res.status(500).json({ success: false, message: 'Optimization failed.', error: String(err) });
  }
});

// === Send email with PDF ===
app.post('/send-email', express.json(), async (req, res) => {
  try {
    const { pdfFilename } = req.body || {};
    if (!pdfFilename) return res.status(400).json({ success: false, message: 'pdfFilename required' });

    // prefer cloud copy if available in DB for this user
    const db = readDb();
    const userId = req.session.user?.id;
    const opt = db.optimizations?.find(o => o.pdfLocal && o.userId === userId && o.pdfLocal.endsWith(pdfFilename));
    const pdfPathLocal = opt ? path.join(generatedDir, pdfFilename) : path.join(generatedDir, pdfFilename);

    if (!fs.existsSync(pdfPathLocal)) {
      // fallback: try cloud entry
      const cloudEntry = opt?.pdfUrl;
      if (!cloudEntry) return res.status(404).json({ success: false, message: 'File not found' });
    }

    const userEmail = req.session.user?.email;
    if (!userEmail) return res.status(400).json({ success: false, message: 'No logged-in user to email to' });

    const transporter = await createTransporter();
    if (!transporter) return res.status(500).json({ success: false, message: 'Email not configured on server' });

    const mailOptions = {
      from: process.env.MAIL_FROM || process.env.MAIL_USER,
      to: userEmail,
      subject: 'Your Optimized CV from Job-Fit',
      text: 'Attached is the optimized CV generated by Job-Fit. Good luck with your application!',
      attachments: [{ filename: path.basename(pdfFilename), path: pdfPathLocal }],
    };

    await transporter.sendMail(mailOptions);
    return res.json({ success: true, message: 'Email sent' });
  } catch (err) {
    console.error('send-email error:', err);
    return res.status(500).json({ success: false, message: 'Failed to send email', error: String(err) });
  }
});

// === Stripe Checkout (unchanged) ===
app.post('/create-checkout-session', express.json(), async (req, res) => {
  try {
    const { email, metadata } = req.body;
    const session = await stripe.checkout.sessions.create({
      mode: 'subscription',
      payment_method_types: ['card'],
      customer_email: email,
      line_items: [{ price: process.env.STRIPE_PRICE_ID, quantity: 1 }],
      subscription_data: { metadata: metadata || {} },
      success_url: `${process.env.DOMAIN}/download`,
      cancel_url: `${process.env.DOMAIN}/`,
    });
    return res.json({ url: session.url });
  } catch (err) {
    console.error('stripe error', err);
    return res.status(500).json({ message: err.message || 'Stripe error' });
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

/***********************
 * Dashboard API routes *
 ***********************/

// Saved CVs (per-user) - read from DB.saved
app.get('/api/saved-cvs', (req, res) => {
  if (!req.session.user) return res.status(401).json([]);
  const db = readDb();
  const files = (db.saved || [])
    .filter(f => f.userId === req.session.user.id)
    .map(f => ({ ...f }));
  res.json(files);
});

// Past optimizations (per-user) - read from DB.optimizations
app.get('/api/past-optimizations', (req, res) => {
  if (!req.session.user) return res.status(401).json([]);
  const db = readDb();
  const files = (db.optimizations || [])
    .filter(f => f.userId === req.session.user.id)
    .map(f => ({ ...f }));
  res.json(files);
});

// Subscription status
app.get('/api/subscription-status', (req, res) => {
  if (!req.session.user) return res.status(401).json({ active: false });
  // TODO: Integrate Stripe subscription status (requires storing customer id)
  res.json({ active: true });
});

// Simple profile update (example)
app.post('/api/profile', express.json(), (req, res) => {
  if (!req.session.user) return res.status(401).json({ success: false, message: 'Not logged in' });
  const db = readDb();
  db.users = db.users || {};
  const id = req.session.user.id;
  db.users[id] = db.users[id] || {};
  db.users[id].name = req.body.name || req.session.user.name;
  db.users[id].email = req.body.email || req.session.user.email;
  writeDb(db);
  // update session copy
  req.session.user.name = db.users[id].name;
  req.session.user.email = db.users[id].email;
  res.json({ success: true, user: req.session.user });
});

// start
const PORT = process.env.PORT || 4242;
app.listen(PORT, () => console.log(`🚀 Running http://localhost:${PORT}`));
