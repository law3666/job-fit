// server.js — Updated: fixes dashboard download + date issues
require("dotenv").config();
const express = require("express");
const session = require("express-session");
const path = require("path");
const fs = require("fs");
const multer = require("multer");
const bodyParser = require("body-parser");
const puppeteer = require("puppeteer-core");
const chromium = require("@sparticuz/chromium");
const mammoth = require("mammoth");
const pdfParse = require("pdf-parse");
const Groq = require("groq-sdk");
const cloudinary = require("cloudinary").v2;
const passport = require("passport");
const GoogleStrategy = require("passport-google-oauth20").Strategy;
const Stripe = require("stripe");

const app = express();

// ===== BASIC SETUP =====
app.use(express.static("public"));
app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());

app.use(
  session({
    secret: process.env.SESSION_SECRET || "supersecret",
    resave: false,
    saveUninitialized: false,
  })
);

app.set("view engine", "ejs");

// ===== MULTER STORAGE =====
const upload = multer({ dest: "uploads/" });

// ===== CLOUDINARY =====
cloudinary.config({
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME || "",
  api_key: process.env.CLOUDINARY_API_KEY || "",
  api_secret: process.env.CLOUDINARY_API_SECRET || "",
});

// ===== STRIPE =====
const stripe = Stripe(process.env.STRIPE_SECRET_KEY || "");

// ===== GROQ =====
const groq = new Groq({ apiKey: process.env.GROQ_API_KEY || "" });

// ===== GOOGLE OAUTH =====
passport.use(
  new GoogleStrategy(
    {
      clientID: process.env.GOOGLE_CLIENT_ID || "",
      clientSecret: process.env.GOOGLE_CLIENT_SECRET || "",
      callbackURL: "/auth/google/callback",
    },
    (accessToken, refreshToken, profile, done) => {
      done(null, profile);
    }
  )
);
passport.serializeUser((user, done) => done(null, user));
passport.deserializeUser((obj, done) => done(null, obj));
app.use(passport.initialize());
app.use(passport.session());

// ===== ENSURE GENERATED DIR & SERVE IT =====
const GEN_DIR = path.join(__dirname, "generated");
if (!fs.existsSync(GEN_DIR)) fs.mkdirSync(GEN_DIR, { recursive: true });

// Serve generated files as static so dashboard links like /generated/<file> work
app.use("/generated", express.static(GEN_DIR));

// ===== PUPPETEER LAUNCH HELPERS =====
async function launchBrowser(launchOptions = {}) {
  // sparticuz/chromium gives good defaults for serverless/container envs
  const args = [...(chromium.args || []), "--no-sandbox", "--disable-setuid-sandbox", "--disable-dev-shm-usage", ...(launchOptions.args || [])];
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

// ===== ROUTES =====
app.get("/", (req, res) => res.render("index"));

app.get("/auth/google", passport.authenticate("google", { scope: ["profile", "email"] }));

app.get(
  "/auth/google/callback",
  passport.authenticate("google", { failureRedirect: "/" }),
  (req, res) => {
    // store minimal user in session
    req.session.user = {
      id: req.user.id || null,
      name: req.user.displayName || "User",
      email: (req.user.emails && req.user.emails[0] && req.user.emails[0].value) || null,
    };
    res.redirect("/dashboard");
  }
);

app.get("/logout", (req, res) => {
  req.session.destroy(() => res.redirect("/"));
});

app.get("/dashboard", (req, res) => {
  if (!req.session.user) return res.redirect("/");
  // savedCVs and pastOptimizations include filename + date (ISO string)
  res.render("dashboard", {
    user: req.session.user,
    savedCVs: req.session.savedCVs || [],
    pastOptimizations: req.session.pastOptimizations || [],
    subscription: req.session.subscriptionStatus || "Inactive",
  });
});

// ===== Helper: sanitize a filename =====
function sanitizeFilename(name) {
  // keep base name only, replace spaces with underscores, strip unsafe chars
  const base = path.basename(String(name || ""));
  return base.replace(/\s+/g, "_").replace(/[^a-zA-Z0-9._-]/g, "");
}

// ===== PROCESS CV (upload -> optimize -> pdf) =====
app.post("/process-cv", upload.single("cvFile"), async (req, res) => {
  let browser = null;
  try {
    if (!req.file) return res.status(400).send("No file uploaded.");

    // 1) Extract text
    let textContent = "";
    const mime = req.file.mimetype || "";

    if (mime === "application/pdf" || req.file.originalname.toLowerCase().endsWith(".pdf")) {
      const dataBuffer = fs.readFileSync(req.file.path);
      const parsed = await pdfParse(dataBuffer).catch((e) => {
        console.warn("pdfParse warning:", e?.message || e);
        return { text: "" };
      });
      textContent = parsed.text || "";
    } else {
      // try docx -> text, otherwise fallback to reading raw file
      try {
        const result = await mammoth.extractRawText({ path: req.file.path });
        textContent = result.value || "";
      } catch (e) {
        textContent = fs.readFileSync(req.file.path, "utf8");
      }
    }

    // 2) Save original uploaded CV into generated/ with safe filename
    const safeOriginalName = sanitizeFilename(req.file.originalname || `upload-${Date.now()}`);
    const originalFilename = `${Date.now()}-${safeOriginalName}`;
    const originalPath = path.join(GEN_DIR, originalFilename);

    // copy the uploaded temp file to generated
    await fs.promises.copyFile(req.file.path, originalPath);

    // record in session (use ISO date strings so front-end can parse/format reliably)
    if (!req.session.savedCVs) req.session.savedCVs = [];
    req.session.savedCVs.push({
      filename: originalFilename,
      date: new Date().toISOString(),
      // optionally include originalName for UI
      originalName: req.file.originalname,
    });

    // 3) Send text to Groq (AI) to optimize CV -> produce HTML/text (keep errors handled)
    let optimizedCV = "";
    try {
      const completion = await groq.chat.completions.create({
        model: process.env.GROQ_MODEL || "llama-3.3-70b-versatile",
        messages: [
          { role: "system", content: "You are an expert resume writer and career coach." },
          { role: "user", content: `Optimize this CV for clarity, ATS, and impact:\n\n${textContent}` },
        ],
        temperature: 0.2,
        max_tokens: 1800,
      });
      optimizedCV =
        completion?.choices?.[0]?.message?.content ||
        completion?.choices?.[0]?.text ||
        String(optimizedCV || "");
    } catch (aiErr) {
      console.error("GROQ error:", aiErr?.message || aiErr);
      // fallback to using the raw extracted text so user at least gets a PDF/preview
      optimizedCV = textContent || "No content available from AI.";
    }

    // 4) Create PDF with Puppeteer
    try {
      browser = await launchBrowser();
      const page = await browser.newPage();

      const htmlContent = `<!doctype html>
      <html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
      <style>body{font-family:Inter,system-ui,-apple-system,"Helvetica Neue",Arial;color:#111;padding:24px;background:#fff}pre{white-space:pre-wrap;word-break:break-word}</style>
      </head><body><div class="content"><pre>${escapeHtmlForHtml(optimizedCV)}</pre></div></body></html>`;

      await page.setContent(htmlContent, { waitUntil: "networkidle0" });

      const optimizedFilename = `optimized-${Date.now()}.pdf`;
      const optimizedPath = path.join(GEN_DIR, optimizedFilename);

      const pdfBuffer = await page.pdf({ format: "A4", printBackground: true, margin: { top: "18mm", bottom: "18mm" } });
      await fs.promises.writeFile(optimizedPath, pdfBuffer);

      // record optimization
      if (!req.session.pastOptimizations) req.session.pastOptimizations = [];
      req.session.pastOptimizations.push({
        filename: optimizedFilename,
        date: new Date().toISOString(),
      });

      await page.close();
    } catch (puppErr) {
      console.error("Puppeteer generation failed:", puppErr?.message || puppErr);
      // still continue — we already saved original uploaded CV
      // you may decide to return preview-only or provide error notice on UI
    } finally {
      if (browser) {
        try {
          await browser.close();
        } catch (e) {
          // ignore
        }
      }
    }

    // 5) redirect back to dashboard (dashboard will show savedCVs and pastOptimizations)
    return res.redirect("/dashboard");
  } catch (err) {
    console.error("PROCESS-CV error:", err);
    return res.status(500).send("Failed to process CV.");
  }
});

// ===== DOWNLOAD ROUTE (fallback if direct static serving is not used) =====
app.get("/download", (req, res) => {
  const file = req.query.file;
  if (!file) return res.status(400).send("No file specified.");
  const abs = path.join(GEN_DIR, path.basename(file));
  if (!fs.existsSync(abs)) return res.status(404).send("File not found");
  res.download(abs);
});

// ===== STRIPE CHECKOUT =====
app.post("/create-checkout-session", async (req, res) => {
  try {
    const checkoutSession = await stripe.checkout.sessions.create({
      payment_method_types: ["card"],
      mode: "subscription",
      line_items: [{ price: process.env.STRIPE_PRICE_ID, quantity: 1 }],
      success_url: `${process.env.BASE_URL || ""}/payment-success`,
      cancel_url: `${process.env.BASE_URL || ""}/payment-cancel`,
    });
    res.json({ url: checkoutSession.url });
  } catch (e) {
    console.error("create-checkout-session error:", e);
    res.status(500).json({ message: "Stripe error" });
  }
});

app.get("/payment-success", (req, res) => {
  req.session.subscriptionStatus = "Active";
  res.redirect("/dashboard");
});
app.get("/payment-cancel", (req, res) => res.send("Payment canceled."));

// ===== START SERVER =====
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`🚀 Running ${process.env.BASE_URL || "http://localhost:" + PORT}`));

// ====== SMALL UTIL ======
function escapeHtmlForHtml(str) {
  if (!str) return "";
  return String(str)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;");
}
