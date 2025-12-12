// ==============================
//            IMPORTS
// ==============================
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
const { Groq } = require("groq-sdk");   // ✅ FIXED: correct Groq import
const cloudinary = require("cloudinary").v2;
const passport = require("passport");
const GoogleStrategy = require("passport-google-oauth20").Strategy;
const Stripe = require("stripe");

const app = express();

// ==============================
//            SETUP
// ==============================
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

// MUST come AFTER session
app.use(passport.initialize());
app.use(passport.session());

app.set("view engine", "ejs");

// ==============================
//           STORAGE
// ==============================
const upload = multer({ dest: "uploads/" });

// ==============================
//       CLOUDINARY CONFIG
// ==============================
cloudinary.config({
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME || "",
  api_key: process.env.CLOUDINARY_API_KEY || "",
  api_secret: process.env.CLOUDINARY_API_SECRET || "",
});

// ==============================
//           STRIPE
// ==============================
const stripe = Stripe(process.env.STRIPE_SECRET_KEY || "");

// ==============================
//             GROQ
// ==============================
const groq = new Groq({ apiKey: process.env.GROQ_API_KEY });

// ==============================
//     GOOGLE AUTH / PASSPORT
// ==============================
passport.use(
  new GoogleStrategy(
    {
      clientID: process.env.GOOGLE_CLIENT_ID || "",
      clientSecret: process.env.GOOGLE_CLIENT_SECRET || "",
      callbackURL: "/auth/google/callback",
    },
    (accessToken, refreshToken, profile, done) => done(null, profile)
  )
);

passport.serializeUser((user, done) => done(null, user));
passport.deserializeUser((obj, done) => done(null, obj));

// ==============================
//      GENERATED DIRECTORY
// ==============================
const GEN_DIR = path.join(__dirname, "generated");
if (!fs.existsSync(GEN_DIR)) fs.mkdirSync(GEN_DIR, { recursive: true });

app.use("/generated", express.static(GEN_DIR)); // keep static for easy downloads

// ==============================
//         LAUNCH BROWSER
// ==============================
async function launchBrowser() {
  return await puppeteer.launch({
    args: [...chromium.args, "--no-sandbox"],
    headless: chromium.headless,
    executablePath: await chromium.executablePath(),
  });
}

// ==============================
//             ROUTES
// ==============================
app.get("/", (req, res) => res.render("index"));

// GOOGLE LOGIN
app.get("/auth/google", passport.authenticate("google", { scope: ["profile", "email"] }));

app.get(
  "/auth/google/callback",
  passport.authenticate("google", { failureRedirect: "/" }),
  (req, res) => {
    req.session.user = {
      name: req.user.displayName,
      email: req.user.emails[0].value,
    };
    res.redirect("/dashboard");
  }
);

app.get("/logout", (req, res) => req.session.destroy(() => res.redirect("/")));

// DASHBOARD
app.get("/dashboard", (req, res) => {
  if (!req.session.user) return res.redirect("/");
  res.render("dashboard", {
    user: req.session.user,
    savedCVs: req.session.savedCVs || [],
    pastOptimizations: req.session.pastOptimizations || [],
    subscription: req.session.subscriptionStatus || "Inactive",
  });
});

// ==============================
//      SANITIZE FILENAME
// ==============================
function sanitizeFilename(name) {
  const base = path.basename(name);
  return base.replace(/\s+/g, "_").replace(/[^a-zA-Z0-9._-]/g, "");
}

// ==============================
//    PROCESS CV & OPTIMIZE
// ==============================
app.post("/process-cv", upload.single("cvFile"), async (req, res) => {
  try {
    if (!req.file) return res.status(400).send("No file uploaded.");

    // 1. Extract text
    let textContent = "";
    if (req.file.mimetype === "application/pdf") {
      const buffer = fs.readFileSync(req.file.path);
      const parsed = await pdfParse(buffer);
      textContent = parsed.text;
    } else {
      const result = await mammoth.extractRawText({ path: req.file.path });
      textContent = result.value;
    }

    // 2. Save original file
    const safeName = sanitizeFilename(req.file.originalname);
    const originalFilename = `${Date.now()}-${safeName}`;
    const originalPath = path.join(GEN_DIR, originalFilename);
    await fs.promises.copyFile(req.file.path, originalPath);

    if (!req.session.savedCVs) req.session.savedCVs = [];
    req.session.savedCVs.push({
      filename: originalFilename,
      date: new Date().toISOString(),
    });

    // 3. Optimize via Groq
    const result = await groq.chat.completions.create({
      model: "mixtral-8x7b-32768",
      messages: [
        { role: "system", content: "You are a CV optimization assistant." },
        { role: "user", content: textContent },
      ],
    });

    const optimizedText = result.choices[0].message.content;

    // 4. Generate PDF
    const browser = await launchBrowser();
    const page = await browser.newPage();
    await page.setContent(`<html><body><pre>${optimizedText}</pre></body></html>`);

    const optimizedFilename = `optimized-${Date.now()}.pdf`;
    const optimizedPath = path.join(GEN_DIR, optimizedFilename);

    const pdfBuffer = await page.pdf({ format: "A4" });
    await fs.promises.writeFile(optimizedPath, pdfBuffer);
    await browser.close();

    if (!req.session.pastOptimizations) req.session.pastOptimizations = [];
    req.session.pastOptimizations.push({
      filename: optimizedFilename,
      date: new Date().toISOString(),
    });

    res.redirect("/dashboard");
  } catch (err) {
    console.error("PROCESS ERROR:", err);
    res.status(500).send("Error processing CV.");
  }
});

// ==============================
//       STRIPE CHECKOUT
// ==============================
app.post("/create-checkout-session", async (req, res) => {
  try {
    const sessionStripe = await stripe.checkout.sessions.create({
      payment_method_types: ["card"],
      mode: "subscription",
      line_items: [{ price: process.env.STRIPE_PRICE_ID, quantity: 1 }],
      success_url: `${process.env.BASE_URL}/payment-success`,
      cancel_url: `${process.env.BASE_URL}/payment-cancel`,
    });
    res.json({ url: sessionStripe.url });
  } catch (err) {
    res.status(500).json({ error: "Stripe error" });
  }
});

// SUCCESS / CANCEL
app.get("/payment-success", (req, res) => {
  req.session.subscriptionStatus = "Active";
  res.redirect("/dashboard");
});

app.get("/payment-cancel", (req, res) => res.send("Payment canceled."));

// ==============================
//       START SERVER
// ==============================
const PORT = process.env.PORT || 3000;
app.listen(PORT, () =>
  console.log(`🚀 Running on ${process.env.BASE_URL || "http://localhost:" + PORT}`)
);
