// server.js (FINAL FIXED VERSION)

require("dotenv").config();
const express = require("express");
const session = require("express-session");
const passport = require("passport");
const GoogleStrategy = require("passport-google-oauth20").Strategy;
const bodyParser = require("body-parser");
const multer = require("multer");
const path = require("path");
const fs = require("fs");
const cors = require("cors");
const { v4: uuidv4 } = require("uuid");
const fetch = require("node-fetch");
const chromium = require("@sparticuz/chromium");
const puppeteer = require("puppeteer-core");
const Stripe = require("stripe");
const stripe = Stripe(process.env.STRIPE_SECRET_KEY);
const Groq = require("groq-sdk");

const app = express();

// -----------------------
// Basic App Config
// -----------------------
app.use(cors());
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

app.use(
  session({
    secret: process.env.SESSION_SECRET || "defaultsecret",
    resave: false,
    saveUninitialized: false,
  })
);

app.use(passport.initialize());
app.use(passport.session());

app.set("view engine", "ejs");
app.use(express.static("public"));
app.use("/uploads", express.static(path.join(__dirname, "uploads")));
app.use("/generated", express.static(path.join(__dirname, "generated")));

// -----------------------
// JSON Database
// -----------------------
const dbPath = path.join(__dirname, "db.json");

const loadDB = () => {
  if (!fs.existsSync(dbPath)) {
    fs.writeFileSync(
      dbPath,
      JSON.stringify({ users: {}, optimizations: {}, uploads: {} }, null, 2)
    );
  }
  return JSON.parse(fs.readFileSync(dbPath));
};

const saveDB = (db) => {
  fs.writeFileSync(dbPath, JSON.stringify(db, null, 2));
};

// -----------------------
// Google OAuth Strategy
// -----------------------
passport.use(
  new GoogleStrategy(
    {
      clientID: process.env.GOOGLE_CLIENT_ID,
      clientSecret: process.env.GOOGLE_CLIENT_SECRET,
      callbackURL: process.env.DOMAIN
        ? `${process.env.DOMAIN}/auth/google/callback`
        : "/auth/google/callback",
    },
    function (accessToken, refreshToken, profile, done) {
      const db = loadDB();

      if (!db.users[profile.id]) {
        db.users[profile.id] = {
          id: profile.id,
          name: profile.displayName,
          avatar:
            profile.photos && profile.photos.length > 0
              ? profile.photos[0].value
              : null,
          email:
            profile.emails && profile.emails.length > 0
              ? profile.emails[0].value
              : null,
          subscriptionActive: false,
        };
        saveDB(db);
      }

      return done(null, db.users[profile.id]);
    }
  )
);

passport.serializeUser((user, done) => done(null, user.id));
passport.deserializeUser((id, done) => {
  const db = loadDB();
  done(null, db.users[id]);
});

// -----------------------
// Auth Routes
// -----------------------
app.get("/auth/google", passport.authenticate("google", { scope: ["profile", "email"] }));

app.get(
  "/auth/google/callback",
  passport.authenticate("google", {
    failureRedirect: "/login?error=true",
  }),
  (req, res) => {
    res.redirect("/dashboard");
  }
);

app.get("/logout", (req, res) => {
  req.logout(() => {});
  res.redirect("/");
});

// -----------------------
// Dashboard
// -----------------------
function isLoggedIn(req, res, next) {
  if (req.isAuthenticated()) return next();
  res.redirect("/");
}

app.get("/dashboard", isLoggedIn, (req, res) => {
  const db = loadDB();

  const uploads = db.uploads[req.user.id] || [];
  const optimizations = db.optimizations[req.user.id] || [];

  res.render("dashboard", {
    user: req.user,
    uploads,
    optimizations,
    subscriptionActive: req.user.subscriptionActive,
  });
});

// -----------------------
// File Upload
// -----------------------
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    const dir = "./uploads";
    if (!fs.existsSync(dir)) fs.mkdirSync(dir);
    cb(null, dir);
  },
  filename: (req, file, cb) => {
    cb(null, Date.now() + "-" + file.originalname.replace(/\s+/g, "_"));
  },
});

const upload = multer({ storage });

// Save CV Upload
app.post("/upload", isLoggedIn, upload.single("cv"), (req, res) => {
  const db = loadDB();

  if (!db.uploads[req.user.id]) db.uploads[req.user.id] = [];

  db.uploads[req.user.id].push({
    id: uuidv4(),
    filename: req.file.filename,
    fileName: req.file.filename, // FIX #1
    path: "/uploads/" + req.file.filename,
    uploadedAt: new Date().toISOString(), // FIX #2
    date: new Date().toISOString(), // FIX #2
  });

  saveDB(db);
  res.json({ success: true });
});

// -----------------------
// Optimization Save
// -----------------------
app.post("/save-optimization", isLoggedIn, (req, res) => {
  const { filename } = req.body;
  const db = loadDB();

  if (!db.optimizations[req.user.id]) db.optimizations[req.user.id] = [];

  db.optimizations[req.user.id].push({
    id: uuidv4(),
    filename,
    fileName: filename, // FIX #1
    date: new Date().toISOString(),
  });

  saveDB(db);
  res.json({ success: true });
});

// -----------------------
// PDF Generator (unchanged)
// -----------------------
app.post("/generate-pdf", isLoggedIn, async (req, res) => {
  try {
    const { html } = req.body;

    const browser = await puppeteer.launch({
      args: chromium.args,
      defaultViewport: chromium.defaultViewport,
      executablePath: await chromium.executablePath(),
      headless: chromium.headless,
    });

    const page = await browser.newPage();
    await page.setContent(html, { waitUntil: "networkidle0" });

    const fileName = `optimized-${Date.now()}.pdf`;
    const filePath = path.join("generated", fileName);

    if (!fs.existsSync("generated")) fs.mkdirSync("generated");

    await page.pdf({ path: filePath, format: "A4" });
    await browser.close();

    res.json({ file: `/generated/${fileName}` });
  } catch (err) {
    console.error("PDF Error:", err);
    res.status(500).json({ error: "Failed to generate PDF" });
  }
});

// -----------------------
// Stripe Subscription
// -----------------------
app.post("/create-checkout-session", isLoggedIn, async (req, res) => {
  const session = await stripe.checkout.sessions.create({
    mode: "subscription",
    success_url: `${process.env.DOMAIN}/dashboard`,
    cancel_url: `${process.env.DOMAIN}/dashboard`,
    customer_email: req.user.email,
    line_items: [{ price: process.env.STRIPE_PRICE_ID, quantity: 1 }],
  });

  res.json({ url: session.url });
});

// Webhook
app.post("/webhook", bodyParser.raw({ type: "application/json" }), (req, res) => {
  const event = req.body;
  const db = loadDB();

  if (event.type === "checkout.session.completed") {
    const email = event.data.object.customer_email;

    for (let id in db.users) {
      if (db.users[id].email === email) {
        db.users[id].subscriptionActive = true;
      }
    }

    saveDB(db);
  }

  res.sendStatus(200);
});

// -----------------------
// Start Server
// -----------------------
const PORT = process.env.PORT || 3000;
app.listen(PORT, () =>
  console.log(`🚀 Server running on ${process.env.DOMAIN || "http://localhost:" + PORT}`)
);
