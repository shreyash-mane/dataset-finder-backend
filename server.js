const express = require("express");
const cors = require("cors");
const mongoose = require("mongoose");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const passport = require("passport");
const GoogleStrategy = require("passport-google-oauth20").Strategy;
const GitHubStrategy = require("passport-github2").Strategy;
const Anthropic = require("@anthropic-ai/sdk");
const PDFDocument = require("pdfkit");
const twilio = require("twilio");
const Resend = require("resend").Resend;

const app = express();
app.use(express.json());
app.use(cors({ origin: "*", methods: ["GET","POST","PUT","DELETE","OPTIONS"], allowedHeaders: ["Content-Type","Authorization"] }));
app.options("*", cors());
app.use(passport.initialize());

// ── ENV ───────────────────────────────────────────────────────────────────────
const ANTHROPIC_API_KEY = process.env.ANTHROPIC_API_KEY;
const MONGODB_URI       = process.env.MONGODB_URI;
const JWT_SECRET        = process.env.JWT_SECRET || "dataset-finder-secret-2026";
const GOOGLE_CLIENT_ID  = process.env.GOOGLE_CLIENT_ID;
const GOOGLE_SECRET     = process.env.GOOGLE_CLIENT_SECRET;
const GITHUB_CLIENT_ID  = process.env.GITHUB_CLIENT_ID;
const GITHUB_SECRET     = process.env.GITHUB_CLIENT_SECRET;
const FRONTEND_URL      = process.env.FRONTEND_URL || "https://dataset-finder-frontend.vercel.app";
const SERPER_API_KEY    = process.env.SERPER_API_KEY;
const RESEND_API_KEY    = process.env.RESEND_API_KEY;
const FROM_EMAIL        = process.env.FROM_EMAIL || "otp@data-lab.co.uk";
const TWILIO_SID        = process.env.TWILIO_ACCOUNT_SID;
const TWILIO_TOKEN      = process.env.TWILIO_AUTH_TOKEN;
const TWILIO_SERVICE_SID = process.env.TWILIO_SERVICE_SID;
const PORT              = parseInt(process.env.PORT) || 3001;

console.log("API Key loaded:", ANTHROPIC_API_KEY ? "YES" : "NO - MISSING!");
console.log("MongoDB URI loaded:", MONGODB_URI ? "YES" : "NO - MISSING!");

const client = new Anthropic({ apiKey: ANTHROPIC_API_KEY });

// ── MongoDB ───────────────────────────────────────────────────────────────────
mongoose.connect(MONGODB_URI)
  .then(() => console.log("MongoDB connected!"))
  .catch(err => console.error("MongoDB error:", err.message));

const userSchema = new mongoose.Schema({
  name:       { type: String, required: true },
  email:      { type: String, required: true, unique: true },
  password:   { type: String },
  provider:   { type: String, default: "email" },
  providerId: { type: String },
  avatar:     { type: String },
  createdAt:  { type: Date, default: Date.now },
});
const User = mongoose.model("User", userSchema);

const collectionSchema = new mongoose.Schema({
  userId:    { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true },
  name:      { type: String, required: true },
  color:     { type: String, default: "#3b82f6" },
  createdAt: { type: Date, default: Date.now },
});
const Collection = mongoose.model("Collection", collectionSchema);

const savedDatasetSchema = new mongoose.Schema({
  userId:            { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true },
  collectionId:      { type: mongoose.Schema.Types.ObjectId, ref: "Collection", default: null },
  name:              { type: String, required: true },
  source:            { type: String },
  url:               { type: String },
  description:       { type: String },
  size:              { type: String },
  format:            { type: String },
  reliabilityScore:  { type: Number },
  reliabilityLabel:  { type: String },
  reliabilityFactors:{ type: Object },
  reliabilityReasons:[ String ],
  citedInPapers:     { type: Number },
  papers:            [ Object ],
  tags:              [ String ],
  lastUpdated:       { type: String },
  license:           { type: String },
  notes:             { type: String, default: "" },
  savedAt:           { type: Date, default: Date.now },
});
const SavedDataset = mongoose.model("SavedDataset", savedDatasetSchema);

// ── Search Cache Schema ──────────────────────────────────────────────────────
const searchCacheSchema = new mongoose.Schema({
  queryKey:  { type: String, required: true, unique: true }, // normalized query
  datasets:  [ Object ],
  mode:      { type: String, default: "fast" },
  createdAt: { type: Date, default: Date.now, expires: 86400 }, // auto-delete after 24h
});
const SearchCache = mongoose.model("SearchCache", searchCacheSchema);

// ── Auth Helpers ──────────────────────────────────────────────────────────────
const generateToken = (userId) => jwt.sign({ userId }, JWT_SECRET, { expiresIn: "30d" });
const authMiddleware = async (req, res, next) => {
  const token = req.headers.authorization?.split(" ")[1];
  if (!token) return res.status(401).json({ error: "No token provided" });
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = await User.findById(decoded.userId);
    if (!req.user) return res.status(401).json({ error: "User not found" });
    next();
  } catch { return res.status(401).json({ error: "Invalid token" }); }
};

// ── Passport Google ───────────────────────────────────────────────────────────
if (GOOGLE_CLIENT_ID && GOOGLE_SECRET) {
  passport.use(new GoogleStrategy({
    clientID: GOOGLE_CLIENT_ID, clientSecret: GOOGLE_SECRET,
    callbackURL: `https://dataset-finder-backend-production.up.railway.app/auth/google/callback`,
  }, async (accessToken, refreshToken, profile, done) => {
    try {
      let user = await User.findOne({ email: profile.emails[0].value });
      if (!user) user = await User.create({ name: profile.displayName, email: profile.emails[0].value, provider: "google", providerId: profile.id, avatar: profile.photos[0]?.value });
      done(null, user);
    } catch (err) { done(err); }
  }));
}

// ── Passport GitHub ───────────────────────────────────────────────────────────
if (GITHUB_CLIENT_ID && GITHUB_SECRET) {
  passport.use(new GitHubStrategy({
    clientID: GITHUB_CLIENT_ID, clientSecret: GITHUB_SECRET,
    callbackURL: `https://dataset-finder-backend-production.up.railway.app/auth/github/callback`,
    scope: ["user:email"],
  }, async (accessToken, refreshToken, profile, done) => {
    try {
      const email = profile.emails?.[0]?.value || `${profile.username}@github.com`;
      let user = await User.findOne({ email });
      if (!user) user = await User.create({ name: profile.displayName || profile.username, email, provider: "github", providerId: profile.id, avatar: profile.photos[0]?.value });
      done(null, user);
    } catch (err) { done(err); }
  }));
}

passport.serializeUser((user, done) => done(null, user.id));
passport.deserializeUser(async (id, done) => { const user = await User.findById(id); done(null, user); });

// ── Email / SMS helpers ───────────────────────────────────────────────────────
const resendClient = RESEND_API_KEY ? new Resend(RESEND_API_KEY) : null;

const twilioClient = TWILIO_SID && TWILIO_TOKEN ? twilio(TWILIO_SID, TWILIO_TOKEN) : null;

// OTP store: email → { otp, expiry }  (phone OTP handled by Twilio Verify)
const otpStore = new Map();

function generateOtp() {
  return String(Math.floor(100000 + Math.random() * 900000));
}

// ── Rate Limiter ──────────────────────────────────────────────────────────────
const rateLimitMap = new Map();
const MAX_SEARCHES_PER_DAY = 5;

function getRateLimitInfo(ip) {
  const now = Date.now();
  const entry = rateLimitMap.get(ip);
  if (!entry || now > entry.resetAt) {
    const resetAt = new Date(); resetAt.setHours(24, 0, 0, 0);
    const newEntry = { count: 0, resetAt: resetAt.getTime() };
    rateLimitMap.set(ip, newEntry); return newEntry;
  }
  return entry;
}
function getUserIp(req) {
  return req.headers["x-forwarded-for"]?.split(",")[0].trim() || req.socket.remoteAddress || "unknown";
}

// ── Smart Query Parser ────────────────────────────────────────────────────────
function parseSmartQuery(query) {
  // Handle AND/OR queries like "suicidal AND mental health" or "climate OR weather"
  const upperQ = query.toUpperCase();
  if (upperQ.includes(" AND ")) {
    const parts = query.split(/ AND /i).map(p => p.trim());
    return { type: "AND", parts, prompt: `Find datasets that cover ALL of these topics together: ${parts.join(", ")}. The datasets must be relevant to every topic mentioned.` };
  }
  if (upperQ.includes(" OR ")) {
    const parts = query.split(/ OR /i).map(p => p.trim());
    return { type: "OR", parts, prompt: `Find datasets related to ANY of these topics: ${parts.join(", ")}. Show the most relevant datasets for each topic.` };
  }
  return { type: "SIMPLE", parts: [query], prompt: `Find datasets for: ${query}` };
}

// ── System Prompt ─────────────────────────────────────────────────────────────
const SYSTEM_PROMPT = `You are a dataset discovery expert with broad knowledge of datasets from Kaggle, HuggingFace, UCI ML Repository, Zenodo, PapersWithCode, GitHub, Google Dataset Search, government open data portals, and thousands of published research papers.

When given a dataset search request, respond ONLY with a valid JSON array (no markdown, no backticks, no extra text) containing exactly 3 dataset recommendations.

IMPORTANT RULES:
- Sort papers within each dataset by year DESCENDING (newest first)
- Include only papers from the last 5 years when possible (2020-2025)
- reliabilityScore must be a weighted average of the 7 factors

Each dataset object must have these exact keys:
- "rank": number (1, 2, or 3)
- "name": string
- "source": string (e.g. "Kaggle", "HuggingFace", "UCI ML Repository", "Zenodo", "PapersWithCode", "GitHub", "Government")
- "url": string
- "description": string (2-3 sentences)
- "size": string (e.g. "2.3 GB", "45,000 rows")
- "sizeBytes": number (approximate size in bytes for sorting, e.g. 2300000000)
- "format": string
- "year": number (year the dataset was published or last majorly updated)
- "reliabilityScore": number 1.0-10.0 (one decimal)
- "reliabilityLabel": one of: "Excellent", "Very Good", "Good", "Fair", "Poor"
- "reliabilityFactors": object with exactly these 7 keys each scored 1-10:
    "citationCount", "sourceCredibility", "documentation", "licenseClarity", "communityAdoption", "maintenance", "biasAndDiversity"
- "reliabilityReasons": array of exactly 3 strings
- "citedInPapers": number
- "papers": array of exactly 3 objects sorted by year DESCENDING (newest first), each with: "title", "authors", "year", "venue", "citations"
- "tags": array of 4-5 strings
- "lastUpdated": string
- "license": string (e.g. "CC BY 4.0", "MIT", "Apache 2.0", "Public Domain", "CC0")

Rank by reliabilityScore descending. Return ONLY the raw JSON array.`;

// ════════════════════════════════════════════════════════════════════════════
// ROUTES
// ════════════════════════════════════════════════════════════════════════════

app.get("/health", (req, res) => res.json({ status: "ok", timestamp: new Date().toISOString() }));

// ── Auth Email/Password ───────────────────────────────────────────────────────
app.post("/auth/register", async (req, res) => {
  const { name, email, password } = req.body;
  if (!name || !email || !password) return res.status(400).json({ error: "All fields required" });
  if (password.length < 6) return res.status(400).json({ error: "Password must be at least 6 characters" });
  try {
    const existing = await User.findOne({ email });
    if (existing) return res.status(400).json({ error: "Email already registered" });
    const hashed = await bcrypt.hash(password, 12);
    const user = await User.create({ name, email, password: hashed, provider: "email" });
    const token = generateToken(user._id);
    res.json({ token, user: { id: user._id, name: user.name, email: user.email, avatar: user.avatar } });
  } catch (err) { res.status(500).json({ error: "Registration failed: " + err.message }); }
});

app.post("/auth/login", async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) return res.status(400).json({ error: "Email and password required" });
  try {
    const user = await User.findOne({ email });
    if (!user || !user.password) return res.status(401).json({ error: "Invalid email or password" });
    const valid = await bcrypt.compare(password, user.password);
    if (!valid) return res.status(401).json({ error: "Invalid email or password" });
    const token = generateToken(user._id);
    res.json({ token, user: { id: user._id, name: user.name, email: user.email, avatar: user.avatar } });
  } catch (err) { res.status(500).json({ error: "Login failed" }); }
});

// ── Auth Google/GitHub ────────────────────────────────────────────────────────
app.get("/auth/google", passport.authenticate("google", { scope: ["profile","email"] }));
app.get("/auth/google/callback", passport.authenticate("google", { session: false, failureRedirect: `${FRONTEND_URL}/login?error=google` }), (req, res) => {
  const token = generateToken(req.user._id);
  res.redirect(`${FRONTEND_URL}/auth/callback?token=${token}&name=${encodeURIComponent(req.user.name)}&email=${encodeURIComponent(req.user.email)}`);
});

app.get("/auth/github", passport.authenticate("github", { scope: ["user:email"] }));
app.get("/auth/github/callback", passport.authenticate("github", { session: false, failureRedirect: `${FRONTEND_URL}/login?error=github` }), (req, res) => {
  const token = generateToken(req.user._id);
  res.redirect(`${FRONTEND_URL}/auth/callback?token=${token}&name=${encodeURIComponent(req.user.name)}&email=${encodeURIComponent(req.user.email)}`);
});

app.get("/auth/me", authMiddleware, (req, res) => {
  res.json({ id: req.user._id, name: req.user.name, email: req.user.email, avatar: req.user.avatar });
});

// ── Forgot Password ───────────────────────────────────────────────────────────

// Send OTP to email
app.post("/auth/forgot/send-email", async (req, res) => {
  const { email } = req.body;
  if (!email?.trim()) return res.status(400).json({ error: "Email is required." });
  try {
    const user = await User.findOne({ email: email.trim().toLowerCase() });
    if (!user) return res.status(404).json({ error: "No account found with that email." });

    const otp = generateOtp();
    otpStore.set(email.trim().toLowerCase(), { otp, expiry: Date.now() + 10 * 60 * 1000 });

    if (!resendClient) return res.status(503).json({ error: "Email service not configured." });

    await resendClient.emails.send({
      from: `DataLab <${FROM_EMAIL}>`,
      to: [email.trim()],
      subject: `Your DataLab OTP: ${otp}`,
      html: `
        <div style="font-family:sans-serif;max-width:480px;margin:0 auto;padding:32px;background:#030712;color:#e0e8ff;border-radius:16px;">
          <div style="font-size:28px;font-weight:800;margin-bottom:4px;">🧪 DataLab</div>
          <div style="color:#4a5a7a;font-size:13px;margin-bottom:24px;">Password Reset</div>
          <p style="color:#8899bb;">Use the OTP below to reset your password. It expires in <strong>10 minutes</strong>.</p>
          <div style="background:#0d1b3e;border:1px solid #1e3a8a;border-radius:12px;padding:24px;text-align:center;margin:24px 0;">
            <div style="font-size:36px;font-weight:900;letter-spacing:10px;color:#6fa3ef;font-family:monospace;">${otp}</div>
          </div>
          <p style="color:#4a5a7a;font-size:12px;">If you didn't request this, ignore this email.</p>
        </div>`,
    });
    res.json({ success: true, message: "OTP sent to your email." });
  } catch (err) {
    console.error("Email OTP error:", err.message);
    res.status(500).json({ error: "Failed to send email. Please try again." });
  }
});

// Send OTP to phone via Twilio Verify (handles generation + delivery)
app.post("/auth/forgot/send-phone", async (req, res) => {
  const { phone } = req.body; // expects E.164 e.g. "+447911123456"
  if (!phone?.trim()) return res.status(400).json({ error: "Phone number is required." });
  try {
    if (!twilioClient || !TWILIO_SERVICE_SID) return res.status(503).json({ error: "SMS service not configured." });

    await twilioClient.verify.v2.services(TWILIO_SERVICE_SID)
      .verifications.create({ to: phone.trim(), channel: "sms" });

    res.json({ success: true, message: "OTP sent via SMS." });
  } catch (err) {
    console.error("SMS OTP error:", err.message);
    res.status(500).json({ error: "Failed to send SMS. Check the phone number and try again." });
  }
});

// Verify OTP + reset password in one step
app.post("/auth/forgot/reset", async (req, res) => {
  const { key, otp, newPassword } = req.body; // key = email or phone
  if (!key || !otp || !newPassword) return res.status(400).json({ error: "All fields required." });
  if (newPassword.length < 6) return res.status(400).json({ error: "Password must be at least 6 characters." });

  const stored = otpStore.get(key.trim().toLowerCase()) || otpStore.get(key.trim());
  if (!stored) return res.status(400).json({ error: "No OTP found. Please request a new one." });
  if (Date.now() > stored.expiry) { otpStore.delete(key); return res.status(400).json({ error: "OTP expired. Please request a new one." }); }
  if (stored.otp !== otp.trim()) return res.status(400).json({ error: "Incorrect OTP." });

  try {
    // Find user by email or phone (email-based lookup for both flows since phone isn't stored)
    const isEmail = key.includes("@");
    let user;
    if (isEmail) {
      user = await User.findOne({ email: key.trim().toLowerCase() });
    } else {
      return res.status(400).json({ error: "Phone-based reset: please log in with your email after resetting via phone." });
    }
    if (!user) return res.status(404).json({ error: "User not found." });

    user.password = await bcrypt.hash(newPassword, 12);
    await user.save();
    otpStore.delete(key.trim().toLowerCase());
    otpStore.delete(key.trim());

    const token = generateToken(user._id);
    res.json({ success: true, token, user: { id: user._id, name: user.name, email: user.email } });
  } catch (err) {
    res.status(500).json({ error: "Password reset failed." });
  }
});

// Verify phone OTP via Twilio Verify
app.post("/auth/forgot/verify-otp", async (req, res) => {
  const { key, otp } = req.body; // key = E.164 phone number
  if (!key || !otp) return res.status(400).json({ error: "Phone and OTP required." });
  try {
    if (!twilioClient || !TWILIO_SERVICE_SID) return res.status(503).json({ error: "SMS service not configured." });

    const check = await twilioClient.verify.v2.services(TWILIO_SERVICE_SID)
      .verificationChecks.create({ to: key.trim(), code: otp.trim() });

    if (check.status !== "approved") return res.status(400).json({ error: "Incorrect or expired OTP." });

    // Mark phone as verified in memory so reset endpoint can proceed
    otpStore.set(key.trim(), { verified: true, expiry: Date.now() + 10 * 60 * 1000 });
    res.json({ success: true });
  } catch (err) {
    console.error("Verify OTP error:", err.message);
    res.status(400).json({ error: "Incorrect or expired OTP." });
  }
});

// Reset password for phone-verified users
app.post("/auth/forgot/reset-phone", async (req, res) => {
  const { phone, email, newPassword } = req.body;
  if (!phone || !email || !newPassword) return res.status(400).json({ error: "All fields required." });
  if (newPassword.length < 6) return res.status(400).json({ error: "Password must be at least 6 characters." });

  const stored = otpStore.get(phone.trim());
  if (!stored?.verified || Date.now() > stored.expiry) {
    return res.status(400).json({ error: "Phone not verified. Please request a new OTP." });
  }

  try {
    const user = await User.findOne({ email: email.trim().toLowerCase() });
    if (!user) return res.status(404).json({ error: "No account found with that email." });
    user.password = await bcrypt.hash(newPassword, 12);
    await user.save();
    otpStore.delete(phone.trim());

    const token = generateToken(user._id);
    res.json({ success: true, token, user: { id: user._id, name: user.name, email: user.email } });
  } catch (err) {
    res.status(500).json({ error: "Password reset failed." });
  }
});

// ── Search ────────────────────────────────────────────────────────────────────
app.get("/api/rate-limit", (req, res) => {
  const ip = getUserIp(req);
  const info = getRateLimitInfo(ip);
  const remaining = Math.max(0, MAX_SEARCHES_PER_DAY - info.count);
  const resetIn = Math.ceil((info.resetAt - Date.now()) / 1000 / 60);
  res.json({ remaining, used: info.count, max: MAX_SEARCHES_PER_DAY, resetInMinutes: resetIn });
});

app.post("/api/search", async (req, res) => {
  const { query, liveSearch } = req.body;
  if (!query?.trim()) return res.status(400).json({ error: "Query is required." });
  if (query.trim().length > 300) return res.status(400).json({ error: "Query too long." });

  const ip = getUserIp(req);
  const info = getRateLimitInfo(ip);
  if (info.count >= MAX_SEARCHES_PER_DAY) {
    const resetIn = Math.ceil((info.resetAt - Date.now()) / 1000 / 60);
    return res.status(429).json({ error: `You've used all 5 free searches for today. Resets in ${resetIn} minutes.`, resetInMinutes: resetIn });
  }

  const parsed = parseSmartQuery(query.trim());
  const cacheKey = query.trim().toLowerCase().replace(/\s+/g, " ");

  // ── Check cache first (unless liveSearch requested) ───────────────────────
  if (!liveSearch) {
    try {
      const cached = await SearchCache.findOne({ queryKey: cacheKey });
      if (cached) {
        console.log("Cache hit for:", cacheKey);
        const remaining = Math.max(0, MAX_SEARCHES_PER_DAY - info.count);
        return res.json({ datasets: cached.datasets, remaining, used: info.count, max: MAX_SEARCHES_PER_DAY, mode: "cached", queryType: parsed.type, fromCache: true });
      }
    } catch (err) { console.log("Cache check failed:", err.message); }
  }

  // Only count against rate limit for actual API calls
  info.count += 1;

  const userMessage = parsed.prompt + ". Include only recent papers (2020-2025) sorted newest first.";
  let datasets = null;
  let mode = "fast";

  // ── Live web search using Serper free API ────────────────────────────────
  if (liveSearch) {
    try {
      let serperContext = null;
      // Try Serper free real-time Google search first
      if (SERPER_API_KEY) {
        const serperRes = await fetch("https://google.serper.dev/search", {
          method: "POST",
          headers: { "X-API-KEY": SERPER_API_KEY, "Content-Type": "application/json" },
          body: JSON.stringify({ q: query.trim() + " dataset site:kaggle.com OR site:huggingface.co OR site:paperswithcode.com OR site:zenodo.org", num: 10 }),
        });
        if (serperRes.ok) {
          const serperData = await serperRes.json();
          serperContext = (serperData.organic || []).slice(0, 8)
            .map(r => "Title: " + r.title + "\nURL: " + r.link + "\nSnippet: " + r.snippet)
            .join("\n\n");
          console.log("Serper returned", (serperData.organic || []).length, "results");
        }
      }

      if (serperContext) {
        // Use Haiku + Serper results — fast AND real-time!
        const livePrompt = "Here are real-time Google search results for '" + query.trim() + "':\n\n" + serperContext + "\n\nBased on these actual search results, " + userMessage + ". Use the real URLs from the search results.";
        const message = await client.messages.create({
          model: "claude-haiku-4-5",
          max_tokens: 2000,
          system: SYSTEM_PROMPT,
          messages: [{ role: "user", content: livePrompt }],
        });
        const text = (message.content || []).filter(c => c.type === "text").map(c => c.text || "").join("");
        if (text) {
          const jsonMatch = text.match(/\[[\s\S]*\]/);
          if (jsonMatch) { datasets = JSON.parse(jsonMatch[0]); mode = "live"; }
        }
      } else {
        // Fallback to Anthropic web search if no Serper key
        const message = await client.messages.create({
          model: "claude-sonnet-4-5",
          max_tokens: 3000,
          system: SYSTEM_PROMPT,
          tools: [{ type: "web_search_20250305", name: "web_search" }],
          messages: [{ role: "user", content: "Search the internet right now and " + userMessage }],
        });
        const text = (message.content || []).filter(c => c.type === "text").map(c => c.text || "").join("");
        if (text) {
          const jsonMatch = text.match(/\[[\s\S]*\]/);
          if (jsonMatch) { datasets = JSON.parse(jsonMatch[0]); mode = "live"; }
        }
      }
    } catch (err) { console.log("Live search failed, trying fast:", err.message); }
  }

  // ── Fast search using Haiku (default, ~2-3 sec) ───────────────────────────
  if (!datasets) {
    try {
      const message = await client.messages.create({
        model: "claude-haiku-4-5",
        max_tokens: 2000,
        system: SYSTEM_PROMPT,
        messages: [{ role: "user", content: userMessage }],
      });
      const text = (message.content || []).filter(c => c.type === "text").map(c => c.text || "").join("");
      if (text) {
        const jsonMatch = text.match(/\[[\s\S]*\]/);
        if (jsonMatch) { datasets = JSON.parse(jsonMatch[0]); mode = "fast"; }
      }
    } catch (err) { console.log("Fast search failed:", err.message); }
  }

  if (!datasets) {
    info.count = Math.max(0, info.count - 1);
    return res.status(500).json({ error: "Search failed. Please try again." });
  }

  // Sort papers newest first
  datasets = datasets.map(ds => ({
    ...ds,
    papers: (ds.papers || []).sort((a, b) => (b.year || 0) - (a.year || 0))
  }));

  // ── Save to cache ─────────────────────────────────────────────────────────
  try {
    await SearchCache.findOneAndUpdate(
      { queryKey: cacheKey },
      { queryKey: cacheKey, datasets, mode },
      { upsert: true, new: true }
    );
  } catch (err) { console.log("Cache save failed:", err.message); }

  const remaining = Math.max(0, MAX_SEARCHES_PER_DAY - info.count);
  return res.json({ datasets, remaining, used: info.count, max: MAX_SEARCHES_PER_DAY, mode, queryType: parsed.type, fromCache: false });
});

// ── Collections ───────────────────────────────────────────────────────────────
app.get("/api/collections", authMiddleware, async (req, res) => {
  const cols = await Collection.find({ userId: req.user._id }).sort({ createdAt: -1 });
  res.json(cols);
});
app.post("/api/collections", authMiddleware, async (req, res) => {
  const { name, color } = req.body;
  if (!name?.trim()) return res.status(400).json({ error: "Collection name required" });
  const col = await Collection.create({ userId: req.user._id, name: name.trim(), color: color || "#3b82f6" });
  res.json(col);
});
app.delete("/api/collections/:id", authMiddleware, async (req, res) => {
  await Collection.deleteOne({ _id: req.params.id, userId: req.user._id });
  await SavedDataset.deleteMany({ collectionId: req.params.id, userId: req.user._id });
  res.json({ success: true });
});

// ── Saved Datasets ────────────────────────────────────────────────────────────
app.get("/api/saved", authMiddleware, async (req, res) => {
  const filter = { userId: req.user._id };
  if (req.query.collectionId) filter.collectionId = req.query.collectionId;
  const datasets = await SavedDataset.find(filter).sort({ savedAt: -1 });
  res.json(datasets);
});
app.post("/api/saved", authMiddleware, async (req, res) => {
  const { dataset, collectionId } = req.body;
  if (!dataset) return res.status(400).json({ error: "Dataset required" });
  const existing = await SavedDataset.findOne({ userId: req.user._id, name: dataset.name, source: dataset.source });
  if (existing) return res.status(400).json({ error: "Dataset already saved" });
  const saved = await SavedDataset.create({ userId: req.user._id, collectionId: collectionId || null, ...dataset });
  res.json(saved);
});
app.put("/api/saved/:id/notes", authMiddleware, async (req, res) => {
  const ds = await SavedDataset.findOneAndUpdate({ _id: req.params.id, userId: req.user._id }, { notes: req.body.notes }, { new: true });
  res.json(ds);
});
app.delete("/api/saved/:id", authMiddleware, async (req, res) => {
  await SavedDataset.deleteOne({ _id: req.params.id, userId: req.user._id });
  res.json({ success: true });
});

// ── PDF Download ──────────────────────────────────────────────────────────────
app.get("/api/saved/:id/pdf", authMiddleware, async (req, res) => {
  const dataset = await SavedDataset.findOne({ _id: req.params.id, userId: req.user._id });
  if (!dataset) return res.status(404).json({ error: "Dataset not found" });
  res.setHeader("Content-Type", "application/pdf");
  res.setHeader("Content-Disposition", `attachment; filename="${dataset.name.replace(/[^a-z0-9]/gi,"_")}.pdf"`);
  const doc = new PDFDocument({ margin: 50 });
  doc.pipe(res);
  doc.fontSize(22).fillColor("#1d4ed8").text("Dataset Finder", { align: "center" });
  doc.fontSize(10).fillColor("#6b7280").text("AI-Powered Dataset Discovery", { align: "center" });
  doc.moveDown();
  doc.moveTo(50, doc.y).lineTo(550, doc.y).strokeColor("#e5e7eb").stroke();
  doc.moveDown();
  doc.fontSize(18).fillColor("#111827").text(dataset.name);
  doc.fontSize(11).fillColor("#6b7280").text(`Source: ${dataset.source}   |   License: ${dataset.license}   |   Year: ${dataset.year || dataset.lastUpdated}`);
  doc.moveDown(0.5);
  doc.fontSize(13).fillColor("#1d4ed8").text(`Reliability Score: ${dataset.reliabilityScore}/10 — ${dataset.reliabilityLabel}`);
  doc.moveDown(0.5);
  doc.fontSize(11).fillColor("#374151").text("Description:", { underline: true });
  doc.fontSize(10).fillColor("#4b5563").text(dataset.description);
  doc.moveDown(0.5);
  doc.fontSize(11).fillColor("#374151").text("Details:", { underline: true });
  doc.fontSize(10).fillColor("#4b5563").text(`Size: ${dataset.size} | Format: ${dataset.format} | Updated: ${dataset.lastUpdated} | Citations: ${dataset.citedInPapers?.toLocaleString()} | URL: ${dataset.url}`);
  doc.moveDown(0.5);
  if (dataset.papers?.length) {
    doc.fontSize(11).fillColor("#374151").text("Recent Research Papers (Newest First):", { underline: true });
    [...dataset.papers].sort((a,b)=>(b.year||0)-(a.year||0)).forEach((p, i) => {
      doc.fontSize(10).fillColor("#4b5563").text(`${i+1}. ${p.title} (${p.year})`).text(`   ${p.authors} · ${p.venue} · ${p.citations?.toLocaleString()} citations`);
    });
    doc.moveDown(0.5);
  }
  if (dataset.notes) {
    doc.fontSize(11).fillColor("#374151").text("My Notes:", { underline: true });
    doc.fontSize(10).fillColor("#4b5563").text(dataset.notes);
  }
  doc.moveDown();
  doc.fontSize(9).fillColor("#9ca3af").text(`Generated by Dataset Finder · ${new Date().toLocaleDateString()}`, { align: "center" });
  doc.end();
});

// ── Start ─────────────────────────────────────────────────────────────────────
app.listen(PORT, "0.0.0.0", () => console.log(`Dataset Finder backend running on port ${PORT}`));
