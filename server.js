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

const app = express();
app.use(express.json());
app.use(cors({ origin: "*", methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"], allowedHeaders: ["Content-Type", "Authorization"] }));
app.options("*", cors());
app.use(passport.initialize());

// ── ENV ───────────────────────────────────────────────────────────────────────
const ANTHROPIC_API_KEY = process.env.ANTHROPIC_API_KEY;
const MONGODB_URI       = process.env.MONGODB_URI;
const JWT_SECRET        = process.env.JWT_SECRET || "dataset-finder-secret-key-change-this";
const GOOGLE_CLIENT_ID  = process.env.GOOGLE_CLIENT_ID;
const GOOGLE_SECRET     = process.env.GOOGLE_CLIENT_SECRET;
const GITHUB_CLIENT_ID  = process.env.GITHUB_CLIENT_ID;
const GITHUB_SECRET     = process.env.GITHUB_CLIENT_SECRET;
const FRONTEND_URL      = process.env.FRONTEND_URL || "https://dataset-finder-frontend.vercel.app";
const PORT              = parseInt(process.env.PORT) || 3001;

console.log("API Key loaded:", ANTHROPIC_API_KEY ? "YES" : "NO - MISSING!");
console.log("MongoDB URI loaded:", MONGODB_URI ? "YES" : "NO - MISSING!");

const client = new Anthropic({ apiKey: ANTHROPIC_API_KEY });

// ── MongoDB ───────────────────────────────────────────────────────────────────
mongoose.connect(MONGODB_URI).then(() => console.log("MongoDB connected!")).catch(err => console.error("MongoDB error:", err));

// User Schema
const userSchema = new mongoose.Schema({
  name:         { type: String, required: true },
  email:        { type: String, required: true, unique: true },
  password:     { type: String },
  provider:     { type: String, default: "email" }, // email, google, github
  providerId:   { type: String },
  avatar:       { type: String },
  createdAt:    { type: Date, default: Date.now },
});
const User = mongoose.model("User", userSchema);

// Collection Schema
const collectionSchema = new mongoose.Schema({
  userId:     { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true },
  name:       { type: String, required: true },
  color:      { type: String, default: "#3b82f6" },
  createdAt:  { type: Date, default: Date.now },
});
const Collection = mongoose.model("Collection", collectionSchema);

// Saved Dataset Schema
const savedDatasetSchema = new mongoose.Schema({
  userId:           { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true },
  collectionId:     { type: mongoose.Schema.Types.ObjectId, ref: "Collection", default: null },
  name:             { type: String, required: true },
  source:           { type: String },
  url:              { type: String },
  description:      { type: String },
  size:             { type: String },
  format:           { type: String },
  reliabilityScore: { type: Number },
  reliabilityLabel: { type: String },
  reliabilityFactors: { type: Object },
  reliabilityReasons: [String],
  citedInPapers:    { type: Number },
  papers:           [Object],
  tags:             [String],
  lastUpdated:      { type: String },
  license:          { type: String },
  notes:            { type: String, default: "" },
  savedAt:          { type: Date, default: Date.now },
});
const SavedDataset = mongoose.model("SavedDataset", savedDatasetSchema);

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
  } catch (err) {
    return res.status(401).json({ error: "Invalid token" });
  }
};

// ── Passport Google ───────────────────────────────────────────────────────────
if (GOOGLE_CLIENT_ID && GOOGLE_SECRET) {
  passport.use(new GoogleStrategy({
    clientID: GOOGLE_CLIENT_ID,
    clientSecret: GOOGLE_SECRET,
    callbackURL: `https://dataset-finder-backend-production.up.railway.app/auth/google/callback`,
  }, async (accessToken, refreshToken, profile, done) => {
    try {
      let user = await User.findOne({ email: profile.emails[0].value });
      if (!user) {
        user = await User.create({
          name: profile.displayName,
          email: profile.emails[0].value,
          provider: "google",
          providerId: profile.id,
          avatar: profile.photos[0]?.value,
        });
      }
      done(null, user);
    } catch (err) { done(err); }
  }));
}

// ── Passport GitHub ───────────────────────────────────────────────────────────
if (GITHUB_CLIENT_ID && GITHUB_SECRET) {
  passport.use(new GitHubStrategy({
    clientID: GITHUB_CLIENT_ID,
    clientSecret: GITHUB_SECRET,
    callbackURL: `https://dataset-finder-backend-production.up.railway.app/auth/github/callback`,
    scope: ["user:email"],
  }, async (accessToken, refreshToken, profile, done) => {
    try {
      const email = profile.emails?.[0]?.value || `${profile.username}@github.com`;
      let user = await User.findOne({ email });
      if (!user) {
        user = await User.create({
          name: profile.displayName || profile.username,
          email,
          provider: "github",
          providerId: profile.id,
          avatar: profile.photos[0]?.value,
        });
      }
      done(null, user);
    } catch (err) { done(err); }
  }));
}

passport.serializeUser((user, done) => done(null, user.id));
passport.deserializeUser(async (id, done) => {
  const user = await User.findById(id);
  done(null, user);
});

// ── Rate Limiter ──────────────────────────────────────────────────────────────
const rateLimitMap = new Map();
const MAX_SEARCHES_PER_DAY = 5;

function getRateLimitInfo(ip) {
  const now = Date.now();
  const entry = rateLimitMap.get(ip);
  if (!entry || now > entry.resetAt) {
    const resetAt = new Date();
    resetAt.setHours(24, 0, 0, 0);
    const newEntry = { count: 0, resetAt: resetAt.getTime() };
    rateLimitMap.set(ip, newEntry);
    return newEntry;
  }
  return entry;
}

function getUserIp(req) {
  return req.headers["x-forwarded-for"]?.split(",")[0].trim() || req.socket.remoteAddress || "unknown";
}

// ── System Prompt ─────────────────────────────────────────────────────────────
const SYSTEM_PROMPT = `You are a dataset discovery expert with broad knowledge of datasets from Kaggle, HuggingFace, UCI ML Repository, Zenodo, PapersWithCode, GitHub, Google Dataset Search, government open data portals, and thousands of published research papers across all domains.

When a user searches for a dataset topic, respond ONLY with a valid JSON array (no markdown, no backticks, no extra text) containing exactly 3 dataset recommendations.

Each dataset object must have these exact keys:
- "rank": number (1, 2, or 3)
- "name": string
- "source": string
- "url": string (a real plausible URL)
- "description": string (2-3 sentences)
- "size": string
- "format": string
- "reliabilityScore": number from 1.0 to 10.0 (weighted average of 7 factors, one decimal)
- "reliabilityLabel": one of: "Excellent", "Very Good", "Good", "Fair", "Poor"
- "reliabilityFactors": object with exactly these 7 keys each scored 1-10:
    "citationCount", "sourceCredibility", "documentation", "licenseClarity", "communityAdoption", "maintenance", "biasAndDiversity"
- "reliabilityReasons": array of exactly 3 strings
- "citedInPapers": number
- "papers": array of exactly 3 objects each with: "title", "authors", "year", "venue", "citations"
- "tags": array of 4-5 strings
- "lastUpdated": string
- "license": string

Rank by reliabilityScore descending. Return ONLY the raw JSON array, nothing else.`;

// ════════════════════════════════════════════════════════════════════════════
// ROUTES
// ════════════════════════════════════════════════════════════════════════════

// Health check
app.get("/health", (req, res) => res.json({ status: "ok", timestamp: new Date().toISOString() }));

// ── Auth: Email/Password ──────────────────────────────────────────────────────
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
  } catch (err) {
    res.status(500).json({ error: "Registration failed" });
  }
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
  } catch (err) {
    res.status(500).json({ error: "Login failed" });
  }
});

// ── Auth: Google OAuth ────────────────────────────────────────────────────────
app.get("/auth/google", passport.authenticate("google", { scope: ["profile", "email"] }));
app.get("/auth/google/callback", passport.authenticate("google", { session: false, failureRedirect: `${FRONTEND_URL}/login?error=google` }), (req, res) => {
  const token = generateToken(req.user._id);
  res.redirect(`${FRONTEND_URL}/auth/callback?token=${token}&name=${encodeURIComponent(req.user.name)}&email=${encodeURIComponent(req.user.email)}`);
});

// ── Auth: GitHub OAuth ────────────────────────────────────────────────────────
app.get("/auth/github", passport.authenticate("github", { scope: ["user:email"] }));
app.get("/auth/github/callback", passport.authenticate("github", { session: false, failureRedirect: `${FRONTEND_URL}/login?error=github` }), (req, res) => {
  const token = generateToken(req.user._id);
  res.redirect(`${FRONTEND_URL}/auth/callback?token=${token}&name=${encodeURIComponent(req.user.name)}&email=${encodeURIComponent(req.user.email)}`);
});

// ── Auth: Get current user ────────────────────────────────────────────────────
app.get("/auth/me", authMiddleware, (req, res) => {
  res.json({ id: req.user._id, name: req.user.name, email: req.user.email, avatar: req.user.avatar });
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
  const { query } = req.body;
  if (!query?.trim()) return res.status(400).json({ error: "Query is required." });
  if (query.trim().length > 200) return res.status(400).json({ error: "Query too long." });

  const ip = getUserIp(req);
  const info = getRateLimitInfo(ip);
  if (info.count >= MAX_SEARCHES_PER_DAY) {
    const resetIn = Math.ceil((info.resetAt - Date.now()) / 1000 / 60);
    return res.status(429).json({ error: `You've used all 5 free searches for today. Resets in ${resetIn} minutes.`, resetInMinutes: resetIn });
  }
  info.count += 1;

  let datasets = null;

  try {
    const message = await client.messages.create({
      model: "claude-sonnet-4-5",
      max_tokens: 4000,
      system: SYSTEM_PROMPT,
      tools: [{ type: "web_search_20250305", name: "web_search" }],
      messages: [{ role: "user", content: "Search the internet right now and find the best 3 real datasets for: " + query.trim() }],
    });
    const text = (message.content || []).filter(c => c.type === "text").map(c => c.text || "").join("");
    if (text) {
      const jsonMatch = text.match(/\[[\s\S]*\]/);
      if (jsonMatch) datasets = JSON.parse(jsonMatch[0]);
    }
  } catch (err) {
    console.log("Live search failed, trying fallback:", err.message);
  }

  if (!datasets) {
    try {
      const fallback = await client.messages.create({
        model: "claude-sonnet-4-5",
        max_tokens: 4000,
        system: SYSTEM_PROMPT,
        messages: [{ role: "user", content: "Find the best 3 datasets for: " + query.trim() }],
      });
      const text = (fallback.content || []).filter(c => c.type === "text").map(c => c.text || "").join("");
      if (text) {
        const jsonMatch = text.match(/\[[\s\S]*\]/);
        if (jsonMatch) datasets = JSON.parse(jsonMatch[0]);
      }
    } catch (err) {
      console.log("Fallback failed:", err.message);
    }
  }

  if (!datasets) {
    info.count = Math.max(0, info.count - 1);
    return res.status(500).json({ error: "Search failed. Please try again." });
  }

  const remaining = Math.max(0, MAX_SEARCHES_PER_DAY - info.count);
  return res.json({ datasets, remaining, used: info.count, max: MAX_SEARCHES_PER_DAY });
});

// ── Collections ───────────────────────────────────────────────────────────────
app.get("/api/collections", authMiddleware, async (req, res) => {
  const collections = await Collection.find({ userId: req.user._id }).sort({ createdAt: -1 });
  res.json(collections);
});

app.post("/api/collections", authMiddleware, async (req, res) => {
  const { name, color } = req.body;
  if (!name?.trim()) return res.status(400).json({ error: "Collection name required" });
  const collection = await Collection.create({ userId: req.user._id, name: name.trim(), color: color || "#3b82f6" });
  res.json(collection);
});

app.delete("/api/collections/:id", authMiddleware, async (req, res) => {
  await Collection.deleteOne({ _id: req.params.id, userId: req.user._id });
  await SavedDataset.deleteMany({ collectionId: req.params.id, userId: req.user._id });
  res.json({ success: true });
});

// ── Saved Datasets ────────────────────────────────────────────────────────────
app.get("/api/saved", authMiddleware, async (req, res) => {
  const { collectionId } = req.query;
  const filter = { userId: req.user._id };
  if (collectionId) filter.collectionId = collectionId;
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
  const { notes } = req.body;
  const dataset = await SavedDataset.findOneAndUpdate(
    { _id: req.params.id, userId: req.user._id },
    { notes },
    { new: true }
  );
  res.json(dataset);
});

app.put("/api/saved/:id/collection", authMiddleware, async (req, res) => {
  const { collectionId } = req.body;
  const dataset = await SavedDataset.findOneAndUpdate(
    { _id: req.params.id, userId: req.user._id },
    { collectionId },
    { new: true }
  );
  res.json(dataset);
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
  res.setHeader("Content-Disposition", `attachment; filename="${dataset.name.replace(/[^a-z0-9]/gi, "_")}.pdf"`);

  const doc = new PDFDocument({ margin: 50 });
  doc.pipe(res);

  // Header
  doc.fontSize(24).fillColor("#1d4ed8").text("Dataset Finder", { align: "center" });
  doc.fontSize(10).fillColor("#6b7280").text("AI-Powered Dataset Discovery", { align: "center" });
  doc.moveDown();
  doc.moveTo(50, doc.y).lineTo(550, doc.y).strokeColor("#e5e7eb").stroke();
  doc.moveDown();

  // Dataset name
  doc.fontSize(20).fillColor("#111827").text(dataset.name);
  doc.fontSize(12).fillColor("#6b7280").text(`Source: ${dataset.source}   |   License: ${dataset.license}`);
  doc.moveDown(0.5);

  // Reliability Score
  doc.fontSize(14).fillColor("#1d4ed8").text(`Reliability Score: ${dataset.reliabilityScore}/10 — ${dataset.reliabilityLabel}`);
  doc.moveDown(0.5);

  // Description
  doc.fontSize(12).fillColor("#374151").text("Description:", { underline: true });
  doc.fontSize(11).fillColor("#4b5563").text(dataset.description);
  doc.moveDown(0.5);

  // Details
  doc.fontSize(12).fillColor("#374151").text("Details:", { underline: true });
  doc.fontSize(11).fillColor("#4b5563")
    .text(`Size: ${dataset.size}`)
    .text(`Format: ${dataset.format}`)
    .text(`Last Updated: ${dataset.lastUpdated}`)
    .text(`Citations: ${dataset.citedInPapers?.toLocaleString()}`)
    .text(`URL: ${dataset.url}`);
  doc.moveDown(0.5);

  // Tags
  doc.fontSize(12).fillColor("#374151").text("Tags:", { underline: true });
  doc.fontSize(11).fillColor("#4b5563").text((dataset.tags || []).join(", "));
  doc.moveDown(0.5);

  // Reliability Factors
  if (dataset.reliabilityFactors) {
    doc.fontSize(12).fillColor("#374151").text("Reliability Factor Breakdown:", { underline: true });
    const factors = {
      citationCount: "Citation Count",
      sourceCredibility: "Source Credibility",
      documentation: "Documentation",
      licenseClarity: "License Clarity",
      communityAdoption: "Community Adoption",
      maintenance: "Maintenance",
      biasAndDiversity: "Bias & Diversity",
    };
    Object.entries(factors).forEach(([key, label]) => {
      const val = dataset.reliabilityFactors[key] || 0;
      doc.fontSize(11).fillColor("#4b5563").text(`${label}: ${val}/10`);
    });
    doc.moveDown(0.5);
  }

  // Papers
  if (dataset.papers?.length) {
    doc.fontSize(12).fillColor("#374151").text("Cited in Research Papers:", { underline: true });
    dataset.papers.forEach((p, i) => {
      doc.fontSize(11).fillColor("#4b5563")
        .text(`${i + 1}. ${p.title}`)
        .text(`   ${p.authors} · ${p.year} · ${p.venue} · ${p.citations?.toLocaleString()} citations`);
    });
    doc.moveDown(0.5);
  }

  // Notes
  if (dataset.notes) {
    doc.fontSize(12).fillColor("#374151").text("My Notes:", { underline: true });
    doc.fontSize(11).fillColor("#4b5563").text(dataset.notes);
    doc.moveDown(0.5);
  }

  // Footer
  doc.moveDown();
  doc.fontSize(9).fillColor("#9ca3af").text(`Generated by Dataset Finder · ${new Date().toLocaleDateString()}`, { align: "center" });

  doc.end();
});

// ── Start ─────────────────────────────────────────────────────────────────────
app.listen(PORT, "0.0.0.0", () => console.log(`Dataset Finder backend running on port ${PORT}`));
