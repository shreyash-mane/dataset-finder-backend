const express = require("express");
const cors = require("cors");
const Anthropic = require("@anthropic-ai/sdk");

const app = express();
app.use(express.json());
app.use(cors({ origin: process.env.FRONTEND_URL || "*" }));

const client = new Anthropic({ apiKey: process.env.ANTHROPIC_API_KEY });

// ── Rate limiter: 5 searches per user per day (stored in memory) ──────────────
// In production you can swap this for Redis for persistence across restarts
const rateLimitMap = new Map(); // { ip -> { count, resetAt } }
const MAX_SEARCHES_PER_DAY = 5;

function getRateLimitInfo(ip) {
  const now = Date.now();
  const entry = rateLimitMap.get(ip);

  if (!entry || now > entry.resetAt) {
    // First search today or day has rolled over
    const resetAt = new Date();
    resetAt.setHours(24, 0, 0, 0); // midnight tonight
    const newEntry = { count: 0, resetAt: resetAt.getTime() };
    rateLimitMap.set(ip, newEntry);
    return newEntry;
  }
  return entry;
}

function getUserIp(req) {
  return (
    req.headers["x-forwarded-for"]?.split(",")[0].trim() ||
    req.socket.remoteAddress ||
    "unknown"
  );
}

// ── System prompt ─────────────────────────────────────────────────────────────
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

// ── Routes ────────────────────────────────────────────────────────────────────

// Health check
app.get("/health", (req, res) => {
  res.json({ status: "ok", timestamp: new Date().toISOString() });
});

// Check remaining searches for this IP
app.get("/api/rate-limit", (req, res) => {
  const ip = getUserIp(req);
  const info = getRateLimitInfo(ip);
  const remaining = Math.max(0, MAX_SEARCHES_PER_DAY - info.count);
  const resetIn = Math.ceil((info.resetAt - Date.now()) / 1000 / 60); // minutes
  res.json({ remaining, used: info.count, max: MAX_SEARCHES_PER_DAY, resetInMinutes: resetIn });
});

// Main search endpoint
app.post("/api/search", async (req, res) => {
  const { query } = req.body;

  if (!query || typeof query !== "string" || !query.trim()) {
    return res.status(400).json({ error: "Query is required." });
  }

  if (query.trim().length > 200) {
    return res.status(400).json({ error: "Query too long. Max 200 characters." });
  }

  // Check rate limit
  const ip = getUserIp(req);
  const info = getRateLimitInfo(ip);

  if (info.count >= MAX_SEARCHES_PER_DAY) {
    const resetIn = Math.ceil((info.resetAt - Date.now()) / 1000 / 60);
    return res.status(429).json({
      error: `You've used all 5 free searches for today. Resets in ${resetIn} minutes.`,
      resetInMinutes: resetIn,
    });
  }

  // Increment count BEFORE the API call to prevent abuse
  info.count += 1;

  try {
    const message = await client.messages.create({
      model: "claude-sonnet-4-5",
      max_tokens: 4000,
      system: SYSTEM_PROMPT,
      tools: [{ type: "web_search_20250305", name: "web_search" }],
      messages: [
        {
          role: "user",
          content:
            "Search the internet right now and find the best 3 real datasets for: " +
            query.trim() +
            ". Search Kaggle, HuggingFace, UCI ML Repository, PapersWithCode, Zenodo, and Google Dataset Search to find real existing datasets with real URLs, real paper citations, and accurate metadata.",
        },
      ],
    });

    const text = (message.content || [])
      .filter((c) => c.type === "text")
      .map((c) => c.text || "")
      .join("");

    if (!text) {
      return res.status(500).json({ error: "Empty response from AI. Please try again." });
    }

    const jsonMatch = text.match(/\[[\s\S]*\]/);
    if (!jsonMatch) {
      return res.status(500).json({ error: "Could not parse AI response. Please try again." });
    }

    const datasets = JSON.parse(jsonMatch[0]);
    const remaining = Math.max(0, MAX_SEARCHES_PER_DAY - info.count);

    return res.json({ datasets, remaining, used: info.count, max: MAX_SEARCHES_PER_DAY });
  } catch (err) {
    // If the API call failed, refund the search
    info.count = Math.max(0, info.count - 1);
    console.error("Anthropic API error:", err.message);
    return res.status(500).json({ error: "Search failed. Please try again." });
  }
});

// ── Start ─────────────────────────────────────────────────────────────────────
const PORT = process.env.PORT || 3001;
app.listen(PORT, () => {
  console.log(`Dataset Finder backend running on port ${PORT}`);
});
