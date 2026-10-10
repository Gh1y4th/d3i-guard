const express = require("express");
const router = express.Router();
const { listScans, getScan } = require("../db");

router.get("/history", async (req, res) => {
  const limit = Math.min(parseInt(req.query.limit, 10) || 50, 200);
  const sessionId = req.get("x-session-id") || null;
  if (!sessionId) return res.json([]);
  try {
    const rows = await listScans(sessionId, limit);
    res.json(rows);
  } catch (err) {
    res.status(500).json({ error: "Could not load history.", message: err.message });
  }
});

router.get("/history/:id", async (req, res) => {
  const sessionId = req.get("x-session-id") || null;
  if (!sessionId) return res.status(404).json({ error: "Scan not found." });
  try {
    const row = await getScan(req.params.id, sessionId);
    if (!row) return res.status(404).json({ error: "Scan not found." });
    res.json(row.result);
  } catch (err) {
    res.status(500).json({ error: "Could not load scan.", message: err.message });
  }
});
