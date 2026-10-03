require("dotenv").config();
const path = require("path");
const express = require("express");
const cors = require("cors");

const { initDb } = require("./db");
const scanRoutes = require("./routes/scan");
const historyRoutes = require("./routes/history");

const app = express();
const PORT = process.env.PORT || 3000;

app.use(cors());
app.use(express.json({ limit: "1mb" }));
app.use(express.static(path.join(__dirname, "..", "public")));

app.get("/api/health", (req, res) => res.json({ ok: true }));
app.use("/api", scanRoutes);
app.use("/api", historyRoutes);

app.listen(PORT, async () => {
  await initDb().catch((e) => console.error("[db] init failed:", e.message));
  console.log(`qr-url-guard listening on port ${PORT}`);
});
