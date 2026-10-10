const { Pool } = require("pg");

const connectionString = process.env.DATABASE_URL;

const pool = connectionString
  ? new Pool({
      connectionString,
      ssl: connectionString.includes("localhost") ? false : { rejectUnauthorized: false },
    })
  : null;

async function initDb() {
  if (!pool) {
    console.warn("[db] No DATABASE_URL set — scan history will not be persisted.");
    return;
  }
  await pool.query(`
    CREATE TABLE IF NOT EXISTS scans (
      id SERIAL PRIMARY KEY,
      url TEXT NOT NULL,
      hostname TEXT,
      verdict TEXT NOT NULL,
      score INTEGER NOT NULL,
      result JSONB NOT NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT now()
    );
  `);
    await pool.query(`
    CREATE TABLE IF NOT EXISTS scans (
      id SERIAL PRIMARY KEY,
      url TEXT NOT NULL,
      hostname TEXT,
      verdict TEXT NOT NULL,
      score INTEGER NOT NULL,
      result JSONB NOT NULL,
      session_id TEXT,
      created_at TIMESTAMPTZ NOT NULL DEFAULT now()
    );
  `);
  await pool.query(`ALTER TABLE scans ADD COLUMN IF NOT EXISTS session_id TEXT;`);
  await pool.query(`CREATE INDEX IF NOT EXISTS idx_scans_created_at ON scans (created_at DESC);`);
  await pool.query(`CREATE INDEX IF NOT EXISTS idx_scans_session_id ON scans (session_id);`);
  console.log("[db] Ready.");
}

async function saveScan({ url, hostname, verdict, score, result, sessionId }) {
  if (!pool) return null;
  const { rows } = await pool.query(
    `INSERT INTO scans (url, hostname, verdict, score, result, session_id) VALUES ($1, $2, $3, $4, $5, $6) RETURNING id, created_at`,
    [url, hostname, verdict, score, result, sessionId || null]
  );
  return rows[0];
}

async function listScans(sessionId, limit = 50) {
  if (!pool) return [];
  const { rows } = await pool.query(
    `SELECT id, url, hostname, verdict, score, created_at FROM scans WHERE session_id = $1 ORDER BY created_at DESC LIMIT $2`,
    [sessionId, limit]
  );
  return rows;
}

async function getScan(id, sessionId) {
  if (!pool) return null;
  const { rows } = await pool.query(`SELECT * FROM scans WHERE id = $1 AND session_id = $2`, [id, sessionId]);
  return rows[0] || null;
}
}
  return rows[0] || null;
}

module.exports = { pool, initDb, saveScan, listScans, getScan };
