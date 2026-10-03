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
  await pool.query(`CREATE INDEX IF NOT EXISTS idx_scans_created_at ON scans (created_at DESC);`);
  console.log("[db] Ready.");
}

async function saveScan({ url, hostname, verdict, score, result }) {
  if (!pool) return null;
  const { rows } = await pool.query(
    `INSERT INTO scans (url, hostname, verdict, score, result) VALUES ($1, $2, $3, $4, $5) RETURNING id, created_at`,
    [url, hostname, verdict, score, result]
  );
  return rows[0];
}

async function listScans(limit = 50) {
  if (!pool) return [];
  const { rows } = await pool.query(
    `SELECT id, url, hostname, verdict, score, created_at FROM scans ORDER BY created_at DESC LIMIT $1`,
    [limit]
  );
  return rows;
}

async function getScan(id) {
  if (!pool) return null;
  const { rows } = await pool.query(`SELECT * FROM scans WHERE id = $1`, [id]);
  return rows[0] || null;
}

module.exports = { pool, initDb, saveScan, listScans, getScan };
