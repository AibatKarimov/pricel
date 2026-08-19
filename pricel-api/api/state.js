import { createClient } from "@libsql/client";
import { createHash } from "node:crypto";

const ALLOWED_ORIGINS = [
  "https://aibatkarimov.github.io",
  "http://localhost:8940",
  "http://localhost:8939",
  "http://localhost:8938",
];

function setCors(req, res) {
  var origin = req.headers.origin;
  if (origin && ALLOWED_ORIGINS.indexOf(origin) !== -1) {
    res.setHeader("Access-Control-Allow-Origin", origin);
  }
  res.setHeader("Access-Control-Allow-Methods", "GET, PUT, OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type");
  res.setHeader("Vary", "Origin");
}

function hashCode(code) {
  return createHash("sha256").update(String(code)).digest("hex");
}

export default async function handler(req, res) {
  setCors(req, res);

  if (req.method === "OPTIONS") {
    res.status(204).end();
    return;
  }

  var client = createClient({
    url: process.env.TURSO_DATABASE_URL,
    authToken: process.env.TURSO_AUTH_TOKEN,
  });

  try {
    if (req.method === "GET") {
      var code = req.query.code;
      if (!code || typeof code !== "string") {
        res.status(400).json({ error: "missing_code" });
        return;
      }
      var hash = hashCode(code);
      var result = await client.execute({
        sql: "SELECT data, updated_at FROM states WHERE code_hash = ?",
        args: [hash],
      });
      if (result.rows.length === 0) {
        res.status(404).json({ error: "not_found" });
        return;
      }
      res.status(200).json({ data: result.rows[0].data, updatedAt: result.rows[0].updated_at });
      return;
    }

    if (req.method === "PUT") {
      var body = req.body || {};
      var putCode = body.code;
      var data = body.data;
      if (!putCode || typeof putCode !== "string") {
        res.status(400).json({ error: "missing_code" });
        return;
      }
      if (typeof data !== "string") {
        res.status(400).json({ error: "missing_data" });
        return;
      }
      if (data.length > 2000000) {
        res.status(413).json({ error: "too_large" });
        return;
      }
      var putHash = hashCode(putCode);
      var updatedAt = new Date().toISOString();
      await client.execute({
        sql:
          "INSERT INTO states (code_hash, data, updated_at) VALUES (?, ?, ?) " +
          "ON CONFLICT(code_hash) DO UPDATE SET data = excluded.data, updated_at = excluded.updated_at",
        args: [putHash, data, updatedAt],
      });
      res.status(200).json({ ok: true, updatedAt: updatedAt });
      return;
    }

    res.status(405).json({ error: "method_not_allowed" });
  } catch (err) {
    res.status(500).json({ error: "server_error", message: String((err && err.message) || err) });
  }
}
