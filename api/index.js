const express = require("express");
const fs = require("fs");
const crypto = require("crypto");
const path = require("path");

const app = express();
app.use(express.json());
app.use(express.static(path.join(__dirname, "../admin")));

const DB = path.join(__dirname, "licenses.json");
const ADMIN_TOKEN = process.env.ADMIN_TOKEN || "changeme";

function load() {
  if (!fs.existsSync(DB)) fs.writeFileSync(DB, "[]");
  return JSON.parse(fs.readFileSync(DB, "utf8"));
}

function save(data) {
  fs.writeFileSync(DB, JSON.stringify(data, null, 2));
}

function genKey() {
  const seg = () => crypto.randomBytes(2).toString("hex").toUpperCase();
  return `${seg()}-${seg()}-${seg()}-${seg()}`;
}

function adminAuth(req, res, next) {
  if (req.headers["x-admin-token"] !== ADMIN_TOKEN)
    return res.status(403).json({ error: "forbidden" });
  next();
}

// Мод проверяет лицензию
app.post("/check", (req, res) => {
  const { key, hwid } = req.body;
  if (!key || !hwid) return res.json({ success: false, reason: "missing_fields" });

  const db = load();
  const entry = db.find(e => e.key === key);

  if (!entry) return res.json({ success: false, reason: "invalid_key" });
  if (entry.status === "banned") return res.json({ success: false, reason: "banned" });

  if (!entry.hwid) {
    entry.hwid = hwid;
    save(db);
    return res.json({ success: true, bound: true });
  }

  if (entry.hwid === hwid) return res.json({ success: true, bound: false });

  return res.json({ success: false, reason: "invalid_hwid" });
});

// --- Админ-роуты ---

// Список всех лицензий
app.get("/admin/list", adminAuth, (req, res) => {
  res.json(load());
});

// Создать ключ
app.post("/admin/create", adminAuth, (req, res) => {
  const { note } = req.body;
  const db = load();
  const entry = { key: genKey(), hwid: null, status: "active", note: note || "" };
  db.push(entry);
  save(db);
  res.json(entry);
});

// Бан / разбан
app.post("/admin/ban", adminAuth, (req, res) => {
  const { key, ban } = req.body;
  const db = load();
  const entry = db.find(e => e.key === key);
  if (!entry) return res.status(404).json({ error: "not found" });
  entry.status = ban ? "banned" : "active";
  save(db);
  res.json({ ok: true });
});

// Сброс HWID
app.post("/admin/reset", adminAuth, (req, res) => {
  const { key } = req.body;
  const db = load();
  const entry = db.find(e => e.key === key);
  if (!entry) return res.status(404).json({ error: "not found" });
  entry.hwid = null;
  save(db);
  res.json({ ok: true });
});

// Удалить ключ
app.post("/admin/delete", adminAuth, (req, res) => {
  const { key } = req.body;
  let db = load();
  db = db.filter(e => e.key !== key);
  save(db);
  res.json({ ok: true });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`API running on :${PORT}`));
