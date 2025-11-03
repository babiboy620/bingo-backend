// server.js
require("dotenv").config();
const express = require("express");
const cors = require("cors");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const { pool } = require("./db");

const app = express();
app.use(cors());
app.use(express.json());

const PORT = process.env.PORT || 10000;
const JWT_SECRET = process.env.JWT_SECRET || "default_secret";

// ✅ Middleware to authenticate users via JWT
function authenticate(req, res, next) {
  const authHeader = req.headers.authorization;
  if (!authHeader) return res.status(401).json({ error: "Missing token" });

  const token = authHeader.split(" ")[1];
  try {
    const user = jwt.verify(token, JWT_SECRET);
    req.user = user;
    next();
  } catch {
    res.status(403).json({ error: "Invalid token" });
  }
}

// ✅ Register a new user
app.post("/api/register", async (req, res) => {
  try {
    const { phone, password, role, name } = req.body;
    const hashed = await bcrypt.hash(password, 10);

    const result = await pool.query(
      "INSERT INTO users (phone, passwordhash, role, name) VALUES ($1, $2, $3, $4) RETURNING id, phone, role, name",
      [phone, hashed, role, name]
    );

    res.json({ success: true, user: result.rows[0] });
  } catch (err) {
    console.error(err.message);
    res.status(500).json({ error: "Registration failed" });
  }
});

// ✅ Login
app.post("/api/login", async (req, res) => {
  try {
    const { phone, password } = req.body;
    const result = await pool.query("SELECT * FROM users WHERE phone=$1", [
      phone,
    ]);
    const user = result.rows[0];

    if (!user) return res.status(400).json({ error: "User not found" });
    const valid = await bcrypt.compare(password, user.passwordhash);
    if (!valid) return res.status(401).json({ error: "Invalid password" });

    const token = jwt.sign(
      { id: user.id, phone: user.phone, role: user.role },
      JWT_SECRET,
      { expiresIn: "7d" }
    );

    res.json({ success: true, token, user });
  } catch (err) {
    console.error(err.message);
    res.status(500).json({ error: "Login failed" });
  }
});

// ✅ Create a game
app.post("/api/games", authenticate, async (req, res) => {
  try {
    const { players, pot, entryfee, winmode } = req.body;

    const result = await pool.query(
      `INSERT INTO games (agentid, ownerid, players, pot, entryfee, winmode)
       VALUES ($1, $2, $3, $4, $5, $6)
       RETURNING *`,
      [req.user.id, req.user.id, players, pot, entryfee, winmode]
    );

    res.json({ success: true, game: result.rows[0] });
  } catch (err) {
    console.error(err.message);
    res.status(500).json({ error: "Failed to create game" });
  }
});

// ✅ Get all games
app.get("/api/games", authenticate, async (req, res) => {
  try {
    const result = await pool.query(
      "SELECT * FROM games ORDER BY createdat DESC"
    );
    res.json(result.rows);
  } catch (err) {
    console.error(err.message);
    res.status(500).json({ error: "Failed to fetch games" });
  }
});

// ✅ Update called numbers
app.put("/api/games/:id/called", authenticate, async (req, res) => {
  try {
    const { numbers } = req.body;
    await pool.query("UPDATE games SET called=$1 WHERE id=$2", [
      JSON.stringify(numbers || []),
      req.params.id,
    ]);
    res.json({ success: true });
  } catch (err) {
    console.error(err.message);
    res.status(500).json({ error: "Failed to update called numbers" });
  }
});

// ✅ Mark game as completed
app.put("/api/games/:id/complete", authenticate, async (req, res) => {
  try {
    const { profit, winnermoney } = req.body;
    await pool.query(
      "UPDATE games SET profit=$1, winnermoney=$2, status='completed' WHERE id=$3",
      [profit, winnermoney, req.params.id]
    );
    res.json({ success: true });
  } catch (err) {
    console.error(err.message);
    res.status(500).json({ error: "Failed to complete game" });
  }
});

// ✅ Default route
app.get("/", (req, res) => {
  res.send("🎯 Bingo Backend is running successfully on Render!");
});

// ✅ Start server
app.listen(PORT, () => {
  console.log(`🚀 Server running on port ${PORT}`);
});
