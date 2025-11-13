// server.js — Full PostgreSQL version (Render-ready)
require("dotenv").config();
const express = require("express");
const cors = require("cors");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const { pool } = require("./db");
const PDFDocument = require("pdfkit");

const app = express();
app.use(cors());
app.use(express.json());

const PORT = process.env.PORT;
const JWT_SECRET = process.env.JWT_SECRET || "default_secret";

// ✅ JWT Middleware
function authenticate(role = null) {
  return (req, res, next) => {
    const authHeader = req.headers.authorization;
    if (!authHeader) return res.status(401).json({ error: "Missing token" });

    const token = authHeader.split(" ")[1];
    try {
      const user = jwt.verify(token, JWT_SECRET);
      if (role && user.role !== role)
        return res.status(403).json({ error: `Only ${role}s allowed` });
      req.user = user;
      next();
    } catch {
      res.status(403).json({ error: "Invalid token" });
    }
  };
}

// ✅ Create the first owner
app.post("/api/create-first-owner", async (req, res) => {
  try {
    const { phone, password, name } = req.body;
    if (!phone || !password)
      return res.status(400).json({ error: "Phone and password required" });

    const check = await pool.query("SELECT COUNT(*) FROM users WHERE role = 'owner'");
    if (parseInt(check.rows[0].count) > 0)
      return res.status(400).json({ error: "Owner already exists" });

    const hashed = await bcrypt.hash(password, 10);
    const result = await pool.query(
      `INSERT INTO users (phone, passwordhash, role, name, isactive)
       VALUES ($1, $2, 'owner', $3, TRUE)
       RETURNING id, phone, role, name`,
      [phone, hashed, name]
    );

    res.json({ success: true, user: result.rows[0] });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Failed to create owner", details: err.message });
  }
});

// ✅ Login
app.post("/api/login", async (req, res) => {
  try {
    const { phone, password } = req.body;
    const result = await pool.query("SELECT * FROM users WHERE phone=$1", [phone]);
    const user = result.rows[0];

    if (!user) return res.status(400).json({ error: "User not found" });
    if (!user.isactive) return res.status(403).json({ error: "Account is blocked" });

    const valid = await bcrypt.compare(password, user.passwordhash);
    if (!valid) return res.status(401).json({ error: "Invalid password" });

    const token = jwt.sign(
      { id: user.id, phone: user.phone, role: user.role, name: user.name },
      JWT_SECRET,
      { expiresIn: "7d" }
    );

    res.json({ success: true, token, user });
  } catch (err) {
    console.error(err.message);
    res.status(500).json({ error: "Login failed" });
  }
});

// ✅ Owner: Create Agent
app.post("/api/agents/create", authenticate, async (req, res) => {
  try {
    // Only owner can create agents
    if (req.user.role !== "owner")
      return res.status(403).json({ error: "Only owner can create agents" });

    const { phone, password, name } = req.body;
    if (!phone || !password)
      return res.status(400).json({ error: "Phone and password required" });

    const exists = await pool.query("SELECT id FROM users WHERE phone=$1", [phone]);
    if (exists.rows.length > 0)
      return res.status(400).json({ error: "Phone already registered" });

    const hashed = await bcrypt.hash(password, 10);
    const insert = await pool.query(
      `INSERT INTO users (phone, passwordhash, role, name, isactive)
       VALUES ($1, $2, 'agent', $3, TRUE)
       RETURNING id, phone, role, name`,
      [phone, hashed, name]
    );

    res.json({ success: true, agent: insert.rows[0] });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Failed to create agent", details: err.message });
  }
});

// ✅ Owner: Get all Agents
app.get("/api/agents", authenticate, async (req, res) => {
  try {
    if (req.user.role !== "owner")
      return res.status(403).json({ error: "Only owner can view agents" });

    const result = await pool.query(
      "SELECT id, phone, name, role, isactive FROM users WHERE role='agent' ORDER BY id ASC"
    );
    res.json(result.rows);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Failed to fetch agents", details: err.message });
  }
});

// ✅ Owner: Toggle (block/unblock) Agent
app.post("/api/agents/:id/toggle", authenticate, async (req, res) => {
  try {
    if (req.user.role !== "owner")
      return res.status(403).json({ error: "Only owner can toggle agents" });

    const id = req.params.id;
    const result = await pool.query("SELECT isactive FROM users WHERE id=$1 AND role='agent'", [id]);
    if (result.rows.length === 0)
      return res.status(404).json({ error: "Agent not found" });

    const newStatus = !result.rows[0].isactive;
    await pool.query("UPDATE users SET isactive=$1 WHERE id=$2", [newStatus, id]);

    res.json({ success: true, id, newStatus });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Failed to toggle agent", details: err.message });
  }
});

// ✅ Owner: Delete Agent
app.delete("/api/agents/:id", authenticate, async (req, res) => {
  try {
    if (req.user.role !== "owner")
      return res.status(403).json({ error: "Only owner can delete agents" });

    await pool.query("DELETE FROM users WHERE id=$1 AND role='agent'", [req.params.id]);
    res.json({ success: true });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Failed to delete agent", details: err.message });
  }
});


/// ✅ Agent: Create Game (stores cartelas, profit, winnermoney, and links them)
app.post("/api/games", authenticate("agent"), async (req, res) => {
  try {
    const {
      players,
      pot,
      entryfee,
      // accept both casings from different frontends
      winmode = req.body.winMode || req.body.winmode || null,
      cartelas = req.body.cartelas || [],
      winnermoney = req.body.winnerMoney || req.body.winnermoney || 0,
      profit = req.body.profit || 0,
      date = req.body.date || new Date(),
    } = req.body || {};

    // validate required
    if (!players || !pot || typeof entryfee === "undefined") {
      return res.status(400).json({ error: "players, pot and entryfee required" });
    }

    // find an owner id
    const ownerResult = await pool.query("SELECT id FROM users WHERE role='owner' LIMIT 1");
    if (ownerResult.rows.length === 0) {
      return res.status(500).json({ error: "No owner found in database" });
    }
    const ownerId = ownerResult.rows[0].id;

    // Insert including cartelas (JSONB), called (empty), winnermoney, profit, date
    const result = await pool.query(
      `INSERT INTO games
        (agentid, ownerid, players, pot, entryfee, winmode, cartelas, called, winnermoney, profit, date)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)
       RETURNING *`,
      [
        req.user.id,
        ownerId,
        players,
        pot,
        entryfee,
        winmode,
        JSON.stringify(cartelas || []), // JSONB
        JSON.stringify([]),             // called starts empty
        winnermoney,
        profit,
        date,
      ]
    );

    const gameId = result.rows[0].id;

    // ✅ NEW: link selected cartelas to this game and mark them as used
    if (cartelas && cartelas.length > 0) {
      await pool.query(
        `UPDATE cartelas 
         SET issued = true, gameid = $1 
         WHERE id = ANY($2)`,
        [gameId, cartelas]
      );
    }

    res.json({ success: true, game: result.rows[0] });
  } catch (err) {
    console.error("❌ Game creation error:", err);
    res.status(500).json({ error: "Failed to create game", details: err.message });
  }
});



// ✅ Agent: My Game History
app.get("/api/games/my-history", authenticate("agent"), async (req, res) => {
  try {
    const result = await pool.query(
      "SELECT * FROM games WHERE agentid=$1 ORDER BY date DESC",
      [req.user.id]
    );
    res.json({ success: true, games: result.rows });
  } catch (err) {
    console.error(err.message);
    res.status(500).json({ error: "Failed to fetch games" });
  }
});

// ✅ Owner: View All Games
app.get("/api/games", authenticate("owner"), async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT g.*, u.name AS agent_name, u.phone AS agent_phone
      FROM games g
      JOIN users u ON g.agentid = u.id
      ORDER BY u.name, g.date DESC
    `);
    res.json({ success: true, games: result.rows });
  } catch (err) {
    console.error(err.message);
    res.status(500).json({ error: "Failed to fetch all games" });
  }
});

// ✅ Owner: Download PDF Report
app.get("/api/reports/owner", authenticate("owner"), async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT g.*, u.name AS agent_name
      FROM games g
      JOIN users u ON g.agentid = u.id
      WHERE u.role = 'agent'
      ORDER BY u.name, g.date DESC
    `);

    const doc = new PDFDocument({ margin: 30 });
    res.setHeader("Content-Type", "application/pdf");
    res.setHeader("Content-Disposition", "attachment; filename=owner_report.pdf");
    doc.pipe(res);

    doc.fontSize(20).text("🎯 Bingo House — Owner Report", { align: "center" });
    doc.moveDown();
    doc.fontSize(12).text(`📅 Date: ${new Date().toLocaleDateString()}`);
    doc.moveDown();

    let currentAgent = null;
    let totalProfitAll = 0;
    let totalProfitAgent = 0;

    for (const g of result.rows) {
      if (currentAgent !== g.agent_name) {
        if (currentAgent !== null) {
          doc.font("Helvetica-Bold").text(`Total Profit: ${totalProfitAgent} birr`);
          doc.moveDown();
        }
        currentAgent = g.agent_name;
        totalProfitAgent = 0;
        doc.fontSize(16).text(`👤 Agent: ${g.agent_name}`, { underline: true });
        doc.moveDown(0.3);
        doc.fontSize(12).text("GameID | Date | Players | Pot | Winner | Profit");
        doc.moveDown(0.3);
      }

      totalProfitAgent += parseFloat(g.profit || 0);
      totalProfitAll += parseFloat(g.profit || 0);
      doc.text(
        `${g.id} | ${new Date(g.date).toLocaleDateString()} | ${g.players} | ${
          g.pot
        } | ${g.winnermoney} | ${g.profit}`
      );
    }

    doc.moveDown();
    doc.font("Helvetica-Bold").text(`Total Profit: ${totalProfitAgent} birr`);
    doc.moveDown(2);
    doc.text(`🏁 Grand Total Profit (All Agents): ${totalProfitAll} birr`, { align: "right" });
    doc.end();
  } catch (err) {
    console.error(err.message);
    res.status(500).json({ error: "Failed to generate PDF" });
  }
});

// ✅ Root test route
app.get("/", (req, res) => {
  res.send("🎯 Bingo Backend (PostgreSQL + Render) running successfully!");
});
// ✅ Fetch all cartelas (used in caller dashboard)
app.get("/api/cartelas", async (req, res) => {
  try {
    const result = await pool.query("SELECT * FROM cartelas ORDER BY id ASC");
    res.json(result.rows);
  } catch (err) {
    console.error("Error fetching cartelas:", err.message);
    res.status(500).json({ error: "Failed to load cartelas" });
  }
});
// ✅ Fetch cartelas linked to a specific game
app.get("/api/games/:id/cartelas", authenticate(), async (req, res) => {
  try {
    const gameId = req.params.id;
    const result = await pool.query(
      "SELECT id, numbers, issued, createdat FROM cartelas WHERE gameid = $1 ORDER BY id ASC",
      [gameId]
    );
    res.json({ success: true, cartelas: result.rows });
  } catch (err) {
    console.error("❌ Error loading cartelas:", err);
    res.status(500).json({ error: "Failed to load cartelas" });
  }
});

// ✅ Save called numbers for a specific game
app.post("/api/games/:id/called", async (req, res) => {
  try {
    const { numbers } = req.body;
    const gameId = req.params.id;

    if (!Array.isArray(numbers)) {
      return res.status(400).json({ error: "Numbers must be an array" });
    }

    await pool.query("UPDATE games SET called = $1 WHERE id = $2", [numbers, gameId]);
    res.json({ success: true, message: "Numbers saved successfully" });
  } catch (err) {
    console.error("❌ Error saving called numbers:", err.message);
    res.status(500).json({ error: "Failed to save called numbers", details: err.message });
  }
});
// ✅ Get single game by id (used by caller)
app.get("/api/games/:id", authenticate(), async (req, res) => {
  try {
    const gameId = req.params.id;
    const q = await pool.query("SELECT * FROM games WHERE id = $1", [gameId]);
    if (q.rows.length === 0) return res.status(404).json({ error: "Game not found" });

    const game = q.rows[0];

    // If cartelas / called stored as JSONB, they come as strings/objects depending on driver version,
    // ensure they are proper JS arrays:
    try {
      if (typeof game.cartelas === "string") game.cartelas = JSON.parse(game.cartelas);
    } catch (e) { /* ignore parse error */ }
    try {
      if (typeof game.called === "string") game.called = JSON.parse(game.called);
    } catch (e) { /* ignore parse error */ }

    res.json({ success: true, game });
  } catch (err) {
    console.error("❌ Error fetching game:", err.message);
    res.status(500).json({ error: "Failed to fetch game", details: err.message });
  }
});

// ✅ Start server
app.listen(PORT, () => console.log(`🚀 Server running on port ${PORT}`));
