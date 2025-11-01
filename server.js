// server.js
require("dotenv").config();
const express = require("express");
const cors = require("cors");
const { pool } = require("./db"); // PostgreSQL pool
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const PDFDocument = require("pdfkit");

const app = express();

// ----------------- CORS -----------------
app.use(
  cors({
    origin: "https://bingo-frontind.netlify.app",
    methods: "GET,POST,PUT,DELETE,OPTIONS",
    allowedHeaders: "Content-Type, Authorization",
  })
);

// ----------------- JSON Parser -----------------
app.use(express.json());

// ----------------- Auth Middleware -----------------
function authMiddleware(requiredRole) {
  return (req, res, next) => {
    const auth = req.headers.authorization;
    if (!auth || !auth.startsWith("Bearer ")) {
      return res.status(401).json({ error: "No token" });
    }
    try {
      const token = auth.split(" ")[1];
      const payload = jwt.verify(token, process.env.JWT_SECRET);
      if (requiredRole && payload.role !== requiredRole) {
        return res.status(403).json({ error: `Only ${requiredRole} allowed` });
      }
      req.user = payload;
      next();
    } catch (err) {
      return res.status(401).json({ error: "Invalid token" });
    }
  };
}

// ----------------- Test Route -----------------
app.get("/", async (req, res) => {
  try {
    const result = await pool.query("SELECT NOW() AS current_time");
    res.json(result.rows);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ----------------- Create First Owner -----------------
app.post("/api/create-first-owner", async (req, res) => {
  try {
    const { phone, password, name } = req.body || {};
    if (!phone || !password)
      return res.status(400).json({ error: "phone and password required" });

    const owners = await pool.query(
      "SELECT COUNT(*) AS cnt FROM users WHERE role='owner'"
    );
    if (parseInt(owners.rows[0].cnt) > 0) {
      return res.status(400).json({ error: "Owner already exists" });
    }

    const hash = await bcrypt.hash(password, 10);
    const insert = await pool.query(
      "INSERT INTO users (phone, passwordhash, role, name, isactive) VALUES ($1,$2,$3,$4,$5) RETURNING id",
      [phone, hash, "owner", name || null, true]
    );

    res.json({ success: true, id: insert.rows[0].id });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Server error", details: err.message });
  }
});

// ----------------- Login -----------------
app.post("/api/login", async (req, res) => {
  try {
    const { phone, password } = req.body || {};
    if (!phone || !password)
      return res.status(400).json({ error: "phone and password required" });

    const result = await pool.query("SELECT * FROM users WHERE phone=$1", [phone]);
    if (result.rows.length === 0)
      return res.status(401).json({ error: "Invalid credentials" });

    const user = result.rows[0];
    if (!user.isactive) return res.status(403).json({ error: "Account is blocked" });

    const ok = await bcrypt.compare(password, user.passwordhash);
    if (!ok) return res.status(401).json({ error: "Invalid credentials" });

    const token = jwt.sign(
      { id: user.id, role: user.role, phone: user.phone, name: user.name },
      process.env.JWT_SECRET,
      { expiresIn: "12h" }
    );

    res.json({
      success: true,
      token,
      role: user.role,
      userId: user.id,
      name: user.name,
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Server error", details: err.message });
  }
});

// ----------------- Owner: Create Agent -----------------
app.post("/api/agents/create", authMiddleware("owner"), async (req, res) => {
  try {
    const { phone, password, name } = req.body || {};
    if (!phone || !password)
      return res.status(400).json({ error: "phone and password required" });

    const existing = await pool.query("SELECT * FROM users WHERE phone=$1", [phone]);
    if (existing.rows.length > 0)
      return res.status(400).json({ error: "Phone already registered" });

    const hash = await bcrypt.hash(password, 10);
    const insert = await pool.query(
      "INSERT INTO users (phone, passwordhash, role, name, isactive) VALUES ($1,$2,$3,$4,$5) RETURNING id",
      [phone, hash, "agent", name || null, true]
    );

    res.json({ success: true, id: insert.rows[0].id });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Server error", details: err.message });
  }
});

// ----------------- Owner: List Agents -----------------
app.get("/api/agents", authMiddleware("owner"), async (req, res) => {
  try {
    const result = await pool.query(
      "SELECT id, phone, name, role, isactive FROM users WHERE role='agent'"
    );
    res.json(result.rows);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Server error", details: err.message });
  }
});

// ----------------- Owner: Block/Unblock Agent -----------------
app.post("/api/agents/:id/toggle", authMiddleware("owner"), async (req, res) => {
  try {
    const agentId = req.params.id;

    const result = await pool.query(
      "SELECT isactive FROM users WHERE id=$1 AND role='agent'",
      [agentId]
    );
    if (result.rows.length === 0) return res.status(404).json({ error: "Agent not found" });

    const current = result.rows[0].isactive;
    const newStatus = !current;

    await pool.query(
      "UPDATE users SET isactive=$1 WHERE id=$2",
      [newStatus, agentId]
    );

    res.json({ success: true, message: newStatus ? "Agent unblocked" : "Agent blocked" });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Server error", details: err.message });
  }
});

// ----------------- Owner: Delete Agent -----------------
app.delete("/api/agents/:id", authMiddleware("owner"), async (req, res) => {
  try {
    const agentId = req.params.id;
    await pool.query("DELETE FROM games WHERE agentid=$1", [agentId]);
    await pool.query("DELETE FROM users WHERE id=$1 AND role='agent'", [agentId]);
    res.json({ success: true, message: "Agent and games deleted successfully" });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Server error", details: err.message });
  }
});

// ----------------- Agent: Start Game -----------------
app.post("/api/games/start", authMiddleware("agent"), async (req, res) => {
  try {
    const { players, pot, entryfee, cartelas, winMode } = req.body || {};
    if (!players || !pot || !entryfee)
      return res.status(400).json({ error: "Missing players, pot or entryFee" });

    const insert = await pool.query(
      `INSERT INTO games (agentid, ownerid, players, pot, entryfee, date, profit, winnermoney, cartelas, called, winmode) 
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11) RETURNING id`,
      [
        req.user.id,
        1,
        players,
        pot,
        entryfee,
        new Date(),
        0,
        0,
        JSON.stringify(cartelas || []),
        JSON.stringify([]),
        winMode || null,
      ]
    );

    res.json({ success: true, gameId: insert.rows[0].id });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Server error", details: err.message });
  }
});

// ----------------- Agent: Update Called Numbers -----------------
app.post("/api/games/:id/called", authMiddleware("agent"), async (req, res) => {
  try {
    const { numbers } = req.body || {};
    await pool.query(
      "UPDATE games SET called=$1 WHERE id=$2",
      [JSON.stringify(numbers || []), req.params.id]
    );
    res.json({ success: true });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Server error", details: err.message });
  }
});

// ----------------- Agent: Finish Game -----------------
app.post("/api/games/:id/finish", authMiddleware("agent"), async (req, res) => {
  try {
    const { numbers, status } = req.body || {};
    await pool.query(
      "UPDATE games SET called=$1, status=$2 WHERE id=$3",
      [JSON.stringify(numbers || []), status || "completed", req.params.id]
    );
    res.json({ success: true });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Server error", details: err.message });
  }
});

// ----------------- Get Game Info -----------------
app.get("/api/games/:id", async (req, res) => {
  try {
    const result = await pool.query("SELECT * FROM games WHERE id=$1", [req.params.id]);
    if (result.rows.length === 0) return res.status(404).json({ error: "Game not found" });

    const game = result.rows[0];
    game.cartelas = JSON.parse(game.cartelas || "[]");
    game.called = JSON.parse(game.called || "[]");

    res.json({ success: true, game });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Server error", details: err.message });
  }
});

// ----------------- Get Cartelas -----------------
app.get("/api/games/:id/cartelas", async (req, res) => {
  try {
    const result = await pool.query("SELECT cartelas FROM games WHERE id=$1", [req.params.id]);
    if (result.rows.length === 0) return res.status(404).json({ error: "Game not found" });

    res.json({ success: true, cartelas: JSON.parse(result.rows[0].cartelas || "[]") });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Server error", details: err.message });
  }
});

// ----------------- Agent: End Game (Update Winner & Profit) -----------------
app.post("/api/games/:id/end", authMiddleware("agent"), async (req, res) => {
  try {
    const { winnerMoney } = req.body || {};
    const gameId = req.params.id;
    if (!winnerMoney) return res.status(400).json({ error: "Winner money required" });

    const game = await pool.query("SELECT pot FROM games WHERE id=$1", [gameId]);
    if (game.rows.length === 0) return res.status(404).json({ error: "Game not found" });

    const profit = game.rows[0].pot - winnerMoney;
    await pool.query("UPDATE games SET winnermoney=$1, profit=$2 WHERE id=$3", [
      winnerMoney,
      profit,
      gameId,
    ]);

    res.json({ success: true, gameId, profit });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Server error", details: err.message });
  }
});

// ----------------- Owner: Reports PDF -----------------
app.get("/api/reports/owner", authMiddleware("owner"), async (req, res) => {
  try {
    const games = await pool.query(
      `SELECT g.*, u.name AS agentname
       FROM games g
       JOIN users u ON g.agentid = u.id
       WHERE u.role='agent'
       ORDER BY u.name, g.date DESC`
    );

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

    for (const g of games.rows) {
      if (currentAgent !== g.agentname) {
        if (currentAgent !== null) {
          doc.font("Helvetica-Bold").text(`Total Profit: ${totalProfitAgent} birr`);
          doc.moveDown();
        }
        currentAgent = g.agentname;
        totalProfitAgent = 0;
        doc.fontSize(16).text(`👤 Agent: ${g.agentname}`, { underline: true });
        doc.moveDown(0.3);
        doc.fontSize(12).text("Game ID | Date | Players | Pot | Winner | Profit");
        doc.moveDown(0.3);
      }
      totalProfitAgent += parseFloat(g.profit || 0);
      totalProfitAll += parseFloat(g.profit || 0);

      doc.text(
        `${g.id} | ${new Date(g.date).toLocaleDateString()} | ${g.players} | ${g.pot} | ${g.winnermoney} | ${g.profit}`
      );
    }

    doc.moveDown();
    doc.font("Helvetica-Bold").text(`Total Profit: ${totalProfitAgent} birr`);
    doc.moveDown(2);
    doc.text(`🏁 Grand Total Profit (All Agents): ${totalProfitAll} birr`, { align: "right" });
    doc.end();
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Failed to generate PDF", details: err.message });
  }
});

// ----------------- Start Server -----------------
const PORT = process.env.PORT || 4000;
app.listen(PORT, () => console.log(`🚀 Server running on port ${PORT}`));
