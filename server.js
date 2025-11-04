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

const PORT = process.env.PORT || 10000;
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
    // check role manually
    if (req.user.role !== "owner") {
      return res.status(403).json({ error: "Only owner can create agents" });
    }

    const { phone, password, name } = req.body;
    if (!phone || !password)
      return res.status(400).json({ error: "Phone and password required" });

    const existing = await pool.query("SELECT id FROM users WHERE phone=$1", [phone]);
    if (existing.rows.length > 0)
      return res.status(400).json({ error: "Phone already registered" });

    const hashed = await bcrypt.hash(password, 10);
    const result = await pool.query(
      `INSERT INTO users (phone, passwordhash, role, name, isactive)
       VALUES ($1, $2, 'agent', $3, TRUE)
       RETURNING id, phone, role, name`,
      [phone, hashed, name]
    );

    res.json({ success: true, agent: result.rows[0] });
  } catch (err) {
    console.error(err.message);
    res.status(500).json({ error: "Failed to create agent" });
  }
});


// ✅ Owner: List Agents
app.get("/api/agents", authenticate("owner"), async (req, res) => {
  try {
    const result = await pool.query(
      "SELECT id, phone, name, role, isactive FROM users WHERE role='agent' ORDER BY id ASC"
    );
    res.json({ success: true, agents: result.rows });
  } catch (err) {
    console.error(err.message);
    res.status(500).json({ error: "Failed to fetch agents" });
  }
});

// ✅ Owner: Toggle Block/Unblock Agent
app.post("/api/agents/:id/toggle", authenticate("owner"), async (req, res) => {
  try {
    const agentId = req.params.id;
    const current = await pool.query("SELECT isactive FROM users WHERE id=$1", [agentId]);
    if (current.rows.length === 0)
      return res.status(404).json({ error: "Agent not found" });

    const newStatus = !current.rows[0].isactive;
    await pool.query("UPDATE users SET isactive=$1 WHERE id=$2", [newStatus, agentId]);
    res.json({ success: true, id: agentId, newStatus });
  } catch (err) {
    console.error(err.message);
    res.status(500).json({ error: "Failed to toggle agent" });
  }
});

// ✅ Owner: Delete Agent
app.delete("/api/agents/:id", authenticate("owner"), async (req, res) => {
  try {
    const agentId = req.params.id;
    await pool.query("DELETE FROM users WHERE id=$1 AND role='agent'", [agentId]);
    res.json({ success: true });
  } catch (err) {
    console.error(err.message);
    res.status(500).json({ error: "Failed to delete agent" });
  }
});

// ✅ Agent: Create Game
app.post("/api/games", authenticate("agent"), async (req, res) => {
  try {
    console.log("Body:", req.body);
console.log("User:", req.user);
    const { players, pot, entryfee, winmode } = req.body;
    const result = await pool.query(
      `INSERT INTO games (agentid, ownerid, players, pot, entryfee, winmode)
       VALUES ($1, 1, $2, $3, $4, $5) RETURNING *`,
      [req.user.id, players, pot, entryfee, winmode]
    );
    res.json({ success: true, game: result.rows[0] });
  } catch (err) {
    console.error(err.message);
    res.status(500).json({ error: "Failed to create game" });
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

// ✅ Start server
app.listen(PORT, () => console.log(`🚀 Server running on port ${PORT}`));
