// server.js (fixed - duplicates removed, original routes preserved)
require("dotenv").config();
const express = require("express");
const cors = require("cors");
const { sql, poolPromise } = require("./db");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");

const app = express();

// CORS config
app.use(
  cors({
    origin: "https://bingo-frontind.netlify.app",
    methods: "GET,POST,PUT,DELETE,OPTIONS",
    allowedHeaders: "Content-Type, Authorization",
  })
);

// parse JSON bodies (MUST be before any route that reads req.body)
app.use(express.json());

// ----------------- Helper: Auth Middleware -----------------
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
    const pool = await poolPromise;
    const result = await pool
      .request()
      .query("SELECT GETDATE() AS CurrentTime");
    res.json(result.recordset);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ----------------- Create First Owner -----------------
app.post("/api/create-first-owner", async (req, res) => {
  try {
    const body = req.body || {};
    const { phone, password, name } = body;
    if (!phone || !password)
      return res.status(400).json({ error: "phone and password required" });

    const pool = await poolPromise;
    const owners = await pool
      .request()
      .query("SELECT COUNT(*) AS cnt FROM Users WHERE Role = 'owner'");
    if (owners.recordset[0].cnt > 0) {
      return res.status(400).json({ error: "Owner already exists" });
    }

    const hash = await bcrypt.hash(password, 10);
    const insert = await pool
      .request()
      .input("phone", sql.NVarChar, phone)
      .input("hash", sql.NVarChar, hash)
      .input("role", sql.NVarChar, "owner")
      .input("name", sql.NVarChar, name || null)
      .query(
        "INSERT INTO Users (Phone, PasswordHash, Role, Name, IsActive) OUTPUT INSERTED.Id VALUES (@phone, @hash, @role, @name, 1)"
      );

    res.json({ success: true, id: insert.recordset[0].Id });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Server error", details: err.message });
  }
});

// ----------------- Login -----------------
app.post("/api/login", async (req, res) => {
  try {
    const body = req.body || {};
    const { phone, password } = body;
    if (!phone || !password)
      return res.status(400).json({ error: "phone and password required" });

    const pool = await poolPromise;
    const result = await pool
      .request()
      .input("phone", sql.NVarChar, phone)
      .query("SELECT * FROM Users WHERE Phone = @phone");

    if (result.recordset.length === 0)
      return res.status(401).json({ error: "Invalid credentials" });

    const user = result.recordset[0];

    if (user.IsActive === 0) {
      return res.status(403).json({ error: "Account is blocked" });
    }

    const ok = await bcrypt.compare(password, user.PasswordHash);
    if (!ok) return res.status(401).json({ error: "Invalid credentials" });

    const token = jwt.sign(
      { id: user.Id, role: user.Role, phone: user.Phone, name: user.Name },
      process.env.JWT_SECRET,
      { expiresIn: "12h" }
    );

    res.json({
      success: true,
      token,
      role: user.Role,
      userId: user.Id,
      name: user.Name,
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Server error", details: err.message });
  }
});

// ----------------- Owner: Create Agent -----------------
app.post("/api/agents/create", authMiddleware("owner"), async (req, res) => {
  try {
    const body = req.body || {};
    const { phone, password, name } = body;
    if (!phone || !password) {
      return res.status(400).json({ error: "phone and password required" });
    }

    const pool = await poolPromise;
    const existing = await pool
      .request()
      .input("phone", sql.NVarChar, phone)
      .query("SELECT Id FROM Users WHERE Phone = @phone");

    if (existing.recordset.length > 0) {
      return res.status(400).json({ error: "Phone already registered" });
    }

    const hash = await bcrypt.hash(password, 10);
    const insert = await pool
      .request()
      .input("phone", sql.NVarChar, phone)
      .input("hash", sql.NVarChar, hash)
      .input("role", sql.NVarChar, "agent")
      .input("name", sql.NVarChar, name || null)
      .input("isActive", sql.Bit, 1)
      .query(
        "INSERT INTO Users (Phone, PasswordHash, Role, Name, IsActive) OUTPUT INSERTED.Id VALUES (@phone, @hash, @role, @name, @isActive)"
      );

    res.json({ success: true, id: insert.recordset[0].Id });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Server error", details: err.message });
  }
});

// ----------------- Owner: List Agents -----------------
app.get("/api/agents", authMiddleware("owner"), async (req, res) => {
  try {
    const pool = await poolPromise;
    const result = await pool
      .request()
      .query(
        "SELECT Id, Phone, Name, Role, IsActive FROM Users WHERE Role = 'agent'"
      );
    res.json(result.recordset);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Server error", details: err.message });
  }
});

// ----------------- Owner: Toggle Agent -----------------
app.post(
  "/api/agents/:id/toggle",
  authMiddleware("owner"),
  async (req, res) => {
    try {
      const agentId = req.params.id;
      const pool = await poolPromise;

      const result = await pool
        .request()
        .input("id", sql.Int, agentId)
        .query("SELECT IsActive FROM Users WHERE Id = @id AND Role = 'agent'");

      if (result.recordset.length === 0) {
        return res.status(404).json({ error: "Agent not found" });
      }

      const current = result.recordset[0].IsActive;
      const newStatus = current ? 0 : 1;

      await pool
        .request()
        .input("id", sql.Int, agentId)
        .input("status", sql.Bit, newStatus)
        .query("UPDATE Users SET IsActive = @status WHERE Id = @id");

      res.json({ success: true, id: agentId, newStatus });
    } catch (err) {
      console.error(err);
      res.status(500).json({ error: "Server error", details: err.message });
    }
  }
);

// ----------------- Agent: Game History -----------------
app.get("/api/games/my-history", authMiddleware("agent"), async (req, res) => {
  try {
    const pool = await poolPromise;
    const result = await pool
      .request()
      .input("agentId", sql.Int, req.user.id)
      .query("SELECT * FROM Games WHERE AgentId = @agentId ORDER BY Date DESC");
    res.json({ success: true, games: result.recordset });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Server error", details: err.message });
  }
});

// ----------------- Agent: Start Game -----------------
app.post("/api/games/start", authMiddleware("agent"), async (req, res) => {
  try {
    const body = req.body || {};
    const { players, pot, entryFee } = body;
    if (!players || !pot || !entryFee) {
      return res
        .status(400)
        .json({ error: "Missing players, pot or entryFee" });
    }

    const pool = await poolPromise;
    const insert = await pool
      .request()
      .input("AgentId", sql.Int, req.user.id)
      .input("OwnerId", sql.Int, 1) // fixed owner for now
      .input("Players", sql.Int, players)
      .input("Pot", sql.Decimal(10, 2), pot)
      .input("EntryFee", sql.Decimal(10, 2), entryFee)
      .input("Date", sql.DateTime, new Date())
      .input("Profit", sql.Decimal(10, 2), 0)
      .input("WinnerMoney", sql.Decimal(10, 2), 0)
      .query(
        "INSERT INTO Games (AgentId, OwnerId, Players, Pot, EntryFee, Date, Profit, WinnerMoney) OUTPUT INSERTED.Id VALUES (@AgentId, @OwnerId, @Players, @Pot, @EntryFee, @Date, @Profit, @WinnerMoney)"
      );

    res.json({ success: true, gameId: insert.recordset[0].Id });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Server error", details: err.message });
  }
});

// ----------------- Agent: End Game -----------------
app.post("/api/games/:id/end", authMiddleware("agent"), async (req, res) => {
  try {
    const body = req.body || {};
    const { winnerMoney } = body;
    const gameId = req.params.id;

    if (!winnerMoney) {
      return res.status(400).json({ error: "Winner money required" });
    }

    const pool = await poolPromise;
    const game = await pool
      .request()
      .input("Id", sql.Int, gameId)
      .query("SELECT Pot FROM Games WHERE Id = @Id");

    if (game.recordset.length === 0) {
      return res.status(404).json({ error: "Game not found" });
    }

    const pot = game.recordset[0].Pot;
    const profit = pot - winnerMoney;

    await pool
      .request()
      .input("Id", sql.Int, gameId)
      .input("WinnerMoney", sql.Decimal(10, 2), winnerMoney)
      .input("Profit", sql.Decimal(10, 2), profit)
      .query(
        "UPDATE Games SET WinnerMoney=@WinnerMoney, Profit=@Profit WHERE Id=@Id"
      );

    res.json({ success: true, gameId, profit });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Server error", details: err.message });
  }
});
// ----------------- Create Game -----------------
// ----------------- Create Game (Agent only, fixed with Date + OwnerId) -----------------
app.post("/api/games", async (req, res) => {
  try {
    const auth = req.headers.authorization;
    if (!auth || !auth.startsWith("Bearer "))
      return res.status(401).json({ error: "No token" });
    const token = auth.split(" ")[1];
    const payload = jwt.verify(token, process.env.JWT_SECRET);

    if (payload.role !== "agent") {
      return res.status(403).json({ error: "Only agents can create games" });
    }

    const body = req.body || {};
    const { players, pot, profit, winnerMoney, cartelas, winMode } = body;
    if (!players || !pot || !profit || !winnerMoney) {
      return res.status(400).json({ error: "Missing game fields" });
    }

    const pool = await poolPromise;
    const insert = await pool
      .request()
      .input("AgentId", sql.Int, payload.id)
      .input("OwnerId", sql.Int, 1) // default owner
      .input("Players", sql.Int, players)
      .input("Pot", sql.Decimal(10, 2), pot)
      .input("Profit", sql.Decimal(10, 2), profit)
      .input("WinnerMoney", sql.Decimal(10, 2), winnerMoney)
      .input("WinMode", sql.NVarChar, winMode || null)
      .input("Cartelas", sql.NVarChar, JSON.stringify(cartelas))
      .input("Called", sql.NVarChar, JSON.stringify([]))
      .input("Date", sql.DateTime, new Date()) // ✅ Add Date
      .input("CreatedAt", sql.DateTime, new Date()) // ✅ Add CreatedAt
      .query(`
        INSERT INTO Games (
          AgentId, OwnerId, Players, Pot, Profit, WinnerMoney, WinMode, Cartelas, Called, Date, CreatedAt
        )
        OUTPUT INSERTED.Id
        VALUES (
          @AgentId, @OwnerId, @Players, @Pot, @Profit, @WinnerMoney, @WinMode, @Cartelas, @Called, @Date, @CreatedAt
        )
      `);

    res.json({ success: true, gameId: insert.recordset[0].Id });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Server error", details: err.message });
  }
});

// ----------------- Get Game Info -----------------
app.get("/api/games/:id", async (req, res) => {
  try {
    const pool = await poolPromise;
    const result = await pool
      .request()
      .input("Id", sql.Int, req.params.id)
      .query("SELECT * FROM Games WHERE Id = @Id");

    if (result.recordset.length === 0)
      return res.status(404).json({ error: "Game not found" });

    const game = result.recordset[0];
    game.Cartelas = JSON.parse(game.Cartelas || "[]");
    game.Called = JSON.parse(game.Called || "[]");
    res.json({ success: true, game });
  } catch (err) {
    res.status(500).json({ error: "Server error", details: err.message });
  }
});

// ----------------- Save Called Numbers -----------------
app.post("/api/games/:id/called", async (req, res) => {
  try {
    const body = req.body || {};
    const { numbers } = body;
    const pool = await poolPromise;
    await pool
      .request()
      .input("Id", sql.Int, req.params.id)
      .input("Called", sql.NVarChar, JSON.stringify(numbers))
      .query("UPDATE Games SET Called=@Called WHERE Id=@Id");
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: "Server error", details: err.message });
  }
});

// ----------------- Finish Game -----------------
app.post("/api/games/:id/finish", async (req, res) => {
  try {
    const body = req.body || {};
    const { numbers, status } = body;
    const pool = await poolPromise;
    await pool
      .request()
      .input("Id", sql.Int, req.params.id)
      .input("Called", sql.NVarChar, JSON.stringify(numbers || []))
      .input("Status", sql.NVarChar, status || "completed")
      .query("UPDATE Games SET Called=@Called, Status=@Status WHERE Id=@Id");
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: "Server error", details: err.message });
  }
});

// ----------------- Get Cartelas -----------------
app.get("/api/games/:id/cartelas", async (req, res) => {
  try {
    const pool = await poolPromise;
    const result = await pool
      .request()
      .input("Id", sql.Int, req.params.id)
      .query("SELECT Cartelas FROM Games WHERE Id=@Id");

    if (result.recordset.length === 0)
      return res.status(404).json({ error: "Game not found" });

    const cartelas = JSON.parse(result.recordset[0].Cartelas || "[]");
    res.json({ success: true, cartelas });
  } catch (err) {
    res.status(500).json({ error: "Server error", details: err.message });
  }
});
// Block agent app.post("/api/block-agent/:id", async (req, res) => { try { const auth = req.headers.authorization; if (!auth || !auth.startsWith("Bearer ")) return res.status(401).json({ error: "No token" }); const token = auth.split(" ")[1]; const payload = jwt.verify(token, process.env.JWT_SECRET); if (payload.role !== "owner") return res.status(403).json({ error: "Only owner allowed" }); const pool = await poolPromise; await pool .request() .input("id", sql.Int, req.params.id) .query("UPDATE Users SET IsActive = 0 WHERE Id = @id AND Role = 'agent'"); res.json({ success: true }); } catch (err) { console.error(err); res.status(500).json({ error: err.message }); } }); // Unblock agent app.post("/api/unblock-agent/:id", async (req, res) => { try { const auth = req.headers.authorization; if (!auth || !auth.startsWith("Bearer ")) return res.status(401).json({ error: "No token" }); const token = auth.split(" ")[1]; const payload = jwt.verify(token, process.env.JWT_SECRET); if (payload.role !== "owner") return res.status(403).json({ error: "Only owner allowed" }); const pool = await poolPromise; await pool .request() .input("id", sql.Int, req.params.id) .query("UPDATE Users SET IsActive = 1 WHERE Id = @id AND Role = 'agent'"); res.json({ success: true }); } catch (err) { console.error(err); res.status(500).json({ error: err.message }); } }); // ----------------- List Agents (Owner only) ----------------- app.get("/api/agents", async (req, res) => { try { const auth = req.headers.authorization; if (!auth || !auth.startsWith("Bearer ")) { return res.status(401).json({ error: "No token" }); } const token = auth.split(" ")[1]; let payload; try { payload = jwt.verify(token, process.env.JWT_SECRET); } catch (err) { return res.status(401).json({ error: "Invalid token" }); } if (payload.role !== "owner") { return res.status(403).json({ error: "Only owner can view agents" }); } const pool = await poolPromise; const result = await pool .request() .query( "SELECT Id, Phone, Name, Role, IsActive FROM Users WHERE Role = 'agent'" ); res.json(result.recordset); } catch (err) { console.error(err); res.status(500).json({ error: "Server error", details: err.message }); } }); // ----------------- Block/Unblock Agent (Owner only) ----------------- app.post("/api/agents/:id/toggle", async (req, res) => { try { const auth = req.headers.authorization; if (!auth || !auth.startsWith("Bearer ")) { return res.status(401).json({ error: "No token" }); } const token = auth.split(" ")[1]; let payload; try { payload = jwt.verify(token, process.env.JWT_SECRET); } catch (err) { return res.status(401).json({ error: "Invalid token" }); } if (payload.role !== "owner") { return res .status(403) .json({ error: "Only owner can block/unblock agents" }); } const agentId = req.params.id; const pool = await poolPromise; // Get current status const result = await pool .request() .input("id", sql.Int, agentId) .query("SELECT IsActive FROM Users WHERE Id = @id AND Role = 'agent'"); if (result.recordset.length === 0) { return res.status(404).json({ error: "Agent not found" }); } const current = result.recordset[0].IsActive; const newStatus = current ? 0 : 1; await pool .request() .input("id", sql.Int, agentId) .input("status", sql.Bit, newStatus) .query("UPDATE Users SET IsActive = @status WHERE Id = @id"); res.json({ success: true, id: agentId, newStatus }); } catch (err) { console.error(err); res.status(500).json({ error: "Server error", details: err.message }); } }); // ----------------- Block/Unblock Agent ----------------- app.post("/api/agents/:id/toggle", async (req, res) => { try { const auth = req.headers.authorization; if (!auth || !auth.startsWith("Bearer ")) { return res.status(401).json({ error: "No token" }); } const token = auth.split(" ")[1]; let payload; try { payload = jwt.verify(token, process.env.JWT_SECRET); } catch (err) { return res.status(401).json({ error: "Invalid token" }); } if (payload.role !== "owner") { return res .status(403) .json({ error: "Only owner can block/unblock agents" }); } const agentId = req.params.id; const pool = await poolPromise; // Get current status const result = await pool .request() .input("id", sql.Int, agentId) .query("SELECT IsActive FROM Users WHERE Id = @id AND Role = 'agent'"); if (result.recordset.length === 0) { return res.status(404).json({ error: "Agent not found" }); } const current = result.recordset[0].IsActive; const newStatus = current ? 0 : 1; await pool .request() .input("id", sql.Int, agentId) .input("status", sql.Bit, newStatus) .query("UPDATE Users SET IsActive = @status WHERE Id = @id"); res.json({ success: true, id: agentId, newStatus }); } catch (err) { console.error(err); res.status(500).json({ error: "Server error", details: err.message }); } }); // ----------------- Agent's Own Game History ----------------- app.get("/api/games/my-history", async (req, res) => { try { const auth = req.headers.authorization; if (!auth || !auth.startsWith("Bearer ")) { return res.status(401).json({ error: "No token" }); } const token = auth.split(" ")[1]; const payload = jwt.verify(token, process.env.JWT_SECRET); if (payload.role !== "agent") { return res.status(403).json({ error: "Only agents can access this" }); } const pool = await poolPromise; const result = await pool .request() .input("agentId", sql.Int, payload.id) .query("SELECT * FROM Games WHERE AgentId = @agentId ORDER BY Date DESC"); res.json({ success: true, games: result.recordset }); } catch (err) { console.error(err); res.status(500).json({ error: "Server error", details: err.message }); } });
// ----------------- Owner: View All Games -----------------
app.get("/api/games", authMiddleware("owner"), async (req, res) => {
  try {
    const pool = await poolPromise;
    const result = await pool.request().query(`
      SELECT 
        Id, AgentId, Players, Pot, Profit, WinnerMoney, WinMode, 
        Date, Status
      FROM Games
      ORDER BY Date DESC
    `);
    res.json({ success: true, games: result.recordset });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Server error", details: err.message });
  }
});

// Delete agent (Owner only)
app.delete("/api/agents/:id", authMiddleware("owner"), async (req, res) => {
  try {
    const pool = await poolPromise;
    const agentId = req.params.id;

    // First delete all games related to this agent
    await pool
      .request()
      .input("AgentId", sql.Int, agentId)
      .query("DELETE FROM Games WHERE AgentId = @AgentId");

    // Then delete the agent
    await pool
      .request()
      .input("id", sql.Int, agentId)
      .query("DELETE FROM Users WHERE Id = @id AND Role = 'agent'");

    res.json({
      success: true,
      message: "Agent and their games deleted successfully.",
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Server error", details: err.message });
  }
});

// ----------------- Owner: Download PDF Report -----------------
const PDFDocument = require("pdfkit");
const fs = require("fs");
app.get("/api/reports/owner", authMiddleware("owner"), async (req, res) => {
  try {
    const pool = await poolPromise;
    const games = await pool.request().query(`
      SELECT g.*, u.Name AS AgentName
      FROM Games g
      JOIN Users u ON g.AgentId = u.Id
      WHERE u.Role = 'agent'
      ORDER BY u.Name, g.Date DESC
    `);

    const doc = new PDFDocument({ margin: 30 });
    res.setHeader("Content-Type", "application/pdf");
    res.setHeader(
      "Content-Disposition",
      "attachment; filename=owner_report.pdf"
    );
    doc.pipe(res);

    doc.fontSize(20).text("🎯 Bingo House — Owner Report", { align: "center" });
    doc.moveDown();
    doc.fontSize(12).text(`📅 Date: ${new Date().toLocaleDateString()}`);
    doc.moveDown();

    let currentAgent = null;
    let totalProfitAll = 0;
    let totalProfitAgent = 0;

    for (const g of games.recordset) {
      if (currentAgent !== g.AgentName) {
        if (currentAgent !== null) {
          doc
            .font("Helvetica-Bold")
            .text(`Total Profit: ${totalProfitAgent} birr`);
          doc.moveDown();
        }
        currentAgent = g.AgentName;
        totalProfitAgent = 0;
        doc.fontSize(16).text(`👤 Agent: ${g.AgentName}`, { underline: true });
        doc.moveDown(0.3);
        doc
          .fontSize(12)
          .text("Game ID | Date | Players | Pot | Winner | Profit");
        doc.moveDown(0.3);
      }

      totalProfitAgent += parseFloat(g.Profit || 0);
      totalProfitAll += parseFloat(g.Profit || 0);

      doc.text(
        `${g.Id} | ${new Date(g.Date).toLocaleDateString()} | ${g.Players} | ${
          g.Pot
        } | ${g.WinnerMoney} | ${g.Profit}`
      );
    }

    // Final totals
    doc.moveDown();
    doc.font("Helvetica-Bold").text(`Total Profit: ${totalProfitAgent} birr`);
    doc.moveDown(2);
    doc.text(`🏁 Grand Total Profit (All Agents): ${totalProfitAll} birr`, {
      align: "right",
    });
    doc.end();
  } catch (err) {
    console.error(err);
    res
      .status(500)
      .json({ error: "Failed to generate PDF", details: err.message });
  }
});
app.post(
  "/api/agents/:id/toggle",
  authMiddleware("owner"),
  async (req, res) => {
    try {
      const agentId = req.params.id;
      const pool = await poolPromise;

      // Get current status
      const result = await pool
        .request()
        .input("id", sql.Int, agentId)
        .query("SELECT IsActive FROM Users WHERE Id=@id AND Role='agent'");

      if (result.recordset.length === 0) {
        return res.status(404).json({ error: "Agent not found" });
      }

      const current = result.recordset[0].IsActive;
      const newStatus = current ? 0 : 1;

      await pool
        .request()
        .input("id", sql.Int, agentId)
        .input("status", sql.Bit, newStatus)
        .query("UPDATE Users SET IsActive=@status WHERE Id=@id");

      res.json({
        success: true,
        message: newStatus ? "Agent unblocked" : "Agent blocked",
      });
    } catch (err) {
      console.error(err);
      res.status(500).json({ error: err.message });
    }
  }
);

// ----------------- Start Server -----------------
const PORT = process.env.PORT || 4000;
app.listen(PORT, () => console.log(`🚀 Server running on port ${PORT}`));
