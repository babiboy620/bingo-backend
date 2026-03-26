// server.js — Full PostgreSQL version (Render-ready)
require("dotenv").config();
const express = require("express");
const cors = require("cors");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const { pool } = require("./db");
// =========================================================
// 📢 FORCE DB WAKE-UP AND TEST (PASTE HERE)
// =========================================================
(async () => {
    try {
        const res = await pool.query('SELECT 1 + 1 AS solution');
        console.log(`✅ DB Wake-up successful. Test query result: ${res.rows[0].solution}`);
    } catch (err) {
        console.error("❌ CRITICAL: Initial DB WAKE-UP FAILED! Check DATABASE_URL/DB status.", err.message);
        // Do NOT exit, let the server start and crash on the route
    }
})();
// =========================================================
const PDFDocument = require("pdfkit");

const app = express();
// 📢 PASTE THE DEBUG LOG HERE (Around line 10)
app.use((req, res, next) => {
    console.log(`[REQUEST START] Method: ${req.method}, URL: ${req.url}`);
    next();
});
// =========================================================

app.use(express.json());      // ← MUST come first
app.use(express.urlencoded({ extended: true }));

// =========================================================
// 🔥 FIXED GLOBAL CORS (RENDER + VERCEL SAFE VERSION)
// =========================================================
app.use((req, res, next) => {
  res.header("Access-Control-Allow-Origin", "https://bingofront.vercel.app");
  res.header("Access-Control-Allow-Methods", "GET,POST,PUT,DELETE,OPTIONS");
  res.header("Access-Control-Allow-Headers", "Content-Type, Authorization");
  res.header("Access-Control-Allow-Credentials", "true");
  if (req.method === "OPTIONS") return res.sendStatus(200);
  next();
});


const PORT = process.env.PORT;
const JWT_SECRET = process.env.JWT_SECRET || "default_secret";

// 📢 ADD THE JWT DEBUG LOG HERE
console.log(`[DEBUG] JWT_SECRET loaded: ${!!process.env.JWT_SECRET}`); // Check if it's set
// ------------------

// ✅ JWT Middleware (ULTRA-DEFENSIVE VERSION)
function authenticate(role = null) {
    // This runs once when the server starts, not per request.
    // Ensure JWT_SECRET is available globally (which it is, from the top of server.js)
    
    return (req, res, next) => {
        // 📢 Check 1: Did we reach the function?
        console.log(`[AUTH DEBUG] 1. Request reached authenticate for ${req.url}`); 
        
        // Ensure role checks are valid, even if token is missing
        if (role && !req.headers.authorization) {
            console.log(`[AUTH DEBUG] 2. Role needed but no token. Sending 401.`);
            return res.status(401).json({ error: "Missing token" });
        }

        const authHeader = req.headers.authorization;
        if (!authHeader) {
            console.log(`[AUTH DEBUG] 3. Token missing, sending 401.`);
            return res.status(401).json({ error: "Missing token" });
        }

        const token = authHeader.split(" ")[1];
        
        // Use a simple log to ensure JWT_SECRET is not causing a runtime crash
        console.log(`[AUTH DEBUG] 4. Token received. JWT_SECRET length: ${JWT_SECRET.length}`);

        try {
            const user = jwt.verify(token, JWT_SECRET);
            
            // This is the core reason you need authentication—to check the user's role and data.
            if (role && user.role !== role) {
                console.log(`[AUTH DEBUG] 5. Role denied: ${user.role}. Sending 403.`);
                return res.status(403).json({ error: `Only ${role}s allowed` });
            }
            
            req.user = user;
            console.log(`[AUTH DEBUG] 6. Auth successful, proceeding.`);
            next();
            
        } catch (error) {
            console.error(`[AUTH DEBUG] 7. JWT Verification FAILED: ${error.message}`);
            // Check if the error is due to an invalid secret length/type
            if (error.message.includes('secret')) {
                 console.error('[AUTH DEBUG] Likely JWT Secret mismatch or malformation!');
            }
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

// ✅ Login (Final Working Version)
app.post("/api/login", async (req, res) => {
  try {
    const { phone, password } = req.body;
    const result = await pool.query("SELECT * FROM users WHERE phone=$1", [phone]);
    const user = result.rows[0];

    if (!user) return res.status(400).json({ error: "User not found" });
    if (!user.isactive) return res.status(403).json({ error: "Account is blocked" });

    // Using the cleanHash logic, which we know works better
    const cleanHash = String(user.passwordhash).trim();
    
    const valid = await bcrypt.compare(password, cleanHash);
    
    if (!valid) {
        console.error("❌ LOGIN FAILURE: Bcrypt comparison failed after cleaning hash.");
        return res.status(401).json({ error: "Invalid password" });
    }
    
    const token = jwt.sign(
      { id: user.id, phone: user.phone, role: user.role, name: user.name },
      JWT_SECRET,
      { expiresIn: "7d" }
    );

    res.json({ success: true, token, user });
  } catch (err) {
    console.error("❌ Login failed:", err.message);
    res.status(500).json({ error: "Login failed" });
  }
});

// ✅ Owner: Create Agent
app.post("/api/agents/create", authenticate("owner"), async (req, res) => {
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

// ✅ Owner: Get all Agents (Final DB Crash Debug)
app.get("/api/agents", authenticate, async (req, res) => {
  try {
    // 📢 Log 1: Confirm the code is running after authentication
    console.log(`[DB CRASH DEBUG] 1. Auth passed for user ID: ${req.user.id}.`); 
    
    // Check role before query (good practice)
    if (req.user.role !== "owner")
      return res.status(403).json({ error: "Only owner can view agents" });

    // 📢 Log 2: Log just before the crashing line
    console.log(`[DB CRASH DEBUG] 2. About to execute pool.query...`); 
    
    // The query that might be crashing the process
    const result = await pool.query(
      "SELECT id, phone, name, role, isactive FROM users WHERE role='agent' ORDER BY id ASC"
    );
    
    // 📢 Log 3: Log after a successful query
    console.log(`[DB CRASH DEBUG] 3. Query succeeded! Returning ${result.rows.length} agents.`);

    res.json(result.rows);
  } catch (err) {
    // 💥 This will catch database errors and prevent the server from crashing
    console.error("❌ FINAL CRASH LOG (Route Handler):", err.message);
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

/// ✅ Agent: Create Game (Final Fix for Date Error)
app.post("/api/games", authenticate("agent"), async (req, res) => {
  try {
    const {
      players,
      pot,
      entryfee,
      winMode,
      winmode,
      cartelas = [],
      winnerMoney,
      winnermoney,
      profit = 0,
      date: incomingDate
    } = req.body || {};

    // -------------------------------
    // ✅ Fix date format
    // -------------------------------
    let dateValue = incomingDate;

    if (typeof dateValue === "string" && dateValue.includes("/")) {
      const [day, month, year] = dateValue.split("/");
      dateValue = `${year}-${month}-${day}`;
    }

    let gameDate = dateValue ? new Date(dateValue) : new Date();

    if (isNaN(gameDate.getTime())) {
      console.warn("Invalid date received — defaulting to now.");
      gameDate = new Date();
    }

    // -------------------------------
    // Normalize values
    // -------------------------------
    const finalWinMode = winMode || winmode || null;
    const finalWinnerMoney = winnerMoney || winnermoney || 0;

    // -------------------------------
    // Validate required fields
    // -------------------------------
    if (!players || !pot || typeof entryfee === "undefined") {
      return res.status(400).json({ error: "players, pot and entryfee required" });
    }

    // -------------------------------
    // Find owner
    // -------------------------------
    const ownerResult = await pool.query(
      "SELECT id FROM users WHERE role='owner' LIMIT 1"
    );

    if (ownerResult.rows.length === 0) {
      return res.status(500).json({ error: "No owner found in database" });
    }

    const ownerId = ownerResult.rows[0].id;

    // -------------------------------
    // Create game (STERILE SQL)
    // -------------------------------
    const sqlQuery = `
      INSERT INTO games (
        agentid,
        ownerid,
        players,
        pot,
        entryfee,
        winmode,
        cartelas,
        called,
        winnermoney,
        profit,
        date
      )
      VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)
      RETURNING *;
    `;

    const result = await pool.query(sqlQuery, [
      req.user.id,
      ownerId,
      players,
      pot,
      entryfee,
      finalWinMode,
      JSON.stringify(cartelas),
      JSON.stringify([]),
      finalWinnerMoney,
      profit,
      gameDate
    ]);

    const gameId = result.rows[0].id;

    // -------------------------------
    // Link selected cartelas
    // -------------------------------
    if (cartelas && cartelas.length > 0) {
      await pool.query(
        `UPDATE cartelas
         SET issued = true, gameid = $1
         WHERE id = ANY($2)`,
        [gameId, cartelas]
      );
    }

    return res.json({ success: true, game: result.rows[0] });

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

// ✅ Fetch cartelas linked to a specific game
// In server.js, modify the /api/games/:id/cartelas endpoint:

app.get("/api/games/:id/cartelas", authenticate(), async (req, res) => {
  try {
    const gameId = req.params.id;
    // 1. Try to load from the 'cartelas' table (the correct source)
    let result = await pool.query(
      "SELECT id, numbers, issued, createdat FROM cartelas WHERE gameid = $1 ORDER BY id ASC",
      [gameId]
    );

    let cartelasList = result.rows;

    // 2. Fallback: If the count is less than expected, fetch the list of IDs from the 'games' table
    // (This assumes the cartelas column in 'games' holds the full list of IDs selected)
    if (cartelasList.length < 13) { // or some other check for an incomplete list
      const gameQ = await pool.query("SELECT cartelas FROM games WHERE id = $1", [gameId]);
      if (gameQ.rows.length > 0) {
        let storedCartelaIds = gameQ.rows[0].cartelas; // This is a JSONB array of IDs

        if (typeof storedCartelaIds === "string") {
          storedCartelaIds = JSON.parse(storedCartelaIds);
        }
        
        if (Array.isArray(storedCartelaIds)) {
            // Filter out IDs that were successfully loaded from the 'cartelas' table
            const loadedIds = new Set(cartelasList.map(c => String(c.id)));
            const missingIds = storedCartelaIds.filter(id => !loadedIds.has(String(id)));

            // Add the missing IDs to the list using just the ID (frontend will use makeGridFromId)
            const fallbackCartelas = missingIds.map(id => ({ 
                id: String(id), 
                numbers: null, 
                issued: true, 
                createdat: null // Placeholder
            }));
            cartelasList = [...cartelasList, ...fallbackCartelas];
        }
      }
    }
    
    // Sort the final list by ID before sending
    cartelasList.sort((a, b) => parseInt(a.id) - parseInt(b.id));

    res.json({ success: true, cartelas: cartelasList });
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
// =========================================================
// 🛑 GLOBAL CRASH HANDLERS (Add this block)
// =========================================================

process.on("unhandledRejection", (reason, promise) => {
    console.error("❌ UNHANDLED REJECTION (Likely DB failure):", reason);
    // Note: Do not exit the process here if possible, let the server try to recover
});

process.on("uncaughtException", (err) => {
    console.error("❌ UNCAUGHT EXCEPTION (Process Killer):", err);
    // In a production environment, you might gracefully exit here (process.exit(1)), 
    // but for debugging, we log it aggressively.
});

// ✅ TEMP HASH GENERATOR ROUTE (REMOVE AFTER USE)
app.get("/api/generate-hash/:password", async (req, res) => {
    try {
        const password = req.params.password;
        if (!password) {
            return res.status(400).send("Please provide a password in the URL.");
        }
        const salt = await bcrypt.genSalt(10);
        const hash = await bcrypt.hash(password, salt);
        console.log(`\n\n📢 NEW HASH GENERATED FOR: ${password}`);
        console.log(`📢 USE THIS HASH: ${hash}\n\n`);
        res.send({ password: password, hash: hash });
    } catch (err) {
        res.status(500).send("Failed to generate hash.");
    }
});
// =========================================================
// ✅ Start server
app.listen(PORT, () => console.log(`🚀 Server running on port ${PORT}`));
