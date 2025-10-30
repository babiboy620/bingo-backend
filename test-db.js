const { poolPromise } = require("./db");

async function testConnection() {
  try {
    const pool = await poolPromise;
    const result = await pool.request().query("SELECT 1 AS number");
    console.log("✅ Database test query result:", result.recordset);
  } catch (err) {
    console.error("❌ Database test failed:", err);
  }
}

testConnection();
