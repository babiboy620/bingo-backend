// db.js
require("dotenv").config();
const { Pool } = require("pg");

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: {
    rejectUnauthorized: false, // Render/Postgres usually needs SSL
  },
});

pool
  .connect()
  .then(() => console.log("✅ Connected to PostgreSQL database"))
  .catch((err) =>
    console.error("❌ PostgreSQL connection failed:", err.message)
  );

module.exports = { pool };
