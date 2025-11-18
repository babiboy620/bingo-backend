// db.js (HARDENED VERSION)
require("dotenv").config();
const { Pool } = require("pg");

// Create PostgreSQL connection pool
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: {
    rejectUnauthorized: false, // Required for Render's PostgreSQL
  },
});

// REMOVE THE .connect().then().catch() BLOCK! 
// It can cause issues with unhandled rejections on startup.

// Export the pool
module.exports = { pool };
