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
<<<<<<< HEAD
  .catch((err) =>
    console.error("❌ PostgreSQL connection failed:", err.message)
  );
=======
  .catch((err) => console.error("❌ PostgreSQL connection failed:", err.message));
>>>>>>> 88b0bea498a73b2d91c073a90895dc022a009c45

module.exports = { pool };
