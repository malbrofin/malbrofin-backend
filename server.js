const express = require("express");
const cors = require("cors");
const { Pool } = require("pg");
const jwt = require("jsonwebtoken");
const admin = require("firebase-admin");
require("dotenv").config();

const app = express();
app.use(cors());
app.use(express.json());

// 🔐 Initialize Firebase Admin
admin.initializeApp({
  credential: admin.credential.applicationDefault(),
});

// 🗄 Database connection
const pool = new Pool({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
  port: process.env.DB_PORT,
  ssl: { rejectUnauthorized: false }
});

// 👑 ADMIN LOGIN (Firebase Verified)
app.post("/admin-login", async (req, res) => {
  try {
    const { firebaseToken } = req.body;

    const decoded = await admin.auth().verifyIdToken(firebaseToken);
    const phone = decoded.phone_number.replace("+", "");

    const userResult = await pool.query(
      "SELECT * FROM users WHERE phone = $1 AND role = 'admin' AND is_active = TRUE",
      [phone]
    );

    if (userResult.rows.length === 0) {
      return res.status(403).json({ message: "Admin not authorized" });
    }

    const user = userResult.rows[0];

    const token = jwt.sign(
      { id: user.id, role: user.role },
      process.env.JWT_SECRET,
      { expiresIn: "24h" }
    );

    res.json({ token });

  } catch (err) {
    res.status(401).json({ error: err.message });
  }
});

// 🔐 Middleware to protect routes
const authenticate = (roles) => {
  return (req, res, next) => {
    const authHeader = req.headers.authorization;
    if (!authHeader) return res.status(401).json({ message: "No token" });

    const token = authHeader.split(" ")[1];

    try {
      const decoded = jwt.verify(token, process.env.JWT_SECRET);
      if (!roles.includes(decoded.role)) {
        return res.status(403).json({ message: "Access denied" });
      }
      req.user = decoded;
      next();
    } catch (err) {
      res.status(401).json({ message: "Invalid token" });
    }
  };
};

// 🧪 Test protected route
app.get("/admin-dashboard", authenticate(['admin']), (req, res) => {
  res.json({ message: "Welcome Admin", user: req.user });
});

app.get("/", (req, res) => {
  res.send("Malbrofin Backend Running Successfully");
});

app.get("/test-db", async (req, res) => {
  try {
    const result = await pool.query("SELECT NOW()");
    res.json(result.rows);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

const PORT = process.env.PORT || 10000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
