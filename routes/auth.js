import express from "express";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import { findByUsername } from "../utils/db.js";

const router = express.Router();

// ─────────────────────────────────────────
// POST /api/auth/login
// ─────────────────────────────────────────
router.post("/login", async (req, res) => {
  const { username, password } = req.body;

  // 1. Validasi input: kedua field wajib diisi
  if (!username || !password) {
    return res
      .status(400)
      .json({ error: "Username and password are required" });
  }

  // 2. Cari user berdasarkan username
  const user = findByUsername(username);
  if (!user) {
    // Jangan tulis "Username tidak ditemukan" — itu membocorkan informasi!
    return res.status(401).json({ error: "Invalid credentials" });
  }

  // 3. Verifikasi password menggunakan bcrypt
  const isPasswordValid = await bcrypt.compare(password, user.passwordHash);
  if (!isPasswordValid) {
    return res.status(401).json({ error: "Invalid credentials" });
  }

  // 4. Generate JWT token
  const payload = {
    id: user.id,
    role: user.role
  };
  
  const token = jwt.sign(payload, process.env.JWT_SECRET || "default_secret", { expiresIn: "1h" });

  res.status(200).json({
    message: "Login successful",
    token: token
  });
});

export default router;
