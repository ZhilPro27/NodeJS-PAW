const db = require('../Database/db');

const User = {
  create: async (userData) => {
    const sql = "INSERT INTO users SET ?";
    try {
      const [result] = await db.promise().query(sql, userData);
      return result;
    } catch (error) {
      throw error;
    }
  },
  findByEmail: async (email) => {
    const sql = "SELECT * FROM users WHERE email = ?";
    try {
      const [rows] = await db.promise().query(sql, [email]);
      return rows[0] || null;
    } catch (error) {
      throw error;
    }
  },
  findByUsername: async (username) => {
    const sql = "SELECT * FROM users WHERE username = ?";
    try {
      const [rows] = await db.promise().query(sql, [username]);
      return rows[0] || null;
    } catch (error) {
      throw error;
    }
  },
  findById: async (id) => {
    const sql = "SELECT id, nama, email, created_at FROM users WHERE id = ?";
    try {
      const [rows] = await db.promise().query(sql, [id]);
      return rows[0] || null;
    } catch (error) {
      throw error;
    }
  },
};

module.exports = User;