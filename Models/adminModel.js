const db = require("../Database/db");

const Admin = {
  getAllAdmins: async () => {
    const sql = "SELECT id, username, nama FROM admin";
    try {
      const [rows] = await db.promise().query(sql);
      return rows;
    } catch (error) {
      throw error;
    }
  },

  getAdminById: async (id) => {
    const sql = "SELECT id, username, nama FROM admin WHERE id = ?";
    try {
      const [rows] = await db.promise().query(sql, [id]);
      return rows[0] || null;
    } catch (error) {
      throw error;
    }
  },

  getAdminByUsername: async (username) => {
    const sql = "SELECT * FROM admin WHERE username = ?";
    try {
      const [rows] = await db.promise().query(sql, [username]);
      return rows[0] || null;
    } catch (error) {
      throw error;
    }
  },

  createAdmin: async (adminData) => {
    const sql = "INSERT INTO admin SET ?";
    try {
      const [result] = await db.promise().query(sql, adminData);
      return result;
    } catch (error) {
      throw error;
    }
  },

  updateAdmin: async (id, adminData) => {
    const sql = "UPDATE admin SET ? WHERE id = ?";
    try {
      const [result] = await db.promise().query(sql, [adminData, id]);
      return result;
    } catch (error) {
      throw error;
    }
  },

  deleteAdmin: async (id) => {
    const sql = "DELETE FROM admin WHERE id = ?";
    try {
      const [result] = await db.promise().query(sql, [id]);
      return result;
    } catch (error) {
      throw error;
    }
  }
};

module.exports = Admin;