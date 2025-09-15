const db = require('../Database/db');

const Log = {
  createLog: async (logData) => {
    const sql = "INSERT INTO auth_logs SET ?";
    try {
      const [result] = await db.promise().query(sql, logData);
      return result;
    } catch (error) {
      console.error("Gagal membuat log:", error);
    }
  },


  getAllLogs: async (page = 1, limit = 15) => {
    const offset = (page - 1) * limit;
    try {
      const sqlData = "SELECT id, DATE_FORMAT(timestamp, '%d-%m-%Y %H:%i:%s') as timestamp, event_type, user_id, role, ip_address, success FROM auth_logs ORDER BY timestamp DESC LIMIT ? OFFSET ?";
      const [rows] = await db.promise().query(sqlData, [limit, offset]);
      
      const sqlCount = "SELECT COUNT(*) as total FROM auth_logs";
      const [countRows] = await db.promise().query(sqlCount);

      return { data: rows, total: countRows[0].total };
    } catch (error) {
      throw error;
    }
  }
};

module.exports = Log;