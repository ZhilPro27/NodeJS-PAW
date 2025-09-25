const Admin = require('../Models/adminModel');
const User = require('../Models/userModel');
const Log = require('../Models/logModel');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const logger = require('../config/logger');

exports.login = async (req, res) => {
  try {
    const { username, password } = req.body;
    const ip_address = req.ip;
    logger.info(`Upaya login untuk user: ${username}`);
    
    const admin = await Admin.getAdminByUsername(username);
    if (admin) {
      const isMatch = await bcrypt.compare(password, admin.password);
      if (isMatch) {
        await Log.createLog({ event_type: 'login', user_id: admin.username, role: 'admin', ip_address, success: true });
        const token = jwt.sign(
          { id: admin.id, username: admin.username, role: 'admin' },
          "your_super_secret_jwt_key", 
          { expiresIn: '1h' }
        );
        logger.info(`Login berhasil untuk admin: ${username}`);
        return res.json({ token, user: { id: admin.id, username: admin.username, role: 'admin' } });
      }
    }

    const user = await User.findByEmail(username);
    if (user) {
      const isMatch = await bcrypt.compare(password, user.password);
      if (isMatch) {
        await Log.createLog({ event_type: 'login', user_id: user.email, role: 'user', ip_address, success: true });
        const token = jwt.sign(
          { id: user.id, email: user.email, role: 'user' },
          "your_super_secret_jwt_key",
          { expiresIn: '8h' }
        );
        logger.info(`Login berhasil untuk user: ${username}`);
        return res.json({ token, user: { id: user.id, email: user.email, nama: user.nama, role: 'user' } });
      }
    }
    logger.warn(`Login gagal untuk user: ${username}`);
    return res.status(401).json({ message: "Kredensial tidak valid." });

  } catch (error) {
    console.error("Login gagal:", error);
    logger.error(`Error saat login: ${error.message}`, { stack: error.stack });
    res.status(500).json({ message: "Terjadi kesalahan pada server." });
  }
};

exports.logout = async (req, res) => {
  try {
    const { username, email, role } = req.user;
    const user_id = role === 'admin' ? username : email;

    await Log.createLog({ event_type: 'logout', user_id, role, success: true, ip_address: req.ip });
    res.json({ message: "Logout berhasil dicatat." });
  } catch (error) {
    console.error("Gagal mencatat logout:", error);
    res.status(500).json({ message: "Terjadi kesalahan pada server." });
  }
};