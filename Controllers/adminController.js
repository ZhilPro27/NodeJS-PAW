const Admin = require('../Models/adminModel');
const Log = require('../Models/logModel');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

exports.register = (req, res) => {
    const { username, password } = req.body;

    bcrypt.hash(password, 10, (err, hash) => {
        if (err) {
            return res.status(500).json({ error: err });
        }

        const newAdmin = {
            username,
            password: hash,
            role: 'Admin'
        };

        Admin.createAdmin(newAdmin, (err, result) => {
            if (err) {
                res.status(500).json({ error: err });
            } else {
                res.status(201).json({ message: "Admin registered successfully", adminId: result.insertId });
            }
        });
    });
};

exports.login = (req, res) => {
  const { username, password } = req.body;
  if (!username || !password)
    return res.status(400).json({ msg: "Please enter all fields" });
  
  Admin.getAdminByUsername(username, async (err, results) => {
    const user = results[0];
      if (!user) return res.status(400).json({ msg: "Invalid credentials" });

      const isMatch = await bcrypt.compare(password, user.password);
      if (!isMatch) return res.status(400).json({ msg: "Invalid credentials" });

      const token = jwt.sign({ id: user.id }, "your_super_secret_jwt_key", {
        expiresIn: 3600,
      });
      res.json({ 
        token, 
        user: { 
          id: user.id, 
          username: user.username 
        } 
      });
    });
};

exports.getAllAdmins = (req, res) => {
    Admin.getAllAdmins((err, result) => {
        if(err) {
            res.status(500).json({ error: err });
        } else {
            res.json(result);
        }
    });
};

exports.getAdminById = (req, res) => {
    const id = req.params.id;
    Admin.getAdminById(id, (err, result) => {
        if(err) {
            res.status(500).json({ error: err });
        } else {
            res.json(result);
        }
    });
};

exports.updateAdmin = (req, res) => {
    const id = req.params.id;
    const adminData = req.body;
    Admin.updateAdmin(id, adminData, (err, result) => {
        if(err) {
            res.status(500).json({ error: err });
        } else {
            res.json({ message: "Admin updated successfully" });
        }
    });
};

exports.deleteAdmin = (req, res) => {
    const id = req.params.id;
    Admin.deleteAdmin(id, (err, result) => {
        if(err) {
            res.status(500).json({ error: err });
        } else {
            res.json({ message: "Admin deleted successfully" });
        }
    });
};

exports.logs = async (req, res) => {
  const page = parseInt(req.query.page) || 1;
  const limit = parseInt(req.query.limit) || 10;

  try {
    const logs = await Log.getAllLogs(page, limit);
    res.json(logs);
  } catch (error) {
    console.error("Gagal memuat log:", error);
    res.status(500).json({ error: "Gagal memuat log" });
  }
};
