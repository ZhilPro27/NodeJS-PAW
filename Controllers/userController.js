const User = require('../Models/userModel');
const bcrypt = require('bcryptjs');

exports.register = async (req, res) => {
  try {
    const { nama, email, password } = req.body;
    if (!nama || !email || !password) {
      return res.status(400).json({ message: "Semua field wajib diisi." });
    }

    const existingUser = await User.findByEmail(email);
    if (existingUser) {
      return res.status(409).json({ message: "Email sudah terdaftar." });
    }

    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);

    const newUser = { nama, email, password: hashedPassword };
    const result = await User.create(newUser);

    res.status(201).json({ message: "Registrasi berhasil!", userId: result.insertId });
  } catch (error) {
    console.error("Registrasi gagal:", error);
    res.status(500).json({ message: "Terjadi kesalahan pada server." });
  }
};

exports.getProfile = async (req, res) => {
  try {
    const userProfile = await User.findById(req.user.id);
    if (!userProfile) {
      return res.status(404).json({ message: "User tidak ditemukan." });
    }
    res.json(userProfile);
  } catch (error) {
    res.status(500).json({ message: "Terjadi kesalahan pada server." });
  }
};