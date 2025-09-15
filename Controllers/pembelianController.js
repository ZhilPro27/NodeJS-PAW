const Pembelian = require('../Models/pembelianModel');



exports.getAllPembelian = (req, res) => {
    Pembelian.getAllPembelian((err, result) => {
        if(err) {
            res.status(500).json({ error: err });
        } else {
            res.json(result);
        }
    });
};

exports.getPembelianById = (req, res) => {
    const id = req.params.id;
    Pembelian.getPembelianById(id, (err, result) => {
        if(err) {
            res.status(500).json({ error: err });
        } else {
            res.json(result);
        }
    });
};

exports.createPembelian = (req, res) => {
    const pembelianData = req.body;
    Pembelian.createPembelian(pembelianData, (err, result) => {
        if(err) {
            res.status(500).json({ error: err });
        } else {
            res.status(201).json({ message: "Pembelian created successfully", pembelianId: result.insertId });
        }
    });
};

exports.updatePembelian = (req, res) => {
    const id = req.params.id;
    const pembelianData = req.body;
    Pembelian.updatePembelian(id, pembelianData, (err, result) => {
        if(err) {
            res.status(500).json({ error: err });
        } else {
            res.json({ message: "Pembelian updated successfully" });
        }
    });
};

exports.deletePembelian = (req, res) => {
    const id = req.params.id;
    Pembelian.deletePembelian(id, (err, result) => {
        if(err) {
            res.status(500).json({ error: err });
        } else {
            res.json({ message: "Pembelian deleted successfully" });
        }
    });
};

exports.hitungTotalHargaPembelian = (req, res) => {
    const id = req.params.id;
    Pembelian.hitungTotalHargaPembelian(id, (err, result) => {
        if(err) {
            res.status(500).json({ error: err });
        } else {
            res.json({ total: result });
        }
    });
};

exports.createPesanan = async (req, res) => {
  try {
    const pesananData = {
      ...req.body,
      userId: req.user.id 
    };
    const result = await Pembelian.createPesanan(pesananData);
    res.status(201).json(result);
  } catch (error) { 
    console.error("Gagal membuat pesanan:", error);
    res.status(500).json({ message: "Terjadi kesalahan pada server." });
  }
};

exports.updateStatusPesanan = async (req, res) => {
  try {
    const { id } = req.params;
    const { status } = req.body; 
    const result = await Pembelian.updateStatusPesanan(id, status);
    res.json({ message: `Pesanan berhasil diubah menjadi ${status}` });
  } catch (error) { 
    console.error("Gagal memperbarui status pesanan:", error);
    res.status(500).json({ message: "Terjadi kesalahan pada server." });
  }
};

exports.getPembelianByStatus = async (req, res) => {
    try {
        const { status } = req.query; 
        console.log("Mencari pesanan dengan status:", status);
        const pesanan = await Pembelian.getPembelianByStatus(status);
        console.log("Hasil query dari model:", pesanan);
        res.json(pesanan);
    } catch (error) { 
        console.error("Gagal mengambil pesanan berdasarkan status:", error);
        res.status(500).json({ message: "Terjadi kesalahan pada server." });
     }
};