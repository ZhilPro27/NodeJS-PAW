const Barang = require('../Models/barangModel');

exports.getAllBarang = (req, res) => {
    Barang.getAllBarang((err, result) => {
        if(err) {
            res.status(500).json({ error: err });
        } else {
            res.json(result);
        }
    });
};

exports.getBarangById = (req, res) => {
    const id = req.params.id;
    Barang.getBarangById(id, (err, result) => {
        if(err) {
            res.status(500).json({ error: err });
        } else {
            res.json(result);
        }
    });
};

exports.createBarang = (req, res) => {
    const barangData = { ...req.body };

    if (req.file) {
        barangData.gambar = req.file.filename;
    }

    Barang.createBarang(barangData, (err, result) => {
        if (err) {
            return res.status(500).json({ error: err.message || "Terjadi kesalahan server." });
        }
        res.status(201).json({ message: "Barang berhasil dibuat", id: result.insertId });
    });
};

exports.updateBarang = (req, res) => {
    const id = req.params.id;
    const barangData = { ...req.body };

    if (req.file) {
        barangData.gambar = req.file.filename;
    }

    Barang.updateBarang(id, barangData, (err, result) => {
        if (err) {
            if (err.message === "Barang tidak ditemukan") {
                return res.status(404).json({ error: err.message });
            }
            return res.status(500).json({ error: err.message || "Terjadi kesalahan server." });
        }

        if (result.affectedRows === 0) {
            return res.status(404).json({ message: `Barang dengan id ${id} tidak ditemukan.` });
        }

        res.json({ message: "Barang berhasil diperbarui" });
    });
};

exports.deleteBarang = (req, res) => {
    const id = req.params.id;
    Barang.deleteBarang(id, (err, result) => {
        if(err) {
            res.status(500).json({ error: err });
        } else {
            res.json({ message: "Barang deleted successfully" });
        }
    });
};

exports.cekKetersediaan = (req, res) => {
    const id = req.params.id;
    const jumlahDibutuhkan = req.body.jumlah;

    Barang.cekKetersediaan(id, jumlahDibutuhkan, (err, result) => {
        if(err) {
            res.status(500).json({ error: err });
        } else {
            res.json({ tersedia: result });
        }
    });
};

exports.updateStokBarang = (req, res) => {
    const id = req.params.id;
    const jumlah = req.body.jumlah;

    Barang.updateStokBarang(id, jumlah, (err, result) => {
        if(err) {
            res.status(500).json({ error: err });
        } else {
            res.json({ message: "Stok barang updated successfully" });
        }
    });
};

exports.isTersedia = (req, res) => {
    const id = req.params.id;
    Barang.isTersedia(id, (err, result) => {
        if(err) {
            res.status(500).json({ error: err });
        } else {
            res.json({ tersedia: result });
        }
    });
};

exports.searchBarang = (req, res) => {
    const keyword = req.query.keyword || '';
    Barang.searchBarang(keyword, (err, result) => {
        if(err) {
            res.status(500).json({ error: err });
        } else {
            res.json(result);
        }
    });
};