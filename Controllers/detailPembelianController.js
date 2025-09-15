const detailPembelian = require('../Models/detailPembelianModel');

exports.getAllDetailPembelian = (req, res) => {
    detailPembelian.getAllDetailPembelian((err, result) => {
        if(err) {
            res.status(500).json({ error: err });
        } else {
            res.json(result);
        }
    });
};

exports.getDetailPembelianById = (req, res) => {
    const id = req.params.id;
    detailPembelian.getDetailPembelianById(id, (err, result) => {
        if(err) {
            res.status(500).json({ error: err });
        } else {
            res.json(result);
        }
    });
};

exports.createDetailPembelian = (req, res) => {
    const detailPembelianData = req.body;
    detailPembelian.createDetailPembelian(detailPembelianData, (err, result) => {
        if(err) {
            res.status(500).json({ error: err });
        } else {
            res.status(201).json({ message: "Detail Pembelian created successfully", detailPembelianId: result.insertId });
        }
    });
};

exports.updateDetailPembelian = (req, res) => {
    const id = req.params.id;
    const detailPembelianData = req.body;
    detailPembelian.updateDetailPembelian(id, detailPembelianData, (err, result) => {
        if(err) {
            res.status(500).json({ error: err });
        } else {
            res.json({ message: "Detail Pembelian updated successfully" });
        }
    });
};

exports.deleteDetailPembelian = (req, res) => {
    const id = req.params.id;
    detailPembelian.deleteDetailPembelian(id, (err, result) => {
        if(err) {
            res.status(500).json({ error: err });
        } else {
            res.json({ message: "Detail Pembelian deleted successfully" });
        }
    });
};

exports.hitungSubTotal = (req, res) => {
    const id = req.params.id;
    detailPembelian.hitungSubTotal(id, (err, result) => {
        if(err) {
            res.status(500).json({ error: err });
        } else {
            res.json({ subtotal: result });
        }
    });
};