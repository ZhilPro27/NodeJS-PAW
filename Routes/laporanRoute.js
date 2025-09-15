const express = require('express');
const router = express.Router();
const LaporanController = require('../Controllers/laporanController');

router.get('/ringkasan', LaporanController.getRingkasan);
router.get('/barang-terlaris', LaporanController.getBarangTerlaris);
router.get('/penjualan-pdf', LaporanController.generateLaporanPDF);

module.exports = router;