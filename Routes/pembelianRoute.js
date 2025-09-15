const express = require('express');
const router = express.Router();
const pembelianController = require('../Controllers/pembelianController');
const authMiddleware = require('../Middleware/auth');

router.get('/pembelian', pembelianController.getAllPembelian);
router.get('/pembelian/:id', pembelianController.getPembelianById);
router.post('/pembelian', pembelianController.createPembelian);
router.put('/pembelian/:id', pembelianController.updatePembelian);
router.delete('/pembelian/:id', pembelianController.deletePembelian);
router.get('/pembelian/hitungTotalHarga/:id', pembelianController.hitungTotalHargaPembelian);
router.post('/pembelian/pesanan', authMiddleware, pembelianController.createPesanan);
router.get('/pembelian/pesanan', authMiddleware, pembelianController.getPembelianByStatus);
router.put('/pembelian/pesanan/:id/status', authMiddleware, pembelianController.updateStatusPesanan);

module.exports = router;
