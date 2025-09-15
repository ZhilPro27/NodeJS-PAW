const express = require('express');
const router = express.Router();
const detailPembelianController = require('../Controllers/detailPembelianController');

router.get('/detailPembelian', detailPembelianController.getAllDetailPembelian);
router.get('/detailPembelian/:id', detailPembelianController.getDetailPembelianById);
router.post('/detailPembelian', detailPembelianController.createDetailPembelian);
router.put('/detailPembelian/:id', detailPembelianController.updateDetailPembelian);
router.delete('/detailPembelian/:id', detailPembelianController.deleteDetailPembelian);
router.get('/detailPembelian/hitungSubTotal/:id', detailPembelianController.hitungSubTotal);

module.exports = router;