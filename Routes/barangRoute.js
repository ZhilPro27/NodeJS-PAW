const express = require('express');
const router = express.Router();
const barangController = require('../Controllers/barangController');
const path = require('path');
const multer = require('multer');
const fs = require('fs');

const uploadDir = path.join(__dirname, '../uploads');
if(!fs.existsSync(uploadDir)){
    fs.mkdirSync(uploadDir);
}

const storage = multer.diskStorage({
    destination: function (req, file, cb) {
        cb(null, uploadDir);
    },
    filename: function (req, file, cb) {
        const uniqueSuffix = Date.now() + path.extname(file.originalname);
        cb(null, 'barang-' + uniqueSuffix);
    }
});

const upload = multer({ 
    storage: storage,
    fileFilter: (req, file, cb) => {
        const allowedTypes = /jpeg|jpg|png|gif/;
        const mimetype = allowedTypes.test(file.mimetype);
        const extname = allowedTypes.test(path.extname(file.originalname).toLowerCase());
        
        if (mimetype && extname) {
            return cb(null, true);
        }
        cb('Error: Hanya file gambar (jpeg, jpg, png, gif) yang diizinkan!');
    }
});



router.get('/barang', barangController.getAllBarang);
router.get('/barang/:id', barangController.getBarangById);
router.post('/barang', upload.single('gambar'), barangController.createBarang);
router.put('/barang/:id', upload.single('gambar'), barangController.updateBarang);
router.delete('/barang/:id', barangController.deleteBarang);
router.post('/barang/search', barangController.searchBarang);
router.get('/barang/cekKetersediaan', barangController.cekKetersediaan);
router.post('/barang/updateStok', barangController.updateStokBarang);

module.exports = router;
