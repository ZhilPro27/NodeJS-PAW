const express = require('express');
const router = express.Router();
const adminController = require('../Controllers/adminController');

router.post('/register', adminController.register);
router.post('/login', adminController.login);
router.get('/admins', adminController.getAllAdmins);
router.get('/admins/:id', adminController.getAdminById);
router.put('/admins/:id', adminController.updateAdmin);
router.delete('/admins/:id', adminController.deleteAdmin);
router.get('/logs', adminController.logs);

module.exports = router;