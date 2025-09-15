const express = require('express');
const router = express.Router();
const authController = require('../Controllers/authcontroller');
const authMiddleware = require('../Middleware/auth');

router.post('/login', authController.login);
router.post('/logout', authMiddleware, authController.logout);

module.exports = router;