const express = require("express");
const router = express.Router();
const userController = require("../Controllers/userController");
const authMiddleware = require("../Middleware/auth");

router.post("/register", userController.register);
router.get('/profile', authMiddleware, userController.getProfile);

module.exports = router;