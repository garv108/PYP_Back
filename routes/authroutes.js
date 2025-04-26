const express = require('express');
const router = express.Router();
const authController = require('../controllers/authController');

// POST route for signup
router.post('/signup', authController.signup);

module.exports = router;
