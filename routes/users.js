require('dotenv').config();
const express = require('express');
const router = express.Router();
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { body, validationResult } = require('express-validator');
const rateLimit = require('express-rate-limit');
const User = require('../models/user');
const logger = require('../utils/logger'); // Winston or Pino logger

// ======================
// 🛡️ Security Config
// ======================
const JWT_SECRET = process.env.JWT_SECRET;
if (!JWT_SECRET || JWT_SECRET.length < 32) {
  throw new Error('FATAL: JWT_SECRET must be 32+ chars in .env');
}

const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 5, // 5 attempts
  keyGenerator: (req) => req.headers['x-real-ip'] || req.ip,
  handler: (req, res) => {
    logger.warn(`Rate limit exceeded for IP: ${req.ip}`);
    return res.status(429).json({ 
      error: 'Too many attempts. Try again in 15 minutes.' 
    });
  }
});

// ======================
// 🚀 Routes
// ======================

// ✅ Health Check
router.get('/test', (req, res) => {
  res.json({ 
    status: 'Operational',
    timestamp: new Date().toISOString()
  });
});

// 🔐 Signup
router.post(
  '/signup',
  limiter,
  [
    body('name')
      .trim()
      .escape()
      .notEmpty()
      .withMessage('Name is required')
      .isLength({ max: 50 }),
    body('email')
      .trim()
      .toLowerCase()
      .normalizeEmail()
      .isEmail()
      .withMessage('Invalid email'),
    body('password')
      .isLength({ min: 8 })
      .withMessage('Must be at least 8 characters')
      .matches(/[0-9]/)
      .withMessage('Must contain a number')
      .matches(/[A-Z]/)
      .withMessage('Must contain uppercase letter')
  ],
  async (req, res) => {
    try {
      // Validate input
      const errors = validationResult(req);
      if (!errors.isEmpty()) {
        logger.debug('Validation failed', { errors: errors.array() });
        return res.status(400).json({ errors: errors.array() });
      }

      const { name, email, password } = req.body;

      // Check for existing user (case-insensitive)
      const existingUser = await User.findOne({ 
        email: { $regex: new RegExp(`^${email}$`, 'i') } 
      });
      if (existingUser) {
        logger.info(`Signup attempt with existing email: ${email}`);
        return res.status(409).json({ error: 'Email already in use' });
      }

      // Hash password
      const hashedPassword = password; // Let the model handle hashing

      // Create user
      const user = new User({
        name,
        email: email.toLowerCase(),
        password: hashedPassword
      });

      await user.save();
      logger.info(`New user created: ${user._id}`);

      // Generate token
      const token = jwt.sign(
        { userId: user._id },
        JWT_SECRET,
        { expiresIn: '24h' }
      );

      // Secure cookie settings
      res.cookie('token', token, {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'strict',
        maxAge: 24 * 60 * 60 * 1000 // 24h
      });

      return res.status(201).json({
        message: 'User created successfully',
        user: {
          id: user._id,
          name: user.name,
          email: user.email
        }
      });

    } catch (error) {
      logger.error('Signup error', { 
        error: error.message,
        stack: error.stack,
        email: req.body.email 
      });
      return res.status(500).json({ error: 'Account creation failed' });
    }
  }
);

// 🔐 Login
router.post(
  '/login',
  limiter,
  [
    body('email')
      .trim()
      .toLowerCase()
      .normalizeEmail()
      .isEmail()
      .withMessage('Invalid email'),
    body('password')
      .notEmpty()
      .withMessage('Password is required')
  ],
  async (req, res) => {
    try {
      // Validate input
      const errors = validationResult(req);
      if (!errors.isEmpty()) {
        return res.status(400).json({ errors: errors.array() });
      }

      const { email, password } = req.body;
      const normalizedEmail = email.toLowerCase();

      // Find user (temporarily include password)
      const user = await User.findOne({ email: normalizedEmail })
        .select('+password');

      if (!user) {
        logger.warn(`Login attempt for non-existent email: ${normalizedEmail}`);
        return res.status(401).json({ error: 'Invalid credentials' });
      }

      // Check password
      const isMatch = await bcrypt.compare(password, user.password);
      if (!isMatch) {
        logger.warn(`Failed login attempt for user: ${user._id}`);
        return res.status(401).json({ error: 'Invalid credentials' });
      }

      // Generate token
      const token = jwt.sign(
        { userId: user._id },
        JWT_SECRET,
        { expiresIn: '24h' }
      );

      // Secure cookie settings
      res.cookie('token', token, {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'strict',
        maxAge: 24 * 60 * 60 * 1000 // 24h
      });

      logger.info(`User logged in: ${user._id}`);
      return res.json({
        message: 'Login successful',
        user: {
          id: user._id,
          name: user.name,
          email: user.email
        }
      });

    } catch (error) {
      logger.error('Login error', {
        error: error.message,
        stack: error.stack,
        email: req.body.email
      });
      return res.status(500).json({ error: 'Authentication failed' });
    }
  }
);

// 🚪 Logout
router.post('/logout', (req, res) => {
  res.clearCookie('token', {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'strict'
  });
  return res.json({ message: 'Logged out successfully' });
});

module.exports = router;