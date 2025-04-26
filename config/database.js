// backend/db.js
const mongoose = require('mongoose');
require('dotenv').config();
const logger = require('./utils/logger'); // Assuming you have a logger

const connectDB = async () => {
  // Validate environment variables
  if (!process.env.MONGO_URI) {
    logger.error('❌ FATAL: MONGO_URI not defined in .env');
    process.exit(1);
  }

  // Connection configuration
  const options = {
    dbName: process.env.DB_NAME || 'GPBASE',
    autoIndex: process.env.NODE_ENV !== 'production', // Better performance
    maxPoolSize: 10, // Default connection pool size
    serverSelectionTimeoutMS: 5000, // Timeout after 5s
    socketTimeoutMS: 45000, // Close sockets after 45s inactivity
  };

  try {
    await mongoose.connect(process.env.MONGO_URI, options);
    
    logger.info('✅ MongoDB connected successfully', {
      dbName: options.dbName,
      host: mongoose.connection.host
    });

    // Connection event listeners
    mongoose.connection.on('connected', () => {
      logger.info('Mongoose connected to DB');
    });

    mongoose.connection.on('error', (err) => {
      logger.error('Mongoose connection error:', err);
    });

    mongoose.connection.on('disconnected', () => {
      logger.warn('Mongoose disconnected from DB');
    });

    // Graceful shutdown
    process.on('SIGINT', async () => {
      await mongoose.connection.close();
      logger.info('Mongoose connection closed due to app termination');
      process.exit(0);
    });

  } catch (error) {
    logger.error('❌ MongoDB connection failed', {
      error: error.message,
      stack: error.stack
    });
    process.exit(1);
  }
};

module.exports = connectDB;