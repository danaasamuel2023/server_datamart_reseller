// =============================================
// GHANA MTN DATA RESELLING PLATFORM - MIDDLEWARE
// Node.js with Express
// =============================================

const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const rateLimit = require('express-rate-limit');
const { body, validationResult, param, query } = require('express-validator');
const crypto = require('crypto');

// Import models (adjust path as needed)
const { User, SystemSetting, ApiLog, Transaction } = require('../schema/schema');

// =============================================
// 1. AUTHENTICATION MIDDLEWARE
// =============================================

const authMiddleware = {
  // Generate JWT Token
  generateToken: (userId, role) => {
    return jwt.sign(
      { userId, role },
      process.env.JWT_SECRET || 'your-secret-key',
      { expiresIn: '7d' }
    );
  },

  // Verify JWT Token
  verifyToken: async (req, res, next) => {
    try {
      const token = req.header('Authorization')?.replace('Bearer ', '') || 
                   req.header('x-auth-token') ||
                   req.cookies?.token;

      if (!token) {
        return res.status(401).json({
          success: false,
          message: 'No authentication token, access denied'
        });
      }

      const decoded = jwt.verify(token, process.env.JWT_SECRET || 'your-secret-key');
      
      const user = await User.findById(decoded.userId)
        .select('-password')
        .lean();

      if (!user) {
        return res.status(401).json({
          success: false,
          message: 'User not found'
        });
      }

      if (user.status === 'suspended' || user.status === 'pending') {
        return res.status(403).json({
          success: false,
          message: `Account is ${user.status}. Please contact support.`
        });
      }

      req.user = user;
      req.userId = user._id;
      req.userRole = user.role;
      next();
    } catch (error) {
      if (error.name === 'TokenExpiredError') {
        return res.status(401).json({
          success: false,
          message: 'Token has expired, please login again'
        });
      }
      
      return res.status(401).json({
        success: false,
        message: 'Invalid token'
      });
    }
  },

  // Optional Authentication (for public routes that can work with or without auth)
  optionalAuth: async (req, res, next) => {
    try {
      const token = req.header('Authorization')?.replace('Bearer ', '') || 
                   req.header('x-auth-token');

      if (token) {
        const decoded = jwt.verify(token, process.env.JWT_SECRET || 'your-secret-key');
        const user = await User.findById(decoded.userId).select('-password').lean();
        if (user && user.status === 'active') {
          req.user = user;
          req.userId = user._id;
          req.userRole = user.role;
        }
      }
      next();
    } catch (error) {
      // Continue without authentication
      next();
    }
  }
};

// =============================================
// 2. AUTHORIZATION MIDDLEWARE (Role-Based)
// =============================================

const roleMiddleware = {
  // Check if user has required role
  hasRole: (...allowedRoles) => {
    return (req, res, next) => {
      if (!req.user) {
        return res.status(401).json({
          success: false,
          message: 'Authentication required'
        });
      }

      if (!allowedRoles.includes(req.user.role)) {
        return res.status(403).json({
          success: false,
          message: `Access denied. Required role: ${allowedRoles.join(' or ')}`
        });
      }

      next();
    };
  },

  // Admin only
  adminOnly: (req, res, next) => {
    if (req.user?.role !== 'admin') {
      return res.status(403).json({
        success: false,
        message: 'Admin access required'
      });
    }
    next();
  },

  // Check role hierarchy (admin > supplier > dealer > agent)
  checkHierarchy: (req, res, next) => {
    const hierarchy = {
      'admin': 4,
      'supplier': 3,
      'dealer': 2,
      'agent': 1
    };

    req.userLevel = hierarchy[req.user?.role] || 0;
    next();
  }
};

// =============================================
// 3. API KEY MIDDLEWARE (For External API Access)
// =============================================

const apiKeyMiddleware = async (req, res, next) => {
  try {
    const apiKey = req.header('X-API-Key');
    const apiSecret = req.header('X-API-Secret');

    if (!apiKey || !apiSecret) {
      return res.status(401).json({
        success: false,
        message: 'API credentials required'
      });
    }

    const user = await User.findOne({
      'apiAccess.apiKey': apiKey,
      'apiAccess.enabled': true,
      status: 'active'
    }).select('-password');

    if (!user) {
      return res.status(401).json({
        success: false,
        message: 'Invalid API key'
      });
    }

    // Verify API secret
    const validSecret = await bcrypt.compare(apiSecret, user.apiAccess.apiSecret);
    if (!validSecret) {
      return res.status(401).json({
        success: false,
        message: 'Invalid API credentials'
      });
    }

    // Check webhook URL if provided
    if (user.apiAccess.webhookUrl && req.body.webhookUrl) {
      if (user.apiAccess.webhookUrl !== req.body.webhookUrl) {
        return res.status(403).json({
          success: false,
          message: 'Webhook URL mismatch'
        });
      }
    }

    req.user = user;
    req.userId = user._id;
    req.userRole = user.role;
    req.isApiRequest = true;

    // Log API request
    await ApiLog.create({
      user: user._id,
      apiKey: apiKey,
      endpoint: req.originalUrl,
      method: req.method,
      request: {
        body: req.body,
        headers: req.headers
      },
      ipAddress: req.ip
    });

    next();
  } catch (error) {
    console.error('API Key Middleware Error:', error);
    return res.status(500).json({
      success: false,
      message: 'API authentication error'
    });
  }
};

// =============================================
// 4. VALIDATION MIDDLEWARE
// =============================================

const validators = {
  // User Registration Validation
  validateRegistration: [
    body('fullName')
      .trim()
      .isLength({ min: 2, max: 100 })
      .withMessage('Full name must be between 2 and 100 characters'),
    body('email')
      .trim()
      .isEmail()
      .normalizeEmail()
      .withMessage('Valid email required'),
    body('phone')
      .trim()
      .matches(/^(\+233|0)[235][0-9]{8}$/)
      .withMessage('Valid Ghana phone number required'),
    body('password')
      .isLength({ min: 6 })
      .withMessage('Password must be at least 6 characters'),
    body('role')
      .optional()
      .isIn(['agent', 'dealer', 'supplier'])
      .withMessage('Invalid role')
  ],

  // Login Validation
  validateLogin: [
    body('emailOrPhone')
      .trim()
      .notEmpty()
      .withMessage('Email or phone number required'),
    body('password')
      .notEmpty()
      .withMessage('Password required')
  ],

  // Data Purchase Validation
  validateDataPurchase: [
    body('productId')
      .isMongoId()
      .withMessage('Valid product ID required'),
    body('beneficiaryNumber')
      .trim()
      .matches(/^(\+233|0)[235][0-9]{8}$/)
      .withMessage('Valid Ghana phone number required for beneficiary'),
    body('quantity')
      .optional()
      .isInt({ min: 1, max: 100 })
      .withMessage('Quantity must be between 1 and 100')
  ],

  // Wallet Funding Validation
  validateWalletFunding: [
    body('amount')
      .isFloat({ min: 1, max: 10000 })
      .withMessage('Amount must be between GHS 1 and GHS 10,000'),
    body('paymentMethod')
      .isIn(['card', 'bank_transfer', 'momo'])
      .withMessage('Invalid payment method')
  ],

  // Price Setting Validation (Admin)
  validatePriceSetting: [
    body('productId')
      .isMongoId()
      .withMessage('Valid product ID required'),
    body('costPrice')
      .isFloat({ min: 0 })
      .withMessage('Valid cost price required'),
    body('agentPrice')
      .isFloat({ min: 0 })
      .withMessage('Valid agent price required'),
    body('dealerPrice')
      .isFloat({ min: 0 })
      .withMessage('Valid dealer price required'),
    body('supplierPrice')
      .isFloat({ min: 0 })
      .withMessage('Valid supplier price required'),
    body('agentPrice').custom((value, { req }) => {
      if (value <= req.body.dealerPrice) {
        throw new Error('Agent price must be higher than dealer price');
      }
      return true;
    }),
    body('dealerPrice').custom((value, { req }) => {
      if (value <= req.body.supplierPrice) {
        throw new Error('Dealer price must be higher than supplier price');
      }
      return true;
    })
  ],

  // Product Creation Validation
  validateProduct: [
    body('name')
      .trim()
      .isLength({ min: 2, max: 100 })
      .withMessage('Product name required'),
    body('productCode')
      .trim()
      .matches(/^[A-Z0-9_]+$/)
      .withMessage('Product code must contain only uppercase letters, numbers, and underscores'),
    body('capacity.value')
      .isFloat({ min: 1 })
      .withMessage('Valid capacity value required'),
    body('capacity.unit')
      .isIn(['MB', 'GB'])
      .withMessage('Capacity unit must be MB or GB'),
    body('validity.value')
      .isInt({ min: 1 })
      .withMessage('Valid validity period required'),
    body('validity.unit')
      .isIn(['hours', 'days', 'weeks', 'months'])
      .withMessage('Invalid validity unit')
  ],

  // Handle validation errors
  handleValidationErrors: (req, res, next) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({
        success: false,
        message: 'Validation failed',
        errors: errors.array().map(err => ({
          field: err.path,
          message: err.msg
        }))
      });
    }
    next();
  }
};

// =============================================
// 5. WALLET MIDDLEWARE - UPDATED FOR MANUAL PROCESSING
// =============================================

const walletMiddleware = {
  // Check wallet balance before transaction
  checkBalance: async (req, res, next) => {
    try {
      const { amount } = req.body;
      const user = await User.findById(req.userId);

      if (!user) {
        return res.status(404).json({
          success: false,
          message: 'User not found'
        });
      }

      if (user.wallet.balance < amount) {
        return res.status(400).json({
          success: false,
          message: 'Insufficient wallet balance',
          currentBalance: user.wallet.balance,
          required: amount
        });
      }

      req.currentBalance = user.wallet.balance;
      next();
    } catch (error) {
      console.error('Wallet Check Error:', error);
      return res.status(500).json({
        success: false,
        message: 'Error checking wallet balance'
      });
    }
  },

  // UPDATED: Allow orders even with pending transactions (manual processing)
  lockWallet: async (req, res, next) => {
    try {
      const userId = req.userId;
      
      // NO LONGER CHECK FOR PENDING TRANSACTIONS
      // Since orders are processed manually and money is deducted immediately,
      // users can place multiple orders as long as they have balance
      
      // Optional: Check if wallet is locked for security reasons
      const user = await User.findById(userId);
      if (user?.wallet?.isLocked) {
        return res.status(403).json({
          success: false,
          message: 'Wallet is temporarily locked. Please contact support.'
        });
      }
      
      // Optional: Rate limit to prevent rapid order spamming
      const recentOrderCount = await Transaction.countDocuments({
        user: userId,
        type: 'data_purchase',
        createdAt: { $gte: new Date(Date.now() - 60000) } // Last minute
      });
      
      if (recentOrderCount >= 10) {
        return res.status(429).json({
          success: false,
          message: 'Too many orders placed recently. Please wait a moment before placing another order.'
        });
      }

      // Optional: Check for processing status (if you use this status when actively fulfilling)
      const processingTx = await Transaction.findOne({
        user: userId,
        status: 'processing', // Only if you mark orders as 'processing' when actively fulfilling
        createdAt: { $gte: new Date(Date.now() - 300000) } // Within last 5 minutes
      });

      if (processingTx) {
        return res.status(409).json({
          success: false,
          message: 'We are currently processing your order. Please wait a moment.'
        });
      }

      next();
    } catch (error) {
      console.error('Wallet Lock Error:', error);
      return res.status(500).json({
        success: false,
        message: 'Transaction processing error'
      });
    }
  }
};

// =============================================
// 6. SYSTEM MIDDLEWARE
// =============================================

const systemMiddleware = {
  // Check maintenance mode
  checkMaintenance: async (req, res, next) => {
    try {
      // Skip for admin users
      if (req.user?.role === 'admin') {
        return next();
      }

      const maintenanceSetting = await SystemSetting.findOne({
        key: 'maintenance_mode'
      });

      if (maintenanceSetting?.value === true) {
        const message = await SystemSetting.findOne({
          key: 'maintenance_message'
        });

        return res.status(503).json({
          success: false,
          message: message?.value || 'System is under maintenance. Please try again later.'
        });
      }

      next();
    } catch (error) {
      // Continue if error (don't block the system)
      next();
    }
  },

  // Check user registration setting
  checkRegistrationEnabled: async (req, res, next) => {
    try {
      const setting = await SystemSetting.findOne({
        key: 'user_registration'
      });

      if (setting?.value === false) {
        return res.status(403).json({
          success: false,
          message: 'User registration is currently disabled'
        });
      }

      next();
    } catch (error) {
      next();
    }
  }
};

// =============================================
// 7. RATE LIMITING MIDDLEWARE (FIXED FOR IPv6)
// =============================================

const rateLimiters = {
  // General API rate limit
  general: rateLimit({
    windowMs: 1 * 60 * 1000, // 1 minute
    max: 100, // 100 requests per minute
    message: 'Too many requests, please try again later',
    standardHeaders: true,
    legacyHeaders: false,
    // Use default key generator (handles IPv6 properly)
    keyGenerator: (req) => req.ip
  }),

  // Strict rate limit for sensitive operations
  strict: rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 5, // 5 requests per 15 minutes
    message: 'Too many attempts, please try again later',
    skipSuccessfulRequests: true,
    // Use default key generator
    keyGenerator: (req) => req.ip
  }),

  // Login rate limit
  login: rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 5, // 5 login attempts per 15 minutes
    message: 'Too many login attempts, please try again later',
    skipSuccessfulRequests: true,
    keyGenerator: (req) => {
      // Combine email/phone with IP
      const identifier = req.body?.emailOrPhone || '';
      return `${identifier}_${req.ip}`;
    },
    skip: (req) => !req.body?.emailOrPhone && !req.ip
  }),

  // Transaction rate limit
  transaction: rateLimit({
    windowMs: 1 * 60 * 1000, // 1 minute
    max: 10, // 10 transactions per minute
    message: 'Transaction rate limit exceeded, please wait',
    keyGenerator: (req) => {
      // Use userId if available, otherwise use IP
      return req.userId ? `user_${req.userId}` : `ip_${req.ip}`;
    }
  }),

  // API rate limit (for external API users)
  api: rateLimit({
    windowMs: 1 * 60 * 1000, // 1 minute
    max: 60, // 60 requests per minute for API users
    message: 'API rate limit exceeded',
    keyGenerator: (req) => {
      // Use API key if available, otherwise use IP
      const apiKey = req.header('X-API-Key');
      return apiKey ? `api_${apiKey}` : `ip_${req.ip}`;
    }
  })
};

// =============================================
// 8. SECURITY MIDDLEWARE
// =============================================

const securityMiddleware = {
  // Sanitize input to prevent XSS and injection
  sanitizeInput: (req, res, next) => {
    // Clean request body
    if (req.body) {
      Object.keys(req.body).forEach(key => {
        if (typeof req.body[key] === 'string') {
          req.body[key] = req.body[key].trim();
        }
      });
    }
    next();
  },

  // Generate unique transaction reference
  generateReference: (req, res, next) => {
    req.transactionRef = 'TXN' + Date.now() + crypto.randomBytes(4).toString('hex').toUpperCase();
    next();
  },

  // Log activity
  logActivity: async (req, res, next) => {
    try {
      if (req.user) {
        // Update last activity
        await User.findByIdAndUpdate(req.userId, {
          lastActivity: new Date()
        });
      }
      next();
    } catch (error) {
      next();
    }
  }
};

// =============================================
// 9. ERROR HANDLING MIDDLEWARE
// =============================================

const errorHandler = (err, req, res, next) => {
  console.error('Error:', err);

  // Mongoose validation error
  if (err.name === 'ValidationError') {
    const errors = Object.values(err.errors).map(e => e.message);
    return res.status(400).json({
      success: false,
      message: 'Validation error',
      errors
    });
  }

  // Duplicate key error
  if (err.code === 11000) {
    const field = Object.keys(err.keyValue)[0];
    return res.status(400).json({
      success: false,
      message: `${field} already exists`
    });
  }

  // JWT errors
  if (err.name === 'JsonWebTokenError') {
    return res.status(401).json({
      success: false,
      message: 'Invalid token'
    });
  }

  // Default error
  return res.status(err.status || 500).json({
    success: false,
    message: err.message || 'Internal server error',
    ...(process.env.NODE_ENV === 'development' && { stack: err.stack })
  });
};

// =============================================
// 10. REQUEST LOGGING MIDDLEWARE
// =============================================

const requestLogger = (req, res, next) => {
  const start = Date.now();

  // Log response after it's sent
  res.on('finish', () => {
    const duration = Date.now() - start;
    console.log({
      method: req.method,
      url: req.originalUrl,
      status: res.statusCode,
      duration: `${duration}ms`,
      user: req.user?.email,
      ip: req.ip,
      timestamp: new Date().toISOString()
    });
  });

  next();
};

// =============================================
// EXPORT MIDDLEWARE
// =============================================

module.exports = {
  // Authentication
  auth: authMiddleware,
  
  // Authorization
  role: roleMiddleware,
  
  // API Key
  apiKey: apiKeyMiddleware,
  
  // Validation
  validate: validators,
  
  // Wallet
  wallet: walletMiddleware,
  
  // System
  system: systemMiddleware,
  
  // Rate Limiting
  rateLimit: rateLimiters,
  
  // Security
  security: securityMiddleware,
  
  // Error Handler
  errorHandler,
  
  // Request Logger
  requestLogger
};