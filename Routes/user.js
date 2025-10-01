// =============================================
// USER PROFILE ROUTES - GHANA MTN DATA PLATFORM
// Complete User Management & Profile APIs
// =============================================

const express = require('express');
const router = express.Router();
const bcrypt = require('bcryptjs');
const crypto = require('crypto');
const mongoose = require('mongoose');

// Import models
const {
  User,
  Transaction,
  WalletTransaction,
  Notification,
  ApiLog
} = require('../schema/schema');

// Import middleware
const {
  auth,
  validate,
  security
} = require('../middleware/middleware');

// All routes require authentication
router.use(auth.verifyToken);

// =============================================
// 1. USER PROFILE DISPLAY
// =============================================

// Get current user profile
router.get('/profile', async (req, res) => {
  try {
    const userId = req.userId;
    
    const user = await User.findById(userId)
      .select('-password -apiAccess.apiSecret')
      .populate('referral.referredBy', 'fullName email')
      .populate('createdBy', 'fullName email')
      .lean();
    
    if (!user) {
      return res.status(404).json({
        success: false,
        message: 'User not found'
      });
    }
    
    // Get additional stats
    const [transactionStats, referralCount] = await Promise.all([
      // Transaction statistics
      Transaction.aggregate([
        { $match: { user: mongoose.Types.ObjectId(userId) } },
        {
          $group: {
            _id: null,
            totalTransactions: { $sum: 1 },
            totalSpent: { $sum: '$amount' },
            successfulTransactions: {
              $sum: { $cond: [{ $eq: ['$status', 'successful'] }, 1, 0] }
            }
          }
        }
      ]),
      
      // Referral count
      User.countDocuments({ 'referral.referredBy': userId })
    ]);
    
    // Format response
    const profile = {
      // Basic Information
      personalInfo: {
        id: user._id,
        fullName: user.fullName,
        email: user.email,
        phone: user.phone,
        emailVerified: user.emailVerified,
        phoneVerified: user.phoneVerified,
        createdAt: user.createdAt,
        lastLogin: user.lastLogin
      },
      
      // Account Information
      account: {
        role: user.role,
        status: user.status,
        username: user.username,
        twoFactorEnabled: user.twoFactorEnabled
      },
      
      // Profile Details
      profile: {
        address: user.profile?.address,
        city: user.profile?.city,
        state: user.profile?.state,
        country: user.profile?.country || 'Ghana',
        postalCode: user.profile?.postalCode,
        businessName: user.profile?.businessName,
        taxId: user.profile?.taxId,
        kycStatus: user.profile?.kycStatus || 'not_submitted',
        avatar: user.profile?.avatar
      },
      
      // Wallet Information
      wallet: {
        balance: user.wallet?.balance || 0,
        currency: user.wallet?.currency || 'GHS',
        formattedBalance: `GHS ${(user.wallet?.balance || 0).toFixed(2)}`
      },
      
      // Referral Information
      referral: {
        referralCode: user.referral?.code,
        referredBy: user.referral?.referredBy ? {
          id: user.referral.referredBy._id,
          name: user.referral.referredBy.fullName
        } : null,
        referralCount: referralCount,
        referralEarnings: user.referral?.referralEarnings || 0
      },
      
      // API Access
      apiAccess: {
        enabled: user.apiAccess?.enabled || false,
        apiKey: user.apiAccess?.apiKey,
        webhookUrl: user.apiAccess?.webhookUrl,
        lastUsed: user.apiAccess?.lastUsed,
        requestCount: user.apiAccess?.requestCount || 0
      },
      
      // Statistics
      stats: {
        totalTransactions: transactionStats[0]?.totalTransactions || 0,
        totalSpent: transactionStats[0]?.totalSpent || 0,
        successfulTransactions: transactionStats[0]?.successfulTransactions || 0,
        accountAge: Math.floor((Date.now() - new Date(user.createdAt).getTime()) / (1000 * 60 * 60 * 24)) + ' days'
      },
      
      // Commission Settings (for dealers/suppliers)
      commission: user.role !== 'agent' ? {
        rate: user.commissionSettings?.rate || 0,
        customRates: user.commissionSettings?.customRates || []
      } : undefined
    };
    
    res.json({
      success: true,
      data: profile
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: 'Error fetching profile',
      error: error.message
    });
  }
});

// Get simplified profile (for quick access)
router.get('/profile/summary', async (req, res) => {
  try {
    const user = await User.findById(req.userId)
      .select('fullName email phone role wallet.balance status')
      .lean();
    
    res.json({
      success: true,
      data: {
        fullName: user.fullName,
        email: user.email,
        phone: user.phone,
        role: user.role,
        walletBalance: user.wallet?.balance || 0,
        status: user.status
      }
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: 'Error fetching profile summary',
      error: error.message
    });
  }
});

// =============================================
// 2. UPDATE PROFILE INFORMATION
// =============================================

// Update personal information
router.put('/profile/personal', async (req, res) => {
  try {
    const userId = req.userId;
    const { fullName, phone } = req.body;
    
    const updates = {};
    
    // Validate and add updates
    if (fullName) {
      if (fullName.length < 2 || fullName.length > 100) {
        return res.status(400).json({
          success: false,
          message: 'Full name must be between 2 and 100 characters'
        });
      }
      updates.fullName = fullName.trim();
    }
    
    if (phone) {
      if (!phone.match(/^(\+233|0)[235][0-9]{8}$/)) {
        return res.status(400).json({
          success: false,
          message: 'Invalid Ghana phone number format'
        });
      }
      
      // Check if phone number is already in use
      const phoneExists = await User.findOne({ 
        phone, 
        _id: { $ne: userId } 
      });
      
      if (phoneExists) {
        return res.status(400).json({
          success: false,
          message: 'Phone number already in use'
        });
      }
      
      updates.phone = phone;
      updates.phoneVerified = false; // Reset verification
    }
    
    if (Object.keys(updates).length === 0) {
      return res.status(400).json({
        success: false,
        message: 'No valid updates provided'
      });
    }
    
    const user = await User.findByIdAndUpdate(
      userId,
      { ...updates, updatedAt: new Date() },
      { new: true }
    ).select('-password');
    
    res.json({
      success: true,
      message: 'Personal information updated successfully',
      data: {
        fullName: user.fullName,
        phone: user.phone
      }
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: 'Error updating personal information',
      error: error.message
    });
  }
});

// Update profile details (address, business info)
router.put('/profile/details', async (req, res) => {
  try {
    const userId = req.userId;
    const {
      address,
      city,
      state,
      postalCode,
      businessName,
      taxId
    } = req.body;
    
    const profileUpdates = {};
    
    if (address) profileUpdates['profile.address'] = address;
    if (city) profileUpdates['profile.city'] = city;
    if (state) profileUpdates['profile.state'] = state;
    if (postalCode) profileUpdates['profile.postalCode'] = postalCode;
    if (businessName) profileUpdates['profile.businessName'] = businessName;
    if (taxId) profileUpdates['profile.taxId'] = taxId;
    
    const user = await User.findByIdAndUpdate(
      userId,
      { ...profileUpdates, updatedAt: new Date() },
      { new: true }
    ).select('profile');
    
    res.json({
      success: true,
      message: 'Profile details updated successfully',
      data: user.profile
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: 'Error updating profile details',
      error: error.message
    });
  }
});

// Update email (requires verification)
router.post('/profile/update-email', async (req, res) => {
  try {
    const userId = req.userId;
    const { newEmail, password } = req.body;
    
    if (!newEmail || !password) {
      return res.status(400).json({
        success: false,
        message: 'New email and password required'
      });
    }
    
    // Validate email format
    const emailRegex = /^\w+([.-]?\w+)*@\w+([.-]?\w+)*(\.\w{2,3})+$/;
    if (!emailRegex.test(newEmail)) {
      return res.status(400).json({
        success: false,
        message: 'Invalid email format'
      });
    }
    
    // Verify password
    const user = await User.findById(userId);
    const validPassword = await bcrypt.compare(password, user.password);
    
    if (!validPassword) {
      return res.status(401).json({
        success: false,
        message: 'Incorrect password'
      });
    }
    
    // Check if email is already in use
    const emailExists = await User.findOne({ 
      email: newEmail.toLowerCase() 
    });
    
    if (emailExists) {
      return res.status(400).json({
        success: false,
        message: 'Email already in use'
      });
    }
    
    // Generate verification token
    const verificationToken = crypto.randomBytes(32).toString('hex');
    
    user.security.emailVerificationToken = verificationToken;
    user.security.emailVerificationExpires = Date.now() + 3600000; // 1 hour
    await user.save();
    
    // TODO: Send verification email
    
    res.json({
      success: true,
      message: 'Verification email sent to your new email address',
      data: {
        newEmail: newEmail,
        verificationRequired: true
      }
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: 'Error updating email',
      error: error.message
    });
  }
});

// =============================================
// 3. SECURITY SETTINGS
// =============================================

// Change password
router.post('/profile/change-password', async (req, res) => {
  try {
    const userId = req.userId;
    const { currentPassword, newPassword, confirmPassword } = req.body;
    
    // Validate input
    if (!currentPassword || !newPassword || !confirmPassword) {
      return res.status(400).json({
        success: false,
        message: 'All password fields are required'
      });
    }
    
    if (newPassword !== confirmPassword) {
      return res.status(400).json({
        success: false,
        message: 'New passwords do not match'
      });
    }
    
    if (newPassword.length < 6) {
      return res.status(400).json({
        success: false,
        message: 'Password must be at least 6 characters'
      });
    }
    
    if (currentPassword === newPassword) {
      return res.status(400).json({
        success: false,
        message: 'New password must be different from current password'
      });
    }
    
    // Get user and verify current password
    const user = await User.findById(userId);
    const validPassword = await bcrypt.compare(currentPassword, user.password);
    
    if (!validPassword) {
      return res.status(401).json({
        success: false,
        message: 'Current password is incorrect'
      });
    }
    
    // Hash and save new password
    user.password = await bcrypt.hash(newPassword, 10);
    user.security.lastPasswordChange = new Date();
    await user.save();
    
    // Send notification
    await Notification.create({
      user: userId,
      title: 'Password Changed',
      message: 'Your password has been changed successfully. If you did not make this change, please contact support immediately.',
      type: 'warning',
      category: 'security'
    });
    
    res.json({
      success: true,
      message: 'Password changed successfully'
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: 'Error changing password',
      error: error.message
    });
  }
});

// Enable/Disable two-factor authentication
router.post('/profile/2fa/toggle', async (req, res) => {
  try {
    const userId = req.userId;
    const { enable, password } = req.body;
    
    // Verify password
    const user = await User.findById(userId);
    const validPassword = await bcrypt.compare(password, user.password);
    
    if (!validPassword) {
      return res.status(401).json({
        success: false,
        message: 'Incorrect password'
      });
    }
    
    if (enable) {
      // Generate 2FA secret
      const secret = crypto.randomBytes(32).toString('hex');
      user.twoFactorSecret = secret;
      user.twoFactorEnabled = true;
      
      // TODO: Generate QR code for authenticator app
      
      res.json({
        success: true,
        message: 'Two-factor authentication enabled',
        data: {
          secret: secret,
          qrCode: 'base64_qr_code_here' // Generate actual QR code
        }
      });
    } else {
      user.twoFactorEnabled = false;
      user.twoFactorSecret = null;
      
      res.json({
        success: true,
        message: 'Two-factor authentication disabled'
      });
    }
    
    await user.save();
    
    // Send notification
    await Notification.create({
      user: userId,
      title: '2FA Status Changed',
      message: `Two-factor authentication has been ${enable ? 'enabled' : 'disabled'} for your account`,
      type: 'info',
      category: 'security'
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: 'Error updating 2FA settings',
      error: error.message
    });
  }
});

// Set/Update transaction PIN
router.post('/profile/pin/set', async (req, res) => {
  try {
    const userId = req.userId;
    const { pin, password } = req.body;
    
    // Validate PIN
    if (!pin || pin.length !== 4 || !/^\d+$/.test(pin)) {
      return res.status(400).json({
        success: false,
        message: 'PIN must be exactly 4 digits'
      });
    }
    
    // Verify password
    const user = await User.findById(userId);
    const validPassword = await bcrypt.compare(password, user.password);
    
    if (!validPassword) {
      return res.status(401).json({
        success: false,
        message: 'Incorrect password'
      });
    }
    
    // Hash and save PIN
    const hashedPin = await bcrypt.hash(pin, 10);
    user.wallet.pin = hashedPin;
    user.wallet.pinEnabled = true;
    await user.save();
    
    res.json({
      success: true,
      message: 'Transaction PIN set successfully'
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: 'Error setting PIN',
      error: error.message
    });
  }
});

// View login history
router.get('/profile/login-history', async (req, res) => {
  try {
    const userId = req.userId;
    const { limit = 10 } = req.query;
    
    const user = await User.findById(userId)
      .select('loginHistory')
      .lean();
    
    const history = user.loginHistory
      ?.slice(-limit)
      .reverse() || [];
    
    res.json({
      success: true,
      data: history
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: 'Error fetching login history',
      error: error.message
    });
  }
});

// =============================================
// 4. WALLET INFORMATION
// =============================================

// Get detailed wallet information
router.get('/wallet', async (req, res) => {
  try {
    const userId = req.userId;
    
    const user = await User.findById(userId).select('wallet').lean();
    
    // Get recent wallet transactions
    const recentTransactions = await WalletTransaction.find({ user: userId })
      .sort({ createdAt: -1 })
      .limit(10)
      .lean();
    
    // Calculate wallet statistics
    const stats = await WalletTransaction.aggregate([
      { $match: { user: mongoose.Types.ObjectId(userId) } },
      {
        $group: {
          _id: '$type',
          total: { $sum: '$amount' },
          count: { $sum: 1 }
        }
      }
    ]);
    
    const walletStats = {
      totalCredits: 0,
      totalDebits: 0,
      creditCount: 0,
      debitCount: 0
    };
    
    stats.forEach(stat => {
      if (stat._id === 'credit') {
        walletStats.totalCredits = stat.total;
        walletStats.creditCount = stat.count;
      } else if (stat._id === 'debit') {
        walletStats.totalDebits = stat.total;
        walletStats.debitCount = stat.count;
      }
    });
    
    res.json({
      success: true,
      data: {
        balance: user.wallet?.balance || 0,
        bonus: user.wallet?.bonus || 0,
        commission: user.wallet?.commission || 0,
        currency: user.wallet?.currency || 'GHS',
        formattedBalance: `GHS ${(user.wallet?.balance || 0).toFixed(2)}`,
        pinEnabled: user.wallet?.pinEnabled || false,
        statistics: walletStats,
        recentTransactions: recentTransactions.map(tx => ({
          id: tx._id,
          type: tx.type,
          amount: tx.amount,
          purpose: tx.purpose,
          description: tx.description,
          date: tx.createdAt,
          status: tx.status
        }))
      }
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: 'Error fetching wallet information',
      error: error.message
    });
  }
});

// Get wallet transaction history
router.get('/wallet/transactions', async (req, res) => {
  try {
    const userId = req.userId;
    const { 
      type, 
      purpose, 
      startDate, 
      endDate, 
      page = 1, 
      limit = 20 
    } = req.query;
    
    const filter = { user: userId };
    if (type) filter.type = type;
    if (purpose) filter.purpose = purpose;
    if (startDate || endDate) {
      filter.createdAt = {};
      if (startDate) filter.createdAt.$gte = new Date(startDate);
      if (endDate) filter.createdAt.$lte = new Date(endDate);
    }
    
    const transactions = await WalletTransaction.find(filter)
      .sort({ createdAt: -1 })
      .limit(limit * 1)
      .skip((page - 1) * limit)
      .lean();
    
    const total = await WalletTransaction.countDocuments(filter);
    
    res.json({
      success: true,
      data: transactions,
      pagination: {
        total,
        page: parseInt(page),
        pages: Math.ceil(total / limit)
      }
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: 'Error fetching wallet transactions',
      error: error.message
    });
  }
});

// =============================================
// 5. API KEY MANAGEMENT
// =============================================

// Generate new API key
router.post('/api-keys/generate', async (req, res) => {
  try {
    const userId = req.userId;
    const { webhookUrl, password } = req.body;
    
    // Only allow for certain roles
    if (!['supplier', 'dealer', 'agent'].includes(req.user.role)) {
      return res.status(403).json({
        success: false,
        message: 'API access not available for your account type'
      });
    }
    
    // Verify password
    const user = await User.findById(userId);
    const validPassword = await bcrypt.compare(password, user.password);
    
    if (!validPassword) {
      return res.status(401).json({
        success: false,
        message: 'Incorrect password'
      });
    }
    
    // Generate new API credentials
    const apiKey = 'pk_' + crypto.randomBytes(32).toString('hex');
    const apiSecret = crypto.randomBytes(32).toString('hex');
    const hashedSecret = await bcrypt.hash(apiSecret, 10);
    
    // Save API credentials
    user.apiAccess = {
      enabled: true,
      apiKey: apiKey,
      apiSecret: hashedSecret,
      webhookUrl: webhookUrl,
      requestCount: 0,
      rateLimit: 100
    };
    
    await user.save();
    
    res.json({
      success: true,
      message: 'API credentials generated successfully',
      data: {
        apiKey: apiKey,
        apiSecret: apiSecret, // Only show this once
        webhookUrl: webhookUrl,
        warning: 'Please save your API secret securely. It will not be shown again.'
      }
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: 'Error generating API credentials',
      error: error.message
    });
  }
});

// Regenerate API secret
router.post('/api-keys/regenerate-secret', async (req, res) => {
  try {
    const userId = req.userId;
    const { password } = req.body;
    
    // Verify password
    const user = await User.findById(userId);
    const validPassword = await bcrypt.compare(password, user.password);
    
    if (!validPassword) {
      return res.status(401).json({
        success: false,
        message: 'Incorrect password'
      });
    }
    
    if (!user.apiAccess?.enabled) {
      return res.status(400).json({
        success: false,
        message: 'API access not enabled'
      });
    }
    
    // Generate new secret
    const newApiSecret = crypto.randomBytes(32).toString('hex');
    const hashedSecret = await bcrypt.hash(newApiSecret, 10);
    
    user.apiAccess.apiSecret = hashedSecret;
    await user.save();
    
    res.json({
      success: true,
      message: 'API secret regenerated successfully',
      data: {
        apiKey: user.apiAccess.apiKey,
        apiSecret: newApiSecret,
        warning: 'Please save your new API secret securely. It will not be shown again.'
      }
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: 'Error regenerating API secret',
      error: error.message
    });
  }
});

// Update webhook URL
router.put('/api-keys/webhook', async (req, res) => {
  try {
    const userId = req.userId;
    const { webhookUrl } = req.body;
    
    const user = await User.findById(userId);
    
    if (!user.apiAccess?.enabled) {
      return res.status(400).json({
        success: false,
        message: 'API access not enabled'
      });
    }
    
    user.apiAccess.webhookUrl = webhookUrl;
    await user.save();
    
    res.json({
      success: true,
      message: 'Webhook URL updated successfully',
      data: {
        webhookUrl: webhookUrl
      }
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: 'Error updating webhook URL',
      error: error.message
    });
  }
});

// Get API usage statistics
router.get('/api-keys/usage', async (req, res) => {
  try {
    const userId = req.userId;
    const { startDate, endDate } = req.query;
    
    const user = await User.findById(userId).select('apiAccess').lean();
    
    if (!user.apiAccess?.enabled) {
      return res.status(400).json({
        success: false,
        message: 'API access not enabled'
      });
    }
    
    const filter = { 
      user: userId,
      apiKey: user.apiAccess.apiKey 
    };
    
    if (startDate || endDate) {
      filter.createdAt = {};
      if (startDate) filter.createdAt.$gte = new Date(startDate);
      if (endDate) filter.createdAt.$lte = new Date(endDate);
    }
    
    // Get API logs
    const logs = await ApiLog.find(filter)
      .sort({ createdAt: -1 })
      .limit(100)
      .lean();
    
    // Calculate statistics
    const stats = await ApiLog.aggregate([
      { $match: filter },
      {
        $group: {
          _id: null,
          totalRequests: { $sum: 1 },
          successfulRequests: {
            $sum: { $cond: [{ $eq: ['$success', true] }, 1, 0] }
          },
          failedRequests: {
            $sum: { $cond: [{ $eq: ['$success', false] }, 1, 0] }
          },
          avgResponseTime: { $avg: '$response.responseTime' }
        }
      }
    ]);
    
    res.json({
      success: true,
      data: {
        apiKey: user.apiAccess.apiKey,
        webhookUrl: user.apiAccess.webhookUrl,
        requestCount: user.apiAccess.requestCount,
        rateLimit: user.apiAccess.rateLimit,
        lastUsed: user.apiAccess.lastUsed,
        statistics: stats[0] || {
          totalRequests: 0,
          successfulRequests: 0,
          failedRequests: 0,
          avgResponseTime: 0
        },
        recentLogs: logs.map(log => ({
          endpoint: log.endpoint,
          method: log.method,
          statusCode: log.response?.statusCode,
          success: log.success,
          timestamp: log.createdAt
        }))
      }
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: 'Error fetching API usage',
      error: error.message
    });
  }
});

// Disable API access
router.post('/api-keys/disable', async (req, res) => {
  try {
    const userId = req.userId;
    const { password } = req.body;
    
    // Verify password
    const user = await User.findById(userId);
    const validPassword = await bcrypt.compare(password, user.password);
    
    if (!validPassword) {
      return res.status(401).json({
        success: false,
        message: 'Incorrect password'
      });
    }
    
    user.apiAccess.enabled = false;
    await user.save();
    
    res.json({
      success: true,
      message: 'API access disabled successfully'
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: 'Error disabling API access',
      error: error.message
    });
  }
});

// =============================================
// 6. REFERRAL SYSTEM
// =============================================

// Get referral information
router.get('/referrals', async (req, res) => {
  try {
    const userId = req.userId;
    
    const user = await User.findById(userId)
      .select('referral')
      .populate('referral.referredBy', 'fullName email')
      .lean();
    
    // Get referred users
    const referredUsers = await User.find({ 
      'referral.referredBy': userId 
    })
      .select('fullName email createdAt status wallet.balance')
      .lean();
    
    // Calculate referral statistics
    const referralStats = await Transaction.aggregate([
      {
        $match: {
          user: { $in: referredUsers.map(u => u._id) },
          status: 'successful'
        }
      },
      {
        $group: {
          _id: null,
          totalTransactions: { $sum: 1 },
          totalVolume: { $sum: '$amount' }
        }
      }
    ]);
    
    res.json({
      success: true,
      data: {
        referralCode: user.referral?.code,
        referralLink: `https://platform.com/register?ref=${user.referral?.code}`,
        referredBy: user.referral?.referredBy,
        referralCount: referredUsers.length,
        referralEarnings: user.referral?.referralEarnings || 0,
        activeReferrals: referredUsers.filter(u => u.status === 'active').length,
        referredUsers: referredUsers.map(u => ({
          id: u._id,
          fullName: u.fullName,
          email: u.email,
          joinedDate: u.createdAt,
          status: u.status,
          totalSpent: u.wallet?.balance || 0
        })),
        statistics: referralStats[0] || {
          totalTransactions: 0,
          totalVolume: 0
        }
      }
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: 'Error fetching referral information',
      error: error.message
    });
  }
});

// Generate referral code (if not exists)
router.post('/referrals/generate-code', async (req, res) => {
  try {
    const userId = req.userId;
    
    const user = await User.findById(userId);
    
    if (user.referral?.code) {
      return res.status(400).json({
        success: false,
        message: 'Referral code already exists',
        data: {
          referralCode: user.referral.code
        }
      });
    }
    
    // Generate unique referral code
    let referralCode;
    let codeExists = true;
    
    while (codeExists) {
      referralCode = req.user.fullName.substring(0, 3).toUpperCase() + 
                    crypto.randomBytes(3).toString('hex').toUpperCase();
      
      codeExists = await User.findOne({ 'referral.code': referralCode });
    }
    
    user.referral.code = referralCode;
    await user.save();
    
    res.json({
      success: true,
      message: 'Referral code generated successfully',
      data: {
        referralCode: referralCode,
        referralLink: `https://platform.com/register?ref=${referralCode}`
      }
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: 'Error generating referral code',
      error: error.message
    });
  }
});

// =============================================
// 7. NOTIFICATION PREFERENCES
// =============================================

// Get notification preferences
router.get('/notifications/preferences', async (req, res) => {
  try {
    const userId = req.userId;
    
    const user = await User.findById(userId)
      .select('notificationPreferences')
      .lean();
    
    const preferences = user.notificationPreferences || {
      email: {
        transactions: true,
        security: true,
        marketing: false,
        updates: true
      },
      sms: {
        transactions: true,
        security: true,
        marketing: false,
        updates: false
      },
      push: {
        transactions: true,
        security: true,
        marketing: true,
        updates: true
      }
    };
    
    res.json({
      success: true,
      data: preferences
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: 'Error fetching notification preferences',
      error: error.message
    });
  }
});

// Update notification preferences
router.put('/notifications/preferences', async (req, res) => {
  try {
    const userId = req.userId;
    const { email, sms, push } = req.body;
    
    const updates = {};
    if (email) updates['notificationPreferences.email'] = email;
    if (sms) updates['notificationPreferences.sms'] = sms;
    if (push) updates['notificationPreferences.push'] = push;
    
    const user = await User.findByIdAndUpdate(
      userId,
      updates,
      { new: true }
    ).select('notificationPreferences');
    
    res.json({
      success: true,
      message: 'Notification preferences updated',
      data: user.notificationPreferences
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: 'Error updating notification preferences',
      error: error.message
    });
  }
});

// Get user notifications
router.get('/notifications', async (req, res) => {
  try {
    const userId = req.userId;
    const { 
      read, 
      type, 
      category, 
      page = 1, 
      limit = 20 
    } = req.query;
    
    const filter = { user: userId };
    if (read !== undefined) filter.read = read === 'true';
    if (type) filter.type = type;
    if (category) filter.category = category;
    
    const notifications = await Notification.find(filter)
      .sort({ createdAt: -1 })
      .limit(limit * 1)
      .skip((page - 1) * limit)
      .lean();
    
    const total = await Notification.countDocuments(filter);
    const unreadCount = await Notification.countDocuments({ 
      user: userId, 
      read: false 
    });
    
    res.json({
      success: true,
      data: notifications,
      unreadCount: unreadCount,
      pagination: {
        total,
        page: parseInt(page),
        pages: Math.ceil(total / limit)
      }
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: 'Error fetching notifications',
      error: error.message
    });
  }
});

// Mark notifications as read
router.put('/notifications/mark-read', async (req, res) => {
  try {
    const userId = req.userId;
    const { notificationIds, markAll } = req.body;
    
    if (markAll) {
      await Notification.updateMany(
        { user: userId, read: false },
        { read: true, readAt: new Date() }
      );
      
      res.json({
        success: true,
        message: 'All notifications marked as read'
      });
    } else if (notificationIds && notificationIds.length > 0) {
      await Notification.updateMany(
        { 
          _id: { $in: notificationIds },
          user: userId 
        },
        { read: true, readAt: new Date() }
      );
      
      res.json({
        success: true,
        message: `${notificationIds.length} notifications marked as read`
      });
    } else {
      return res.status(400).json({
        success: false,
        message: 'No notifications specified'
      });
    }
  } catch (error) {
    res.status(500).json({
      success: false,
      message: 'Error marking notifications as read',
      error: error.message
    });
  }
});

// =============================================
// 8. ACCOUNT ACTIONS
// =============================================

// Request account verification
router.post('/profile/verify-account', async (req, res) => {
  try {
    const userId = req.userId;
    const { documents } = req.body; // Array of document URLs
    
    const user = await User.findById(userId);
    
    if (user.profile?.kycStatus === 'verified') {
      return res.status(400).json({
        success: false,
        message: 'Account already verified'
      });
    }
    
    // Update KYC status and documents
    user.profile.kycStatus = 'pending';
    user.profile.kycDocuments = documents.map(doc => ({
      documentType: doc.type,
      documentUrl: doc.url,
      uploadedAt: new Date()
    }));
    
    await user.save();
    
    // Notify admin
    const admins = await User.find({ role: 'admin' }).select('_id');
    for (const admin of admins) {
      await Notification.create({
        user: admin._id,
        title: 'New KYC Verification Request',
        message: `${user.fullName} has submitted documents for verification`,
        type: 'info',
        category: 'account'
      });
    }
    
    res.json({
      success: true,
      message: 'Verification documents submitted successfully',
      data: {
        kycStatus: 'pending'
      }
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: 'Error submitting verification',
      error: error.message
    });
  }
});

// Delete account (soft delete)
router.delete('/profile/delete-account', async (req, res) => {
  try {
    const userId = req.userId;
    const { password, reason } = req.body;
    
    // Verify password
    const user = await User.findById(userId);
    const validPassword = await bcrypt.compare(password, user.password);
    
    if (!validPassword) {
      return res.status(401).json({
        success: false,
        message: 'Incorrect password'
      });
    }
    
    // Check for pending transactions
    const pendingTransactions = await Transaction.findOne({
      user: userId,
      status: 'pending'
    });
    
    if (pendingTransactions) {
      return res.status(400).json({
        success: false,
        message: 'Cannot delete account with pending transactions'
      });
    }
    
    // Check wallet balance
    if (user.wallet.balance > 0) {
      return res.status(400).json({
        success: false,
        message: 'Please withdraw your wallet balance before deleting account',
        walletBalance: user.wallet.balance
      });
    }
    
    // Soft delete account
    user.status = 'suspended';
    user.deletedAt = new Date();
    user.deletionReason = reason;
    await user.save();
    
    res.json({
      success: true,
      message: 'Account deleted successfully'
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: 'Error deleting account',
      error: error.message
    });
  }
});


// =============================================
// EXPORT ROUTER
// =============================================

module.exports = router;