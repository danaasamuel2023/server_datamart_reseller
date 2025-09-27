// =============================================
// AUTH ROUTES - GHANA MTN DATA PLATFORM
// =============================================

const express = require('express');
const router = express.Router();
const bcrypt = require('bcryptjs');
const crypto = require('crypto');

// Import models
const { User, Notification, WalletTransaction } = require('../schema/schema');

// Import middleware
const {
  auth,
  validate,
  rateLimit,
  system,
  security
} = require('../middleware/middleware');

// =============================================
// PUBLIC AUTH ROUTES
// =============================================

// @route   POST /api/auth/register
// @desc    Register new user
// @access  Public
router.post('/register',
  system.checkRegistrationEnabled,
  rateLimit.strict,
  security.sanitizeInput,
  validate.validateRegistration,
  validate.handleValidationErrors,
  async (req, res) => {
    try {
      // SECURITY FIX: Remove role from user input - never accept it
      const { fullName, email, phone, password, referralCode } = req.body;

      // Additional validation to prevent role injection
      if (req.body.role) {
        console.warn(`User attempted to set role during registration: ${email}`);
        // Log this attempt for security monitoring
      }

      // Check if user exists
      const existingUser = await User.findOne({
        $or: [
          { email: email.toLowerCase() },
          { phone }
        ]
      });

      if (existingUser) {
        return res.status(409).json({
          success: false,
          message: 'User with this email or phone already exists'
        });
      }

      // Create new user with HARDCODED role
      const newUser = new User({
        fullName,
        email: email.toLowerCase(),
        phone,
        password, // Will be hashed by the model's pre-save middleware
        role: 'agent', // ALWAYS 'agent' for new registrations - no exceptions
        status: 'pending', // Requires admin approval
        wallet: {
          balance: 0,
          currency: 'GHS'
        }
      });

      // Handle referral
      if (referralCode) {
        const referrer = await User.findOne({ 
          _id: referralCode,
          status: 'active' 
        });
        
        if (referrer) {
          newUser.createdBy = referrer._id;
          
          // Give referral bonus (optional)
          referrer.wallet.balance += 10; // GHS 10 referral bonus
          await referrer.save();
          
          // Log referral bonus transaction
          await WalletTransaction.create({
            user: referrer._id,
            type: 'credit',
            amount: 10,
            balanceBefore: referrer.wallet.balance - 10,
            balanceAfter: referrer.wallet.balance,
            purpose: 'referral',
            reference: 'REF' + Date.now(),
            status: 'completed',
            description: `Referral bonus for ${fullName}`
          });
        }
      }

      await newUser.save();

      // Create welcome notification
      await Notification.create({
        user: newUser._id,
        title: 'Welcome to DATAMART Platform',
        message: 'Your account has been created successfully. Please wait for admin approval.',
        type: 'success'
      });

      res.status(201).json({
        success: true,
        message: 'Registration successful. Please wait for admin approval.',
        data: {
          userId: newUser._id,
          email: newUser.email,
          status: newUser.status
        }
      });
    } catch (error) {
      console.error('Registration Error:', error);
      res.status(500).json({
        success: false,
        message: 'Error during registration',
        error: process.env.NODE_ENV === 'development' ? error.message : undefined
      });
    }
  }
);

// @route   POST /api/auth/login
// @desc    Login user
// @access  Public
router.post('/login',
  rateLimit.login,
  security.sanitizeInput,
  validate.validateLogin,
  validate.handleValidationErrors,
  async (req, res) => {
    try {
      const { emailOrPhone, password } = req.body;

      // Find user by email or phone
      const user = await User.findOne({
        $or: [
          { email: emailOrPhone.toLowerCase() },
          { phone: emailOrPhone }
        ]
      });

      if (!user) {
        return res.status(401).json({
          success: false,
          message: 'Invalid credentials'
        });
      }

      // Check account status
      if (user.status === 'suspended') {
        return res.status(403).json({
          success: false,
          message: 'Your account has been suspended. Please contact support.'
        });
      }

      if (user.status === 'pending') {
        return res.status(403).json({
          success: false,
          message: 'Your account is pending approval. Please wait for admin verification.'
        });
      }

      // Verify password
      const isMatch = await bcrypt.compare(password, user.password);
      if (!isMatch) {
        return res.status(401).json({
          success: false,
          message: 'Invalid credentials'
        });
      }

      // Update last login
      user.lastLogin = new Date();
      await user.save();

      // Generate token
      const token = auth.generateToken(user._id, user.role);

      // Remove sensitive data
      const userObj = user.toObject();
      delete userObj.password;
      delete userObj.apiAccess;

      res.json({
        success: true,
        message: 'Login successful',
        token,
        user: userObj
      });
    } catch (error) {
      console.error('Login Error:', error);
      res.status(500).json({
        success: false,
        message: 'Error during login',
        error: process.env.NODE_ENV === 'development' ? error.message : undefined
      });
    }
  }
);

// @route   POST /api/auth/forgot-password
// @desc    Request password reset
// @access  Public
router.post('/forgot-password',
  rateLimit.strict,
  security.sanitizeInput,
  async (req, res) => {
    try {
      const { emailOrPhone } = req.body;

      if (!emailOrPhone) {
        return res.status(400).json({
          success: false,
          message: 'Email or phone number required'
        });
      }

      // Find user
      const user = await User.findOne({
        $or: [
          { email: emailOrPhone.toLowerCase() },
          { phone: emailOrPhone }
        ]
      });

      // Don't reveal if user exists
      if (!user) {
        return res.json({
          success: true,
          message: 'If an account exists, password reset instructions have been sent.'
        });
      }

      // Generate reset token
      const resetToken = crypto.randomBytes(32).toString('hex');
      const resetTokenHash = crypto
        .createHash('sha256')
        .update(resetToken)
        .digest('hex');

      // Save hashed token to user
      user.passwordResetToken = resetTokenHash;
      user.passwordResetExpires = Date.now() + 3600000; // 1 hour
      await user.save();

      // TODO: Send email/SMS with reset token
      // For now, log it (remove in production)
      console.log('Reset Token:', resetToken);

      res.json({
        success: true,
        message: 'If an account exists, password reset instructions have been sent.',
        ...(process.env.NODE_ENV === 'development' && { resetToken })
      });
    } catch (error) {
      console.error('Forgot Password Error:', error);
      res.status(500).json({
        success: false,
        message: 'Error processing request'
      });
    }
  }
);

// @route   POST /api/auth/reset-password
// @desc    Reset password with token
// @access  Public
router.post('/reset-password',
  rateLimit.strict,
  security.sanitizeInput,
  async (req, res) => {
    try {
      const { token, newPassword } = req.body;

      if (!token || !newPassword) {
        return res.status(400).json({
          success: false,
          message: 'Token and new password required'
        });
      }

      // Hash token to match stored version
      const resetTokenHash = crypto
        .createHash('sha256')
        .update(token)
        .digest('hex');

      // Find user with valid token
      const user = await User.findOne({
        passwordResetToken: resetTokenHash,
        passwordResetExpires: { $gt: Date.now() }
      });

      if (!user) {
        return res.status(400).json({
          success: false,
          message: 'Invalid or expired reset token'
        });
      }

      // Update password
      user.password = newPassword; // Will be hashed by pre-save hook
      user.passwordResetToken = undefined;
      user.passwordResetExpires = undefined;
      await user.save();

      // Create notification
      await Notification.create({
        user: user._id,
        title: 'Password Changed',
        message: 'Your password has been successfully reset.',
        type: 'success'
      });

      res.json({
        success: true,
        message: 'Password reset successful. You can now login with your new password.'
      });
    } catch (error) {
      console.error('Reset Password Error:', error);
      res.status(500).json({
        success: false,
        message: 'Error resetting password'
      });
    }
  }
);

// @route   POST /api/auth/verify-token
// @desc    Verify if token is valid
// @access  Private
router.post('/verify-token',
  auth.verifyToken,
  async (req, res) => {
    res.json({
      success: true,
      message: 'Token is valid',
      user: req.user
    });
  }
);

// @route   POST /api/auth/refresh-token
// @desc    Refresh authentication token
// @access  Private
router.post('/refresh-token',
  auth.verifyToken,
  async (req, res) => {
    try {
      const token = auth.generateToken(req.userId, req.userRole);
      
      res.json({
        success: true,
        message: 'Token refreshed successfully',
        token
      });
    } catch (error) {
      console.error('Token Refresh Error:', error);
      res.status(500).json({
        success: false,
        message: 'Error refreshing token'
      });
    }
  }
);

// @route   POST /api/auth/logout
// @desc    Logout user (optional for JWT)
// @access  Private
router.post('/logout',
  auth.verifyToken,
  async (req, res) => {
    try {
      // Update last activity
      await User.findByIdAndUpdate(req.userId, {
        lastActivity: new Date()
      });

      res.json({
        success: true,
        message: 'Logged out successfully'
      });
    } catch (error) {
      res.json({
        success: true,
        message: 'Logged out successfully'
      });
    }
  }
);

// @route   POST /api/auth/change-password
// @desc    Change password for authenticated user
// @access  Private
router.post('/change-password',
  auth.verifyToken,
  security.sanitizeInput,
  async (req, res) => {
    try {
      const { currentPassword, newPassword } = req.body;

      if (!currentPassword || !newPassword) {
        return res.status(400).json({
          success: false,
          message: 'Current and new passwords required'
        });
      }

      if (newPassword.length < 6) {
        return res.status(400).json({
          success: false,
          message: 'New password must be at least 6 characters'
        });
      }

      // Get user with password
      const user = await User.findById(req.userId).select('+password');

      // Verify current password
      const isMatch = await bcrypt.compare(currentPassword, user.password);
      if (!isMatch) {
        return res.status(401).json({
          success: false,
          message: 'Current password is incorrect'
        });
      }

      // Update password
      user.password = newPassword; // Will be hashed by pre-save hook
      await user.save();

      // Create notification
      await Notification.create({
        user: user._id,
        title: 'Password Changed',
        message: 'Your password has been changed successfully.',
        type: 'success'
      });

      res.json({
        success: true,
        message: 'Password changed successfully'
      });
    } catch (error) {
      console.error('Change Password Error:', error);
      res.status(500).json({
        success: false,
        message: 'Error changing password'
      });
    }
  }
);

// @route   GET /api/auth/profile
// @desc    Get user profile
// @access  Private
router.get('/profile',
  auth.verifyToken,
  async (req, res) => {
    try {
      const user = await User.findById(req.userId)
        .select('-password -apiAccess')
        .lean();

      if (!user) {
        return res.status(404).json({
          success: false,
          message: 'User not found'
        });
      }

      res.json({
        success: true,
        data: user
      });
    } catch (error) {
      console.error('Profile Error:', error);
      res.status(500).json({
        success: false,
        message: 'Error fetching profile'
      });
    }
  }
);

// @route   PUT /api/auth/profile
// @desc    Update user profile
// @access  Private
router.put('/profile',
  auth.verifyToken,
  security.sanitizeInput,
  async (req, res) => {
    try {
      const { fullName, phone } = req.body;
      
      // SECURITY: Prevent role updates through profile endpoint
      if (req.body.role) {
        console.warn(`User ${req.userId} attempted to update role through profile endpoint`);
        return res.status(403).json({
          success: false,
          message: 'Unauthorized field update attempt'
        });
      }
      
      const updates = {};
      if (fullName) updates.fullName = fullName;
      if (phone) {
        // Validate phone format
        if (!/^(\+233|0)[235][0-9]{8}$/.test(phone)) {
          return res.status(400).json({
            success: false,
            message: 'Invalid Ghana phone number format'
          });
        }
        
        // Check if phone is taken
        const phoneExists = await User.findOne({
          phone,
          _id: { $ne: req.userId }
        });
        
        if (phoneExists) {
          return res.status(400).json({
            success: false,
            message: 'Phone number already in use'
          });
        }
        
        updates.phone = phone;
      }

      const user = await User.findByIdAndUpdate(
        req.userId,
        updates,
        { new: true, runValidators: true }
      ).select('-password -apiAccess');

      res.json({
        success: true,
        message: 'Profile updated successfully',
        data: user
      });
    } catch (error) {
      console.error('Update Profile Error:', error);
      res.status(500).json({
        success: false,
        message: 'Error updating profile'
      });
    }
  }
);

module.exports = router;