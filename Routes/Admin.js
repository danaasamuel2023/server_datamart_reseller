// =============================================
// ADMIN API ROUTES - GHANA MTN DATA PLATFORM
// =============================================

const express = require('express');
const router = express.Router();
const bcrypt = require('bcryptjs');
const crypto = require('crypto');
const mongoose = require('mongoose');
const XLSX = require('xlsx'); // npm install xlsx

// Import models
const {
  User,
  Product,
  Transaction,
  PriceSetting,
  WalletTransaction,
  SystemSetting,
  ApiLog,
  Notification,
    Batch  // <- This was missing

} = require('../schema/schema');

// Import middleware
const {
  auth,
  role,
  validate,
  security
} = require('../middleware/middleware');

// All admin routes require authentication and admin role
router.use(auth.verifyToken);
router.use(role.adminOnly);

// =============================================
// 1. DASHBOARD & ANALYTICS APIs
// =============================================

// Verify admin token and get user info
router.get('/verify', async (req, res) => {
  try {
    res.json({
      success: true,
      user: {
        _id: req.user._id,
        fullName: req.user.fullName,
        email: req.user.email,
        role: req.user.role,
        phone: req.user.phone,
        status: req.user.status,
        wallet: req.user.wallet
      }
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: 'Error verifying admin',
      error: error.message
    });
  }
});

// Get dashboard statistics
router.get('/dashboard/stats', async (req, res) => {
  try {
    const { startDate, endDate } = req.query;
    
    const dateFilter = {};
    if (startDate) dateFilter.$gte = new Date(startDate);
    if (endDate) dateFilter.$lte = new Date(endDate);
    
    const stats = await Promise.all([
      User.aggregate([
        { $group: { _id: '$role', count: { $sum: 1 } } }
      ]),
      
      Transaction.aggregate([
        { $match: { ...(dateFilter && { createdAt: dateFilter }) } },
        {
          $group: {
            _id: '$status',
            count: { $sum: 1 },
            totalAmount: { $sum: '$amount' }
          }
        }
      ]),
      
      Transaction.aggregate([
        {
          $match: {
            createdAt: {
              $gte: new Date(new Date().setHours(0, 0, 0, 0))
            }
          }
        },
        {
          $group: {
            _id: null,
            todaySales: { $sum: '$amount' },
            todayTransactions: { $sum: 1 }
          }
        }
      ]),
      
      Product.countDocuments({ status: 'active' }),
      
      User.aggregate([
        {
          $group: {
            _id: null,
            totalWalletBalance: { $sum: '$wallet.balance' }
          }
        }
      ])
    ]);
    
    res.json({
      success: true,
      data: {
        users: stats[0],
        transactions: stats[1],
        today: stats[2][0] || { todaySales: 0, todayTransactions: 0 },
        activeProducts: stats[3],
        totalWalletBalance: stats[4][0]?.totalWalletBalance || 0
      }
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: 'Error fetching dashboard stats',
      error: error.message
    });
  }
});

// Get revenue analytics
router.get('/dashboard/revenue', async (req, res) => {
  try {
    const { period = '7days' } = req.query;
    
    let startDate;
    const endDate = new Date();
    
    switch (period) {
      case '7days':
        startDate = new Date(Date.now() - 7 * 24 * 60 * 60 * 1000);
        break;
      case '30days':
        startDate = new Date(Date.now() - 30 * 24 * 60 * 60 * 1000);
        break;
      case '90days':
        startDate = new Date(Date.now() - 90 * 24 * 60 * 60 * 1000);
        break;
      default:
        startDate = new Date(Date.now() - 7 * 24 * 60 * 60 * 1000);
    }
    
    const revenue = await Transaction.aggregate([
      {
        $match: {
          status: 'successful',
          createdAt: { $gte: startDate, $lte: endDate }
        }
      },
      {
        $group: {
          _id: {
            $dateToString: { format: '%Y-%m-%d', date: '$createdAt' }
          },
          revenue: { $sum: '$amount' },
          transactions: { $sum: 1 }
        }
      },
      { $sort: { _id: 1 } }
    ]);
    
    res.json({
      success: true,
      data: revenue
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: 'Error fetching revenue data',
      error: error.message
    });
  }
});

// Get top performing products
router.get('/dashboard/top-products', async (req, res) => {
  try {
    const { limit = 10 } = req.query;
    
    const topProducts = await Transaction.aggregate([
      { $match: { status: 'successful', type: 'data_purchase' } },
      { $group: {
        _id: '$dataDetails.product',
        totalSales: { $sum: 1 },
        totalRevenue: { $sum: '$amount' }
      }},
      { $sort: { totalRevenue: -1 } },
      { $limit: parseInt(limit) },
      { $lookup: {
        from: 'product_resellers',
        localField: '_id',
        foreignField: '_id',
        as: 'product'
      }},
      { $unwind: '$product' }
    ]);
    
    res.json({
      success: true,
      data: topProducts
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: 'Error fetching top products',
      error: error.message
    });
  }
});

// =============================================
// 2. USER MANAGEMENT APIs
// =============================================

// Get all users with filters
router.get('/users', async (req, res) => {
  try {
    const { 
      role: userRole, 
      status, 
      search, 
      page = 1, 
      limit = 20,
      sortBy = 'createdAt',
      sortOrder = 'desc'
    } = req.query;
    
    const filter = {};
    if (userRole) filter.role = userRole;
    if (status) filter.status = status;
    if (search) {
      filter.$or = [
        { fullName: { $regex: search, $options: 'i' } },
        { email: { $regex: search, $options: 'i' } },
        { phone: { $regex: search, $options: 'i' } }
      ];
    }
    
    const users = await User.find(filter)
      .select('-password')
      .sort({ [sortBy]: sortOrder === 'asc' ? 1 : -1 })
      .limit(limit * 1)
      .skip((page - 1) * limit)
      .populate('createdBy', 'fullName email')
      .lean();
    
    const total = await User.countDocuments(filter);
    
    res.json({
      success: true,
      data: users,
      pagination: {
        total,
        page: parseInt(page),
        pages: Math.ceil(total / limit)
      }
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: 'Error fetching users',
      error: error.message
    });
  }
});

// Create new user
router.post('/users', 
  validate.validateRegistration,
  validate.handleValidationErrors,
  async (req, res) => {
    try {
      const { fullName, email, phone, password, role, status = 'active' } = req.body;
      
      const existingUser = await User.findOne({
        $or: [{ email }, { phone }]
      });
      
      if (existingUser) {
        return res.status(400).json({
          success: false,
          message: 'User with this email or phone already exists'
        });
      }
      
      const user = new User({
        fullName,
        email,
        phone,
        password,
        role,
        status,
        createdBy: req.userId
      });
      
      await user.save();
      
      const userObj = user.toObject();
      delete userObj.password;
      
      res.status(201).json({
        success: true,
        message: 'User created successfully',
        data: userObj
      });
    } catch (error) {
      res.status(500).json({
        success: false,
        message: 'Error creating user',
        error: error.message
      });
    }
  }
);

// Update user details
router.put('/users/:userId', async (req, res) => {
  try {
    const { userId } = req.params;
    const updates = req.body;
    
    delete updates.password;
    delete updates._id;
    delete updates.createdAt;
    
    const user = await User.findByIdAndUpdate(
      userId,
      { ...updates, updatedAt: new Date() },
      { new: true, runValidators: true }
    ).select('-password');
    
    if (!user) {
      return res.status(404).json({
        success: false,
        message: 'User not found'
      });
    }
    
    res.json({
      success: true,
      message: 'User updated successfully',
      data: user
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: 'Error updating user',
      error: error.message
    });
  }
});

// Update user status
router.patch('/users/:userId/status', async (req, res) => {
  try {
    const { userId } = req.params;
    const { status, reason } = req.body;
    
    if (!['active', 'suspended', 'pending'].includes(status)) {
      return res.status(400).json({
        success: false,
        message: 'Invalid status'
      });
    }
    
    const user = await User.findByIdAndUpdate(
      userId,
      { status, updatedAt: new Date() },
      { new: true }
    ).select('-password');
    
    if (!user) {
      return res.status(404).json({
        success: false,
        message: 'User not found'
      });
    }
    
    await Notification.create({
      user: userId,
      title: 'Account Status Update',
      message: `Your account has been ${status}. ${reason || ''}`,
      type: status === 'suspended' ? 'warning' : 'info',
      category: 'system'
    });
    
    res.json({
      success: true,
      message: `User ${status} successfully`,
      data: user
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: 'Error updating user status',
      error: error.message
    });
  }
});

// Reset user password
router.post('/users/:userId/reset-password', async (req, res) => {
  try {
    const { userId } = req.params;
    const { newPassword } = req.body;
    
    if (!newPassword || newPassword.length < 6) {
      return res.status(400).json({
        success: false,
        message: 'Password must be at least 6 characters'
      });
    }
    
    const hashedPassword = await bcrypt.hash(newPassword, 10);
    
    const user = await User.findByIdAndUpdate(
      userId,
      { password: hashedPassword },
      { new: true }
    ).select('fullName email');
    
    if (!user) {
      return res.status(404).json({
        success: false,
        message: 'User not found'
      });
    }
    
    await Notification.create({
      user: userId,
      title: 'Password Reset',
      message: 'Your password has been reset by an administrator',
      type: 'warning',
      category: 'system'
    });
    
    res.json({
      success: true,
      message: 'Password reset successfully'
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: 'Error resetting password',
      error: error.message
    });
  }
});

// Delete user (soft delete)
router.delete('/users/:userId', async (req, res) => {
  try {
    const { userId } = req.params;
    
    const user = await User.findByIdAndUpdate(
      userId,
      { status: 'suspended', deletedAt: new Date() },
      { new: true }
    );
    
    if (!user) {
      return res.status(404).json({
        success: false,
        message: 'User not found'
      });
    }
    
    res.json({
      success: true,
      message: 'User deleted successfully'
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: 'Error deleting user',
      error: error.message
    });
  }
});

// =============================================
// 3. PRODUCT MANAGEMENT APIs
// =============================================

// Get all products
router.get('/products', async (req, res) => {
  try {
    const { status, search, page = 1, limit = 20 } = req.query;
    
    const filter = {};
    if (status) filter.status = status;
    if (search) {
      filter.$or = [
        { name: { $regex: search, $options: 'i' } },
        { productCode: { $regex: search, $options: 'i' } }
      ];
    }
    
    const products = await Product.find(filter)
      .sort({ createdAt: -1 })
      .limit(limit * 1)
      .skip((page - 1) * limit)
      .populate('createdBy', 'fullName')
      .lean();
    
    const total = await Product.countDocuments(filter);
    
    res.json({
      success: true,
      data: products,
      pagination: {
        total,
        page: parseInt(page),
        pages: Math.ceil(total / limit)
      }
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: 'Error fetching products',
      error: error.message
    });
  }
});

// Create new product
router.post('/products',
  validate.validateProduct,
  validate.handleValidationErrors,
  async (req, res) => {
    try {
      const productData = {
        ...req.body,
        createdBy: req.userId
      };
      
      const existing = await Product.findOne({ 
        productCode: productData.productCode 
      });
      
      if (existing) {
        return res.status(400).json({
          success: false,
          message: 'Product code already exists'
        });
      }
      
      const product = new Product(productData);
      await product.save();
      
      res.status(201).json({
        success: true,
        message: 'Product created successfully',
        data: product
      });
    } catch (error) {
      res.status(500).json({
        success: false,
        message: 'Error creating product',
        error: error.message
      });
    }
  }
);

// Update product
router.put('/products/:productId', async (req, res) => {
  try {
    const { productId } = req.params;
    const updates = req.body;
    
    const product = await Product.findByIdAndUpdate(
      productId,
      { ...updates, lastModifiedBy: req.userId },
      { new: true, runValidators: true }
    );
    
    if (!product) {
      return res.status(404).json({
        success: false,
        message: 'Product not found'
      });
    }
    
    res.json({
      success: true,
      message: 'Product updated successfully',
      data: product
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: 'Error updating product',
      error: error.message
    });
  }
});

// Update product status
router.patch('/products/:productId/status', async (req, res) => {
  try {
    const { productId } = req.params;
    const { status } = req.body;
    
    if (!['active', 'inactive'].includes(status)) {
      return res.status(400).json({
        success: false,
        message: 'Invalid status'
      });
    }
    
    const product = await Product.findByIdAndUpdate(
      productId,
      { status, lastModifiedBy: req.userId },
      { new: true }
    );
    
    if (!product) {
      return res.status(404).json({
        success: false,
        message: 'Product not found'
      });
    }
    
    res.json({
      success: true,
      message: `Product ${status === 'active' ? 'activated' : 'deactivated'} successfully`,
      data: product
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: 'Error updating product status',
      error: error.message
    });
  }
});

// Delete product
router.delete('/products/:productId', async (req, res) => {
  try {
    const { productId } = req.params;
    
    const hasTransactions = await Transaction.findOne({
      'dataDetails.product': productId
    });
    
    if (hasTransactions) {
      return res.status(400).json({
        success: false,
        message: 'Cannot delete product with existing transactions'
      });
    }
    
    const product = await Product.findByIdAndDelete(productId);
    
    if (!product) {
      return res.status(404).json({
        success: false,
        message: 'Product not found'
      });
    }
    
    res.json({
      success: true,
      message: 'Product deleted successfully'
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: 'Error deleting product',
      error: error.message
    });
  }
});

// =============================================
// 4. PRICING MANAGEMENT APIs
// =============================================

// Set/Update product pricing for different roles
router.post('/products/:productId/pricing',
  validate.validatePriceSetting,
  validate.handleValidationErrors,
  async (req, res) => {
    try {
      const { productId } = req.params;
      const { costPrice, agentPrice, dealerPrice, supplierPrice } = req.body;
      
      const product = await Product.findById(productId);
      if (!product) {
        return res.status(404).json({
          success: false,
          message: 'Product not found'
        });
      }
      
      const priceSetting = await PriceSetting.findOneAndUpdate(
        { product: productId, isActive: true },
        {
          product: productId,
          costPrice,
          agentPrice,
          dealerPrice,
          supplierPrice,
          setBy: req.userId,
          isActive: true
        },
        { new: true, upsert: true }
      );
      
      product.pricing = [
        { role: 'agent', price: agentPrice },
        { role: 'dealer', price: dealerPrice },
        { role: 'supplier', price: supplierPrice }
      ];
      await product.save();
      
      res.json({
        success: true,
        message: 'Pricing updated successfully',
        data: priceSetting
      });
    } catch (error) {
      res.status(500).json({
        success: false,
        message: 'Error updating pricing',
        error: error.message
      });
    }
  }
);

// Get pricing history for a product
router.get('/products/:productId/pricing-history', async (req, res) => {
  try {
    const { productId } = req.params;
    
    const priceHistory = await PriceSetting.find({ product: productId })
      .sort({ createdAt: -1 })
      .populate('setBy', 'fullName email')
      .lean();
    
    res.json({
      success: true,
      data: priceHistory
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: 'Error fetching pricing history',
      error: error.message
    });
  }
});

// Bulk update pricing
router.post('/products/bulk-pricing', async (req, res) => {
  try {
    const { percentage, operation, roles } = req.body;
    
    if (!percentage || !operation || !roles) {
      return res.status(400).json({
        success: false,
        message: 'Percentage, operation, and roles required'
      });
    }
    
    const products = await Product.find({ status: 'active' });
    const updates = [];
    
    for (const product of products) {
      const currentPricing = await PriceSetting.findOne({
        product: product._id,
        isActive: true
      });
      
      if (currentPricing) {
        const multiplier = operation === 'increase' 
          ? (1 + percentage / 100) 
          : (1 - percentage / 100);
        
        const newPricing = {
          costPrice: currentPricing.costPrice,
          agentPrice: roles.includes('agent') 
            ? currentPricing.agentPrice * multiplier 
            : currentPricing.agentPrice,
          dealerPrice: roles.includes('dealer') 
            ? currentPricing.dealerPrice * multiplier 
            : currentPricing.dealerPrice,
          supplierPrice: roles.includes('supplier') 
            ? currentPricing.supplierPrice * multiplier 
            : currentPricing.supplierPrice,
        };
        
        updates.push({
          productId: product._id,
          ...newPricing
        });
      }
    }
    
    for (const update of updates) {
      await PriceSetting.findOneAndUpdate(
        { product: update.productId, isActive: true },
        {
          ...update,
          setBy: req.userId
        }
      );
    }
    
    res.json({
      success: true,
      message: `Bulk pricing update applied to ${updates.length} products`,
      data: updates
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: 'Error updating bulk pricing',
      error: error.message
    });
  }
});

// =============================================
// 5. TRANSACTION MANAGEMENT APIs
// =============================================

// Get all transactions with filters
router.get('/transactions', async (req, res) => {
  try {
    const { 
      status, 
      type, 
      userId,
      startDate,
      endDate,
      page = 1, 
      limit = 20 
    } = req.query;
    
    const filter = {};
    if (status) filter.status = status;
    if (type) filter.type = type;
    if (userId) filter.user = userId;
    if (startDate || endDate) {
      filter.createdAt = {};
      if (startDate) filter.createdAt.$gte = new Date(startDate);
      if (endDate) filter.createdAt.$lte = new Date(endDate);
    }
    
    const transactions = await Transaction.find(filter)
      .sort({ createdAt: -1 })
      .limit(limit * 1)
      .skip((page - 1) * limit)
      .populate('user', 'fullName email phone role')
      .populate('dataDetails.product', 'name productCode')
      .lean();
    
    const total = await Transaction.countDocuments(filter);
    
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
      message: 'Error fetching transactions',
      error: error.message
    });
  }
});

// Get transaction details
router.get('/transactions/:transactionId', async (req, res) => {
  try {
    const { transactionId } = req.params;
    
    const transaction = await Transaction.findOne({ 
      $or: [
        { _id: transactionId },
        { transactionId: transactionId }
      ]
    })
      .populate('user', 'fullName email phone role wallet')
      .populate('dataDetails.product')
      .lean();
    
    if (!transaction) {
      return res.status(404).json({
        success: false,
        message: 'Transaction not found'
      });
    }
    
    res.json({
      success: true,
      data: transaction
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: 'Error fetching transaction',
      error: error.message
    });
  }
});

// Update order status
router.patch('/transactions/:transactionId/status', async (req, res) => {
  try {
    const { transactionId } = req.params;
    const { status, reason } = req.body;
    
    if (!['pending', 'successful', 'failed'].includes(status)) {
      return res.status(400).json({
        success: false,
        message: 'Invalid status. Must be pending, successful, or failed'
      });
    }
    
    const transaction = await Transaction.findOne({
      $or: [
        { _id: transactionId },
        { transactionId: transactionId }
      ]
    });
    
    if (!transaction) {
      return res.status(404).json({
        success: false,
        message: 'Transaction not found'
      });
    }
    
    const oldStatus = transaction.status;
    
    if (oldStatus === 'successful' && status === 'failed') {
      const user = await User.findById(transaction.user);
      if (user) {
        const balanceBefore = user.wallet.balance;
        user.wallet.balance += transaction.amount;
        await user.save();
        
        await WalletTransaction.create({
          user: transaction.user,
          type: 'credit',
          amount: transaction.amount,
          balanceBefore: balanceBefore,
          balanceAfter: user.wallet.balance,
          purpose: 'refund',
          reference: 'REF' + Date.now(),
          status: 'completed',
          description: `Refund for failed transaction ${transaction.transactionId}`
        });
      }
    }
    
    if ((oldStatus === 'failed' || oldStatus === 'pending') && status === 'successful') {
      const user = await User.findById(transaction.user);
      if (user) {
        if (user.wallet.balance >= transaction.amount) {
          const balanceBefore = user.wallet.balance;
          user.wallet.balance -= transaction.amount;
          await user.save();
          
          await WalletTransaction.create({
            user: transaction.user,
            type: 'debit',
            amount: transaction.amount,
            balanceBefore: balanceBefore,
            balanceAfter: user.wallet.balance,
            purpose: 'purchase',
            reference: transaction.transactionId,
            status: 'completed',
            description: `Payment for transaction ${transaction.transactionId}`
          });
        } else {
          return res.status(400).json({
            success: false,
            message: 'User has insufficient wallet balance for this status change'
          });
        }
      }
    }
    
    transaction.status = status;
    transaction.statusUpdatedBy = req.userId;
    transaction.statusUpdatedAt = new Date();
    if (status === 'successful') {
      transaction.completedAt = new Date();
    }
    if (reason) {
      transaction.statusUpdateReason = reason;
    }
    await transaction.save();
    
    await Notification.create({
      user: transaction.user,
      title: 'Order Status Updated',
      message: `Your order ${transaction.transactionId} status has been updated to ${status}. ${reason || ''}`,
      type: status === 'successful' ? 'success' : status === 'failed' ? 'error' : 'info',
      category: 'transaction',
      relatedTransaction: transaction._id
    });
    
    res.json({
      success: true,
      message: `Transaction status updated to ${status}`,
      data: {
        transactionId: transaction.transactionId,
        oldStatus,
        newStatus: status,
        updatedBy: req.user.fullName
      }
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: 'Error updating transaction status',
      error: error.message
    });
  }
});

// Reverse/Refund transaction
router.post('/transactions/:transactionId/reverse', async (req, res) => {
  try {
    const { transactionId } = req.params;
    const { reason } = req.body;
    
    const transaction = await Transaction.findOne({
      $or: [
        { _id: transactionId },
        { transactionId: transactionId }
      ]
    });
    
    if (!transaction) {
      return res.status(404).json({
        success: false,
        message: 'Transaction not found'
      });
    }
    
    if (transaction.status !== 'successful') {
      return res.status(400).json({
        success: false,
        message: 'Only successful transactions can be reversed'
      });
    }
    
    const user = await User.findById(transaction.user);
    user.wallet.balance += transaction.amount;
    await user.save();
    
    transaction.status = 'reversed';
    transaction.reversedAt = new Date();
    transaction.reversedBy = req.userId;
    transaction.notes = reason;
    await transaction.save();
    
    await WalletTransaction.create({
      user: transaction.user,
      type: 'credit',
      amount: transaction.amount,
      balanceBefore: user.wallet.balance - transaction.amount,
      balanceAfter: user.wallet.balance,
      purpose: 'refund',
      reference: 'REF' + Date.now(),
      status: 'completed',
      description: `Refund for transaction ${transaction.transactionId}`
    });
    
    await Notification.create({
      user: transaction.user,
      title: 'Transaction Refunded',
      message: `Your transaction ${transaction.transactionId} has been refunded. Amount: GHS ${transaction.amount}`,
      type: 'success',
      category: 'transaction',
      relatedTransaction: transaction._id
    });
    
    res.json({
      success: true,
      message: 'Transaction reversed successfully',
      data: transaction
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: 'Error reversing transaction',
      error: error.message
    });
  }
});

// Manual transaction retry
router.post('/transactions/:transactionId/retry', async (req, res) => {
  try {
    const { transactionId } = req.params;
    
    const transaction = await Transaction.findOne({
      $or: [
        { _id: transactionId },
        { transactionId: transactionId }
      ]
    });
    
    if (!transaction) {
      return res.status(404).json({
        success: false,
        message: 'Transaction not found'
      });
    }
    
    if (transaction.status === 'successful') {
      return res.status(400).json({
        success: false,
        message: 'Transaction already successful'
      });
    }
    
    transaction.status = 'processing';
    transaction.retryCount = (transaction.retryCount || 0) + 1;
    await transaction.save();
    
    res.json({
      success: true,
      message: 'Transaction retry initiated',
      data: transaction
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: 'Error retrying transaction',
      error: error.message
    });
  }
});

// Bulk update order statuses
router.post('/transactions/bulk-status-update', async (req, res) => {
  try {
    const { transactionIds, status, reason } = req.body;
    
    if (!transactionIds || !Array.isArray(transactionIds) || transactionIds.length === 0) {
      return res.status(400).json({
        success: false,
        message: 'Transaction IDs array is required'
      });
    }
    
    if (!['pending', 'successful', 'failed'].includes(status)) {
      return res.status(400).json({
        success: false,
        message: 'Invalid status'
      });
    }
    
    const results = {
      updated: [],
      failed: [],
      errors: []
    };
    
    for (const transactionId of transactionIds) {
      try {
        const transaction = await Transaction.findOne({
          $or: [
            { _id: transactionId },
            { transactionId: transactionId }
          ]
        });
        
        if (!transaction) {
          results.failed.push(transactionId);
          results.errors.push({ id: transactionId, error: 'Not found' });
          continue;
        }
        
        transaction.status = status;
        transaction.statusUpdatedBy = req.userId;
        transaction.statusUpdatedAt = new Date();
        if (reason) transaction.statusUpdateReason = reason;
        if (status === 'successful') transaction.completedAt = new Date();
        
        await transaction.save();
        results.updated.push(transactionId);
        
      } catch (error) {
        results.failed.push(transactionId);
        results.errors.push({ id: transactionId, error: error.message });
      }
    }
    
    res.json({
      success: true,
      message: `Bulk status update completed`,
      results: {
        totalRequested: transactionIds.length,
        successfullyUpdated: results.updated.length,
        failed: results.failed.length,
        details: results
      }
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: 'Error in bulk status update',
      error: error.message
    });
  }
});


// Preview export with status change warning
router.post('/orders/export/preview', async (req, res) => {
  try {
    const { 
      startDate, 
      endDate, 
      status = 'pending',
      markAsSuccessful = false
    } = req.body;
    
    const filter = {
      type: 'data_purchase',
      status: status
    };
    
    if (startDate || endDate) {
      filter.createdAt = {};
      if (startDate) filter.createdAt.$gte = new Date(startDate);
      if (endDate) filter.createdAt.$lte = new Date(endDate);
    }
    
    const orders = await Transaction.find(filter)
      .sort({ createdAt: -1 })
      .limit(40)
      .populate('dataDetails.product', 'name capacity')
      .populate('user', 'fullName wallet')
      .lean();
    
    const exportData = orders.map(order => ({
      transactionId: order.transactionId,
      beneficiaryNumber: order.dataDetails?.beneficiaryNumber || 'N/A',
      capacity: order.dataDetails?.capacity || 
        (order.dataDetails?.product?.capacity ? 
          `${order.dataDetails.product.capacity.value}${order.dataDetails.product.capacity.unit}` : 
          'N/A'),
      currentStatus: order.status,
      userName: order.user?.fullName,
      walletBalance: order.user?.wallet?.balance,
      orderAmount: order.amount,
      sufficientBalance: order.user?.wallet?.balance >= order.amount,
      date: order.createdAt
    }));
    
    let impactSummary = null;
    if (status === 'pending' && markAsSuccessful) {
      const totalAmount = exportData.reduce((sum, order) => sum + order.orderAmount, 0);
      const ordersWithInsufficientBalance = exportData.filter(order => !order.sufficientBalance);
      
      impactSummary = {
        totalOrdersToProcess: exportData.length,
        totalAmountToDeduct: totalAmount,
        ordersWithInsufficientBalance: ordersWithInsufficientBalance.length,
        warning: 'These pending orders will be marked as SUCCESSFUL and amounts will be deducted from user wallets'
      };
    }
    
    res.json({
      success: true,
      message: `Found ${exportData.length} orders (max 40 shown)`,
      data: exportData,
      count: exportData.length,
      maxExportLimit: 40,
      willMarkAsSuccessful: markAsSuccessful,
      impactSummary: impactSummary
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: 'Error previewing export data',
      error: error.message
    });
  }
});

// =============================================
// 6. WALLET MANAGEMENT APIs
// =============================================

// Get all wallet transactions
router.get('/wallet-transactions', async (req, res) => {
  try {
    const { 
      userId, 
      type,
      purpose,
      startDate,
      endDate,
      page = 1, 
      limit = 20 
    } = req.query;
    
    const filter = {};
    if (userId) filter.user = userId;
    if (type) filter.type = type;
    if (purpose) filter.purpose = purpose;
    if (startDate || endDate) {
      filter.createdAt = {};
      if (startDate) filter.createdAt.$gte = new Date(startDate);
      if (endDate) filter.createdAt.$lte = new Date(endDate);
    }
    
    const walletTransactions = await WalletTransaction.find(filter)
      .sort({ createdAt: -1 })
      .limit(limit * 1)
      .skip((page - 1) * limit)
      .populate('user', 'fullName email phone role')
      .lean();
    
    const total = await WalletTransaction.countDocuments(filter);
    
    res.json({
      success: true,
      data: walletTransactions,
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

// Adjust user wallet
router.post('/wallet/adjust', async (req, res) => {
  try {
    const { userId, amount, type, reason } = req.body;
    
    if (!userId || !amount || !type || !reason) {
      return res.status(400).json({
        success: false,
        message: 'userId, amount, type, and reason are required'
      });
    }
    
    const user = await User.findById(userId);
    if (!user) {
      return res.status(404).json({
        success: false,
        message: 'User not found'
      });
    }
    
    const balanceBefore = user.wallet.balance;
    
    if (type === 'credit') {
      user.wallet.balance += amount;
    } else if (type === 'debit') {
      if (user.wallet.balance < amount) {
        return res.status(400).json({
          success: false,
          message: 'Insufficient wallet balance'
        });
      }
      user.wallet.balance -= amount;
    }
    
    await user.save();
    
    await WalletTransaction.create({
      user: userId,
      type,
      amount,
      balanceBefore,
      balanceAfter: user.wallet.balance,
      purpose: 'adjustment',
      reference: 'ADJ' + Date.now(),
      status: 'completed',
      description: `Admin adjustment: ${reason}`
    });
    
    await Notification.create({
      user: userId,
      title: 'Wallet Adjustment',
      message: `Your wallet has been ${type}ed with GHS ${amount}. Reason: ${reason}`,
      type: 'info',
      category: 'wallet'
    });
    
    res.json({
      success: true,
      message: 'Wallet adjusted successfully',
      data: {
        user: user.fullName,
        type,
        amount,
        newBalance: user.wallet.balance
      }
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: 'Error adjusting wallet',
      error: error.message
    });
  }
});

// =============================================
// 7. SYSTEM SETTINGS APIs
// =============================================

// Get all system settings
router.get('/settings', async (req, res) => {
  try {
    const { category } = req.query;
    
    const filter = {};
    if (category) filter.category = category;
    
    const settings = await SystemSetting.find(filter)
      .sort({ category: 1, key: 1 })
      .lean();
    
    res.json({
      success: true,
      data: settings
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: 'Error fetching settings',
      error: error.message
    });
  }
});

// Update system setting
router.put('/settings/:key', async (req, res) => {
  try {
    const { key } = req.params;
    const { value, description } = req.body;
    
    const setting = await SystemSetting.findOneAndUpdate(
      { key },
      { 
        value, 
        description,
        lastModifiedBy: req.userId,
        updatedAt: new Date()
      },
      { new: true, upsert: true }
    );
    
    res.json({
      success: true,
      message: 'Setting updated successfully',
      data: setting
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: 'Error updating setting',
      error: error.message
    });
  }
});

// Toggle maintenance mode
router.post('/settings/maintenance', async (req, res) => {
  try {
    const { enabled, message } = req.body;
    
    await SystemSetting.findOneAndUpdate(
      { key: 'maintenance_mode' },
      { value: enabled },
      { upsert: true }
    );
    
    if (message) {
      await SystemSetting.findOneAndUpdate(
        { key: 'maintenance_message' },
        { value: message },
        { upsert: true }
      );
    }
    
    res.json({
      success: true,
      message: `Maintenance mode ${enabled ? 'enabled' : 'disabled'}`
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: 'Error toggling maintenance mode',
      error: error.message
    });
  }
});

// =============================================
// 8. REPORTS APIs
// =============================================

// Generate sales report
router.get('/reports/sales', async (req, res) => {
  try {
    const { startDate, endDate, groupBy = 'day' } = req.query;
    
    const matchStage = {
      status: 'successful',
      type: 'data_purchase'
    };
    
    if (startDate || endDate) {
      matchStage.createdAt = {};
      if (startDate) matchStage.createdAt.$gte = new Date(startDate);
      if (endDate) matchStage.createdAt.$lte = new Date(endDate);
    }
    
    let groupFormat;
    switch (groupBy) {
      case 'hour':
        groupFormat = '%Y-%m-%d %H:00';
        break;
      case 'day':
        groupFormat = '%Y-%m-%d';
        break;
      case 'week':
        groupFormat = '%Y-Week %V';
        break;
      case 'month':
        groupFormat = '%Y-%m';
        break;
      default:
        groupFormat = '%Y-%m-%d';
    }
    
    const report = await Transaction.aggregate([
      { $match: matchStage },
      {
        $group: {
          _id: {
            $dateToString: { format: groupFormat, date: '$createdAt' }
          },
          totalSales: { $sum: 1 },
          totalRevenue: { $sum: '$amount' },
          avgTransactionValue: { $avg: '$amount' }
        }
      },
      { $sort: { _id: 1 } }
    ]);
    
    res.json({
      success: true,
      data: report
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: 'Error generating sales report',
      error: error.message
    });
  }
});

// Generate user activity report
router.get('/reports/user-activity', async (req, res) => {
  try {
    const { startDate, endDate, role } = req.query;
    
    const userFilter = {};
    if (role) userFilter.role = role;
    
    const users = await User.find(userFilter).select('_id fullName email role');
    const userIds = users.map(u => u._id);
    
    const transactionFilter = {
      user: { $in: userIds }
    };
    
    if (startDate || endDate) {
      transactionFilter.createdAt = {};
      if (startDate) transactionFilter.createdAt.$gte = new Date(startDate);
      if (endDate) transactionFilter.createdAt.$lte = new Date(endDate);
    }
    
    const activity = await Transaction.aggregate([
      { $match: transactionFilter },
      {
        $group: {
          _id: '$user',
          totalTransactions: { $sum: 1 },
          totalSpent: { $sum: '$amount' },
          successfulTransactions: {
            $sum: { $cond: [{ $eq: ['$status', 'successful'] }, 1, 0] }
          },
          failedTransactions: {
            $sum: { $cond: [{ $eq: ['$status', 'failed'] }, 1, 0] }
          }
        }
      },
      {
        $lookup: {
          from: 'reseller_users',
          localField: '_id',
          foreignField: '_id',
          as: 'userInfo'
        }
      },
      { $unwind: '$userInfo' },
      {
        $project: {
          user: {
            id: '$userInfo._id',
            fullName: '$userInfo.fullName',
            email: '$userInfo.email',
            role: '$userInfo.role'
          },
          totalTransactions: 1,
          totalSpent: 1,
          successfulTransactions: 1,
          failedTransactions: 1,
          successRate: {
            $multiply: [
              { $divide: ['$successfulTransactions', '$totalTransactions'] },
              100
            ]
          }
        }
      },
      { $sort: { totalSpent: -1 } }
    ]);
    
    res.json({
      success: true,
      data: activity
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: 'Error generating user activity report',
      error: error.message
    });
  }
});

// Export transactions to CSV
router.get('/reports/export/transactions', async (req, res) => {
  try {
    const { startDate, endDate, format = 'json' } = req.query;
    
    const filter = {};
    if (startDate || endDate) {
      filter.createdAt = {};
      if (startDate) filter.createdAt.$gte = new Date(startDate);
      if (endDate) filter.createdAt.$lte = new Date(endDate);
    }
    
    const transactions = await Transaction.find(filter)
      .populate('user', 'fullName email phone')
      .populate('dataDetails.product', 'name productCode')
      .lean();
    
    const exportData = transactions.map(t => ({
      transactionId: t.transactionId,
      date: t.createdAt,
      user: t.user?.fullName,
      email: t.user?.email,
      phone: t.user?.phone,
      product: t.dataDetails?.product?.name,
      beneficiary: t.dataDetails?.beneficiaryNumber,
      amount: t.amount,
      status: t.status,
      reference: t.reference
    }));
    
    if (format === 'csv') {
      const csvHeader = Object.keys(exportData[0]).join(',');
      const csvRows = exportData.map(row => 
        Object.values(row).join(',')
      ).join('\n');
      const csv = `${csvHeader}\n${csvRows}`;
      
      res.setHeader('Content-Type', 'text/csv');
      res.setHeader('Content-Disposition', 'attachment; filename=transactions.csv');
      res.send(csv);
    } else {
      res.json({
        success: true,
        data: exportData
      });
    }
  } catch (error) {
    res.status(500).json({
      success: false,
      message: 'Error exporting transactions',
      error: error.message
    });
  }
});

// =============================================
// 9. API MANAGEMENT
// =============================================

// Get API logs
router.get('/api-logs', async (req, res) => {
  try {
    const { userId, startDate, endDate, page = 1, limit = 20 } = req.query;
    
    const filter = {};
    if (userId) filter.user = userId;
    if (startDate || endDate) {
      filter.createdAt = {};
      if (startDate) filter.createdAt.$gte = new Date(startDate);
      if (endDate) filter.createdAt.$lte = new Date(endDate);
    }
    
    const logs = await ApiLog.find(filter)
      .sort({ createdAt: -1 })
      .limit(limit * 1)
      .skip((page - 1) * limit)
      .populate('user', 'fullName email')
      .lean();
    
    const total = await ApiLog.countDocuments(filter);
    
    res.json({
      success: true,
      data: logs,
      pagination: {
        total,
        page: parseInt(page),
        pages: Math.ceil(total / limit)
      }
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: 'Error fetching API logs',
      error: error.message
    });
  }
});

// Generate API key for user
router.post('/users/:userId/generate-api-key', async (req, res) => {
  try {
    const { userId } = req.params;
    const { webhookUrl } = req.body;
    
    const apiKey = 'pk_' + crypto.randomBytes(32).toString('hex');
    const apiSecret = crypto.randomBytes(32).toString('hex');
    const hashedSecret = await bcrypt.hash(apiSecret, 10);
    
    const user = await User.findByIdAndUpdate(
      userId,
      {
        'apiAccess.enabled': true,
        'apiAccess.apiKey': apiKey,
        'apiAccess.apiSecret': hashedSecret,
        'apiAccess.webhookUrl': webhookUrl
      },
      { new: true }
    ).select('fullName email apiAccess');
    
    if (!user) {
      return res.status(404).json({
        success: false,
        message: 'User not found'
      });
    }
    
    res.json({
      success: true,
      message: 'API credentials generated successfully',
      data: {
        apiKey,
        apiSecret,
        webhookUrl
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

// Revoke API access
router.delete('/users/:userId/revoke-api-access', async (req, res) => {
  try {
    const { userId } = req.params;
    
    const user = await User.findByIdAndUpdate(
      userId,
      {
        'apiAccess.enabled': false,
        'apiAccess.apiKey': null,
        'apiAccess.apiSecret': null
      },
      { new: true }
    ).select('fullName email');
    
    if (!user) {
      return res.status(404).json({
        success: false,
        message: 'User not found'
      });
    }
    
    res.json({
      success: true,
      message: 'API access revoked successfully'
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: 'Error revoking API access',
      error: error.message
    });
  }
});

// =============================================
// 10. NOTIFICATIONS
// =============================================

// Send broadcast notification
router.post('/notifications/broadcast', async (req, res) => {
  try {
    const { title, message, type = 'info', roles, userIds } = req.body;
    
    let recipients = [];
    
    if (userIds && userIds.length > 0) {
      recipients = userIds;
    } else if (roles && roles.length > 0) {
      const users = await User.find({ 
        role: { $in: roles },
        status: 'active'
      }).select('_id');
      recipients = users.map(u => u._id);
    } else {
      const users = await User.find({ status: 'active' }).select('_id');
      recipients = users.map(u => u._id);
    }
    
    const notifications = recipients.map(userId => ({
      user: userId,
      title,
      message,
      type,
      category: 'system'
    }));
    
    await Notification.insertMany(notifications);
    
    res.json({
      success: true,
      message: `Notification sent to ${recipients.length} users`
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: 'Error sending broadcast',
      error: error.message
    });
  }
});


// Add these new routes to your admin.js file

// =============================================
// BATCH MANAGEMENT APIs
// =============================================

// Get all batches with filters
router.get('/batches', async (req, res) => {
  try {
    const { 
      search,
      startDate,
      endDate,
      status,
      page = 1, 
      limit = 20 
    } = req.query;
    
    const filter = {};
    if (status) filter.status = status;
    if (startDate || endDate) {
      filter.exportDate = {};
      if (startDate) filter.exportDate.$gte = new Date(startDate);
      if (endDate) filter.exportDate.$lte = new Date(endDate);
    }
    if (search) {
      filter.$or = [
        { batchId: { $regex: search, $options: 'i' } },
        { 'orders.beneficiaryNumber': { $regex: search, $options: 'i' } },
        { 'orders.transactionId': { $regex: search, $options: 'i' } }
      ];
    }
    
    const batches = await Batch.find(filter)
      .sort({ exportDate: -1 })
      .limit(limit * 1)
      .skip((page - 1) * limit)
      .populate('exportedBy', 'fullName email')
      .lean();
    
    const total = await Batch.countDocuments(filter);
    
    res.json({
      success: true,
      data: batches,
      pagination: {
        total,
        page: parseInt(page),
        pages: Math.ceil(total / limit)
      }
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: 'Error fetching batches',
      error: error.message
    });
  }
});

// Get single batch details
router.get('/batches/:batchId', async (req, res) => {
  try {
    const { batchId } = req.params;
    const { search, page = 1, limit = 40 } = req.query;
    
    const batch = await Batch.findOne({ 
      $or: [
        { _id: batchId },
        { batchId: batchId }
      ]
    }).populate('exportedBy', 'fullName email');
    
    if (!batch) {
      return res.status(404).json({
        success: false,
        message: 'Batch not found'
      });
    }
    
    // Filter orders if search is provided
    let orders = batch.orders;
    if (search) {
      orders = orders.filter(order => 
        order.beneficiaryNumber.includes(search) ||
        order.transactionId.includes(search) ||
        order.userName?.toLowerCase().includes(search.toLowerCase())
      );
    }
    
    // Paginate orders
    const startIndex = (page - 1) * limit;
    const endIndex = page * limit;
    const paginatedOrders = orders.slice(startIndex, endIndex);
    
    res.json({
      success: true,
      data: {
        ...batch.toObject(),
        orders: paginatedOrders,
        ordersPagination: {
          total: orders.length,
          page: parseInt(page),
          pages: Math.ceil(orders.length / limit)
        }
      }
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: 'Error fetching batch details',
      error: error.message
    });
  }
});

// Re-export a batch
router.post('/batches/:batchId/re-export', async (req, res) => {
  try {
    const { batchId } = req.params;
    
    const batch = await Batch.findOne({ 
      $or: [
        { _id: batchId },
        { batchId: batchId }
      ]
    });
    
    if (!batch) {
      return res.status(404).json({
        success: false,
        message: 'Batch not found'
      });
    }
    
    // Generate Excel from batch data
    const excelData = batch.orders.map(order => ({
      'Beneficiary Number': order.beneficiaryNumber,
      'Capacity': order.capacity
    }));
    
    const workbook = XLSX.utils.book_new();
    const worksheet = XLSX.utils.json_to_sheet(excelData);
    XLSX.utils.book_append_sheet(workbook, worksheet, 'Orders');
    
    // Add batch summary
    const summaryData = [{
      'Batch ID': batch.batchId,
      'Export Date': batch.exportDate,
      'Total Orders': batch.stats.totalOrders,
      'Processed': batch.stats.processedOrders,
      'Failed': batch.stats.failedOrders,
      'Total Amount': batch.stats.totalAmount,
      'Exported By': req.user.fullName
    }];
    
    const summarySheet = XLSX.utils.json_to_sheet(summaryData);
    XLSX.utils.book_append_sheet(workbook, summarySheet, 'Summary');
    
    const excelBuffer = XLSX.write(workbook, { type: 'buffer', bookType: 'xlsx' });
    
    res.setHeader('Content-Type', 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet');
    res.setHeader('Content-Disposition', `attachment; filename="batch_${batch.batchId}.xlsx"`);
    res.send(excelBuffer);
    
  } catch (error) {
    res.status(500).json({
      success: false,
      message: 'Error re-exporting batch',
      error: error.message
    });
  }
});

// Updated Export orders to Excel with batch tracking
// Replace the /orders/export/excel route in your admin.js with this optimized version

// FIXED: Export orders to Excel with batch tracking
// This version does NOT deduct money (since money was already deducted when order was placed)
router.post('/orders/export/excel', async (req, res) => {
  try {
    const { 
      startDate, 
      endDate, 
      status = 'pending',
      markAsSuccessful = false,
      confirmExport = true
    } = req.body;
    
    // Build filter
    const filter = {
      type: 'data_purchase',
      status: status
    };
    
    if (startDate || endDate) {
      filter.createdAt = {};
      if (startDate) filter.createdAt.$gte = new Date(startDate);
      if (endDate) filter.createdAt.$lte = new Date(endDate);
    }
    
    // Fetch orders with populated data
    const orders = await Transaction.find(filter)
      .sort({ createdAt: -1 })
      .limit(40)
      .populate('dataDetails.product', 'name capacity')
      .populate('user', 'fullName phone wallet')
      .lean();
    
    if (orders.length === 0) {
      return res.status(404).json({
        success: false,
        message: 'No orders found'
      });
    }
    
    // Generate batch ID
    const batchCount = await Batch.countDocuments();
    const batchId = `BATCH${String(batchCount + 1).padStart(6, '0')}`;
    const batchNumber = batchCount + 1;
    
    const batchOrders = [];
    let totalAmount = 0;
    
    // Prepare batch order data
    for (const order of orders) {
      batchOrders.push({
        transactionId: order.transactionId,
        beneficiaryNumber: order.dataDetails?.beneficiaryNumber || 'N/A',
        capacity: order.dataDetails?.capacity || 'N/A',
        amount: order.amount,
        status: order.status,
        userName: order.user?.fullName,
        userId: order.user?._id
      });
      totalAmount += order.amount;
    }
    
    let processedCount = 0;
    let failedCount = 0;
    
    // Process orders if marking as successful
    if (status === 'pending' && markAsSuccessful) {
      
      // IMPORTANT: Do NOT deduct money - it was already deducted when order was placed!
      // Just update the transaction status
      
      const bulkOps = orders.map(order => ({
        updateOne: {
          filter: { _id: order._id },
          update: {
            $set: {
              status: 'successful',
              completedAt: new Date(),
              statusUpdatedBy: req.userId,
              statusUpdatedAt: new Date(),
              statusUpdateReason: `Batch ${batchId} - Exported for processing`,
              'metadata.batchId': batchId,
              'metadata.exportedAt': new Date()
            }
          }
        }
      }));
      
      const bulkResult = await Transaction.bulkWrite(bulkOps, { ordered: false });
      processedCount = bulkResult.modifiedCount;
      
      // Update batch order status
      batchOrders.forEach(order => {
        const idx = batchOrders.findIndex(bo => bo.transactionId === order.transactionId);
        if (idx !== -1) batchOrders[idx].status = 'successful';
      });
      
      // Optional: Send bulk notification to users
      const notifications = orders.map(order => ({
        user: order.user._id,
        title: 'Order Processed',
        message: `Your order ${order.transactionId} has been processed and sent to ${order.dataDetails?.beneficiaryNumber}`,
        type: 'success',
        category: 'transaction',
        relatedTransaction: order._id
      }));
      
      try {
        await Notification.insertMany(notifications, { ordered: false });
      } catch (notifError) {
        console.log('Some notifications may have failed:', notifError.message);
      }
    }
    
    // Create batch record
    await Batch.create({
      batchId,
      batchNumber,
      exportedBy: req.userId,
      orders: batchOrders,
      stats: {
        totalOrders: orders.length,
        processedOrders: processedCount,
        failedOrders: failedCount,
        totalAmount: totalAmount,
        originalStatus: status,
        markedAsSuccessful: markAsSuccessful
      },
      status: processedCount === orders.length ? 'completed' : 
              processedCount > 0 ? 'partial' : 'exported',
      fileName: `batch_${batchId}_${new Date().toISOString().split('T')[0]}.xlsx`,
      notes: 'Orders exported for MTN processing - no wallet changes (already paid)'
    });
    
    // Generate Excel
    const workbook = XLSX.utils.book_new();
    
    // Main sheet with order details
    const excelData = batchOrders.map(order => ({
      'Beneficiary Number': order.beneficiaryNumber,
      'Data Bundle': order.capacity,
      'Transaction ID': order.transactionId,
      'Status': order.status,
      'Amount (GHS)': order.amount
    }));
    
    const worksheet = XLSX.utils.json_to_sheet(excelData);
    XLSX.utils.book_append_sheet(workbook, worksheet, 'Orders');
    
    // Add summary sheet
    const summaryData = [{
      'Batch ID': batchId,
      'Export Date': new Date().toISOString(),
      'Total Orders': orders.length,
      'Total Amount (GHS)': totalAmount,
      'Status': markAsSuccessful ? 'Marked as Successful' : 'Exported Only',
      'Note': 'Payment already collected from users when orders were placed'
    }];
    
    const summarySheet = XLSX.utils.json_to_sheet(summaryData);
    XLSX.utils.book_append_sheet(workbook, summarySheet, 'Summary');
    
    // Generate buffer
    const excelBuffer = XLSX.write(workbook, { type: 'buffer', bookType: 'xlsx' });
    
    // Send response
    res.setHeader('Content-Type', 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet');
    res.setHeader('Content-Disposition', `attachment; filename="batch_${batchId}.xlsx"`);
    res.setHeader('X-Batch-ID', batchId);
    res.setHeader('X-Export-Summary', JSON.stringify({
      batchId,
      exported: orders.length,
      processed: processedCount,
      failed: failedCount,
      note: 'No wallet changes - orders were already paid'
    }));
    
    res.send(excelBuffer);
    
  } catch (error) {
    console.error('Export error:', error);
    res.status(500).json({
      success: false,
      message: 'Error exporting batch',
      error: error.message
    });
  }
});

// Alternative: Ultra-fast export without processing (just export)
router.post('/orders/export/excel-fast', async (req, res) => {
  try {
    const { status = 'pending' } = req.body;
    
    // Single query with lean for speed
    const orders = await Transaction.find({
      type: 'data_purchase',
      status: status
    })
    .select('transactionId dataDetails.beneficiaryNumber dataDetails.capacity amount')
    .limit(40)
    .lean()
    .exec();
    
    if (orders.length === 0) {
      return res.status(404).json({ success: false, message: 'No orders found' });
    }
    
    // Quick batch ID
    const batchId = `BATCH${Date.now().toString().slice(-6)}`;
    
    // Direct Excel generation
    const data = orders.map(o => ({
      'Beneficiary': o.dataDetails?.beneficiaryNumber || 'N/A',
      'Data': o.dataDetails?.capacity || 'N/A'
    }));
    
    const ws = XLSX.utils.json_to_sheet(data);
    const wb = XLSX.utils.book_new();
    XLSX.utils.book_append_sheet(wb, ws, 'Orders');
    
    const buffer = XLSX.write(wb, { type: 'buffer', bookType: 'xlsx' });
    
    res.setHeader('Content-Type', 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet');
    res.setHeader('Content-Disposition', `attachment; filename="${batchId}.xlsx"`);
    res.send(buffer);
    
  } catch (error) {
    res.status(500).json({ success: false, message: error.message });
  }
});

// Get batch statistics
router.get('/batches/stats', async (req, res) => {
  try {
    const stats = await Batch.aggregate([
      {
        $group: {
          _id: null,
          totalBatches: { $sum: 1 },
          totalOrders: { $sum: '$stats.totalOrders' },
          totalProcessed: { $sum: '$stats.processedOrders' },
          totalFailed: { $sum: '$stats.failedOrders' },
          totalAmount: { $sum: '$stats.totalAmount' }
        }
      }
    ]);
    
    const recentBatches = await Batch.find()
      .sort({ exportDate: -1 })
      .limit(5)
      .populate('exportedBy', 'fullName')
      .lean();
    
    res.json({
      success: true,
      data: {
        overview: stats[0] || {
          totalBatches: 0,
          totalOrders: 0,
          totalProcessed: 0,
          totalFailed: 0,
          totalAmount: 0
        },
        recentBatches
      }
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: 'Error fetching batch statistics',
      error: error.message
    });
  }
});
// =============================================
// EXPORT ROUTER
// =============================================

module.exports = router;