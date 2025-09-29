// =============================================
// COMPLETE ADMIN API ROUTES - GHANA MTN DATA PLATFORM
// With Integrated Export Settings & System Status
// =============================================

const express = require('express');
const router = express.Router();
const bcrypt = require('bcryptjs');
const crypto = require('crypto');
const mongoose = require('mongoose');
const XLSX = require('xlsx');
const cron = require('node-cron');

// Import all models including new export schemas
const {
  User,
  Product,
  Transaction,
  PriceSetting,
  WalletTransaction,
  SystemSetting,
  ApiLog,
  Notification,
  Batch,
} = require('../schema/schema');

const { 
  ExportSettings,
  ExportHistory,
  SystemStatus,
  ExportQueue 
} = require('../EXPORTSchema/schema');

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
// HELPER VARIABLES AND FUNCTIONS (DECLARED ONCE)
// =============================================

// Store scheduled jobs in memory - DECLARED ONLY ONCE
const scheduledJobs = new Map();

// Helper function to schedule auto-completion - SINGLE CORRECT VERSION
function scheduleAutoCompletion(exportId, minutes, settings) {
  try {
    const delay = minutes * 60 * 1000; // Convert minutes to milliseconds
    
    const timeout = setTimeout(async () => {
      try {
        await completeExport(exportId, settings);
        scheduledJobs.delete(exportId);
      } catch (error) {
        console.error(`Error in auto-completion for export ${exportId}:`, error);
        scheduledJobs.delete(exportId);
      }
    }, delay);
    
    scheduledJobs.set(exportId, timeout);
    console.log(`✅ Scheduled auto-completion for export ${exportId} after ${minutes} minutes`);
    console.log(`   Orders will be updated from 'sent' to 'successful' at ${new Date(Date.now() + delay).toLocaleString()}`);
  } catch (error) {
    console.error(`Error scheduling auto-completion for export ${exportId}:`, error);
  }
}

// Helper function to complete an export - SINGLE VERSION
async function completeExport(exportId, settings) {
  const session = await mongoose.startSession();
  let transactionCommitted = false;
  
  try {
    session.startTransaction();
    
    const orders = await Transaction.find({ 
      'metadata.exportId': exportId,
      status: 'sent'
    }).session(session);
    
    if (orders.length === 0) {
      console.log(`No orders to complete for export ${exportId}`);
      await session.abortTransaction();
      session.endSession();
      return;
    }
    
    const successRate = (settings?.autoComplete?.successRate || 95) / 100;
    let successCount = 0;
    let failCount = 0;
    
    const bulkOps = [];
    const userNotifications = new Map();
    
    for (const order of orders) {
      const isSuccess = Math.random() < successRate;
      
      if (isSuccess) {
        successCount++;
        bulkOps.push({
          updateOne: {
            filter: { _id: order._id },
            update: {
              $set: {
                status: 'successful',
                completedAt: new Date(),
                processedAt: new Date()
              }
            }
          }
        });
        
        if (!userNotifications.has(order.user.toString())) {
          userNotifications.set(order.user.toString(), { success: 0, failed: 0 });
        }
        userNotifications.get(order.user.toString()).success++;
        
      } else {
        failCount++;
        bulkOps.push({
          updateOne: {
            filter: { _id: order._id },
            update: {
              $set: {
                status: 'failed',
                failureReason: 'Processing failed at MTN gateway',
                processedAt: new Date()
              }
            }
          }
        });
        
        if (!userNotifications.has(order.user.toString())) {
          userNotifications.set(order.user.toString(), { success: 0, failed: 0 });
        }
        userNotifications.get(order.user.toString()).failed++;
        
        // Handle refund for failed orders
        const user = await User.findById(order.user).session(session);
        if (user) {
          const balanceBefore = user.wallet.balance;
          user.wallet.balance += order.amount;
          await user.save({ session });
          
          await WalletTransaction.create([{
            user: order.user,
            type: 'credit',
            amount: order.amount,
            balanceBefore: balanceBefore,
            balanceAfter: user.wallet.balance,
            purpose: 'refund',
            reference: 'REF' + Date.now() + Math.random().toString(36).substr(2, 9),
            status: 'completed',
            description: `Refund for failed data purchase ${order.transactionId}`,
            relatedTransaction: order._id
          }], { session });
        }
      }
    }
    
    if (bulkOps.length > 0) {
      await Transaction.bulkWrite(bulkOps, { session });
    }
    
    await ExportHistory.findOneAndUpdate(
      { exportId },
      {
        $set: {
          'status.current': 'completed',
          'status.successCount': successCount,
          'status.failedCount': failCount,
          'timestamps.completedAt': new Date()
        }
      },
      { session }
    );
    
    await SystemStatus.findOneAndUpdate(
      { _id: 'current_status' },
      {
        $set: {
          'lastExport.status': 'completed',
          'lastExport.completedAt': new Date(),
          'lastExport.successCount': successCount,
          'lastExport.failedCount': failCount,
          'currentProcessing.isProcessing': false,
          'currentProcessing.activeExports': []
        }
      },
      { session }
    );
    
    // Update batch record
    await Batch.findOneAndUpdate(
      { batchId: { $regex: exportId } },
      {
        $set: {
          'stats.processedOrders': successCount,
          'stats.failedOrders': failCount,
          'status': 'completed',
          'processingStatus': 'completed'
        }
      },
      { session }
    );
    
    const notifications = Array.from(userNotifications.entries()).map(([userId, stats]) => ({
      user: userId,
      title: 'Orders Completed',
      message: `${stats.success} orders completed successfully${stats.failed > 0 ? `, ${stats.failed} failed` : ''}`,
      type: stats.success > 0 ? 'success' : 'error',
      category: 'transaction',
      metadata: {
        exportId,
        successCount: stats.success,
        failedCount: stats.failed
      }
    }));
    
    if (notifications.length > 0) {
      await Notification.insertMany(notifications, { session });
    }
    
    await session.commitTransaction();
    transactionCommitted = true;
    
    console.log(`✅ Export ${exportId} completed: ${successCount} success, ${failCount} failed`);
    
  } catch (error) {
    if (!transactionCommitted) {
      try {
        await session.abortTransaction();
      } catch (abortError) {
        console.error('Error aborting transaction in completeExport:', abortError);
      }
    }
    console.error(`Error completing export ${exportId}:`, error);
  } finally {
    session.endSession();
  }
}

// =============================================
// INITIALIZATION
// =============================================

// Initialize system status on server start
const initializeSystemStatus = async () => {
  try {
    await SystemStatus.findOneAndUpdate(
      { _id: 'current_status' },
      { 
        $setOnInsert: {
          systemHealth: { 
            status: 'healthy',
            lastCheckedAt: new Date()
          },
          currentProcessing: { 
            isProcessing: false,
            activeExports: [],
            queuedExports: 0
          },
          statistics: {
            today: {
              totalExports: 0,
              totalOrders: 0,
              successRate: 100,
              lastUpdated: new Date()
            }
          }
        }
      },
      { upsert: true }
    );
    console.log('✅ System status initialized');
  } catch (error) {
    console.error('❌ Error initializing system status:', error);
  }
};

// Initialize default export settings
const initializeDefaultSettings = async () => {
  try {
    const existingSettings = await ExportSettings.findOne({ settingName: 'default' });
    
    if (!existingSettings) {
      const defaultSettings = new ExportSettings({
        settingName: 'default',
        isActive: true,
        createdBy: null, // System created
        timeSettings: {
          phases: {
            initial: {
              duration: 5,
              unit: 'minutes',
              message: 'Orders received and being prepared for processing...'
            },
            processing: {
              duration: 15,
              unit: 'minutes',
              message: 'Orders are being processed by MTN system...'
            },
            finalizing: {
              duration: 10,
              unit: 'minutes',
              message: 'Finalizing your orders. Almost complete...'
            }
          },
          totalProcessingMinutes: 30,
          bufferMinutes: 5
        },
        messages: {
          beforeExport: 'Preparing to export orders to processing system...',
          exportSuccess: 'Your orders have been successfully sent to MTN for processing.',
          stages: {
            queued: {
              title: 'Queued for Processing',
              description: 'Your orders are in the queue and will be processed shortly.',
              icon: 'clock'
            },
            sent: {
              title: 'Sent to MTN',
              description: 'Orders have been transmitted to MTN processing system.',
              icon: 'send'
            },
            processing: {
              title: 'Processing',
              description: 'Your orders are being processed. This usually takes 15-30 minutes.',
              icon: 'loader'
            },
            completed: {
              title: 'Completed',
              description: 'Your orders have been successfully processed and delivered.',
              icon: 'check-circle'
            },
            failed: {
              title: 'Processing Failed',
              description: 'Some orders could not be processed. Please contact support.',
              icon: 'alert-circle'
            }
          }
        },
        autoComplete: {
          enabled: true,
          strategy: 'fixed_time',
          fixedTimeMinutes: 30,
          successRate: 95
        }
      });
      
      await defaultSettings.save();
      console.log('✅ Default export settings created');
    }
  } catch (error) {
    console.error('❌ Error initializing export settings:', error);
  }
};

// Run initializations
initializeSystemStatus();
initializeDefaultSettings();

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

// Get dashboard statistics with system status
router.get('/dashboard/stats', async (req, res) => {
  try {
    const { startDate, endDate } = req.query;
    
    const dateFilter = {};
    if (startDate) dateFilter.$gte = new Date(startDate);
    if (endDate) dateFilter.$lte = new Date(endDate);
    
    // Get system status for last export info
    const systemStatus = await SystemStatus.findById('current_status')
      .populate('lastExport.exportedBy', 'fullName');
    
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
        totalWalletBalance: stats[4][0]?.totalWalletBalance || 0,
        lastExport: systemStatus?.lastExport,
        systemStatus: {
          health: systemStatus?.systemHealth?.status,
          isProcessing: systemStatus?.currentProcessing?.isProcessing,
          activeExports: systemStatus?.currentProcessing?.activeExports?.length || 0
        }
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

// Update order status (now with 'sent' status support)
router.patch('/transactions/:transactionId/status', async (req, res) => {
  try {
    const { transactionId } = req.params;
    const { status, reason } = req.body;
    
    if (!['pending', 'sent', 'successful', 'failed'].includes(status)) {
      return res.status(400).json({
        success: false,
        message: 'Invalid status. Must be pending, sent, successful, or failed'
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
    
    // Handle refunds for failed transactions
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
    
    if (!['pending', 'sent', 'successful', 'failed'].includes(status)) {
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

// Generate API key for a user
router.post('/users/:id/generate-api-key', async (req, res) => {
  try {
    const { id } = req.params;
    const { webhookUrl } = req.body;
    
    const user = await User.findById(id);
    if (!user) {
      return res.status(404).json({
        success: false,
        message: 'User not found'
      });
    }
    
    // Check if user already has API access
    if (user.apiAccess?.enabled) {
      return res.status(400).json({
        success: false,
        message: 'User already has API access enabled'
      });
    }
    
    // Generate API credentials
    const apiKey = 'pk_' + crypto.randomBytes(32).toString('hex');
    const apiSecret = 'sk_' + crypto.randomBytes(32).toString('hex');
    const hashedSecret = await bcrypt.hash(apiSecret, 10);
    
    // Update user with API access
    user.apiAccess = {
      enabled: true,
      apiKey: apiKey,
      apiSecret: hashedSecret,
      webhookUrl: webhookUrl || '',
      rateLimit: 100,
      requestCount: 0,
      lastUsed: null,
      createdAt: new Date()
    };
    
    await user.save();
    
    // Create notification
    await Notification.create({
      user: id,
      title: 'API Access Enabled',
      message: 'Your API credentials have been generated. Please save them securely.',
      type: 'success',
      category: 'system'
    });
    
    res.json({
      success: true,
      message: 'API key generated successfully',
      data: {
        apiKey: apiKey,
        apiSecret: apiSecret, // Return plain secret only once
        webhookUrl: webhookUrl || ''
      }
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: 'Error generating API key',
      error: error.message
    });
  }
});

// Revoke API access for a user
router.delete('/users/:id/revoke-api-access', async (req, res) => {
  try {
    const { id } = req.params;
    
    const user = await User.findById(id);
    if (!user) {
      return res.status(404).json({
        success: false,
        message: 'User not found'
      });
    }
    
    if (!user.apiAccess?.enabled) {
      return res.status(400).json({
        success: false,
        message: 'User does not have API access enabled'
      });
    }
    
    // Disable API access
    user.apiAccess.enabled = false;
    user.apiAccess.apiKey = null;
    user.apiAccess.apiSecret = null;
    user.apiAccess.revokedAt = new Date();
    await user.save();
    
    // Create notification
    await Notification.create({
      user: id,
      title: 'API Access Revoked',
      message: 'Your API access has been revoked by an administrator.',
      type: 'warning',
      category: 'system'
    });
    
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

// Regenerate API key for a user
router.post('/users/:id/regenerate-api-key', async (req, res) => {
  try {
    const { id } = req.params;
    const { webhookUrl } = req.body;
    
    const user = await User.findById(id);
    if (!user) {
      return res.status(404).json({
        success: false,
        message: 'User not found'
      });
    }
    
    if (!user.apiAccess?.enabled) {
      return res.status(400).json({
        success: false,
        message: 'User does not have API access enabled'
      });
    }
    
    // Generate new API credentials
    const apiKey = 'pk_' + crypto.randomBytes(32).toString('hex');
    const apiSecret = 'sk_' + crypto.randomBytes(32).toString('hex');
    const hashedSecret = await bcrypt.hash(apiSecret, 10);
    
    // Update API access with new credentials
    user.apiAccess.apiKey = apiKey;
    user.apiAccess.apiSecret = hashedSecret;
    user.apiAccess.regeneratedAt = new Date();
    if (webhookUrl !== undefined) {
      user.apiAccess.webhookUrl = webhookUrl;
    }
    
    await user.save();
    
    // Create notification
    await Notification.create({
      user: id,
      title: 'API Credentials Regenerated',
      message: 'Your API credentials have been regenerated. Previous credentials are now invalid.',
      type: 'warning',
      category: 'system'
    });
    
    res.json({
      success: true,
      message: 'API key regenerated successfully',
      data: {
        apiKey: apiKey,
        apiSecret: apiSecret, // Return plain secret only once
        webhookUrl: user.apiAccess.webhookUrl || ''
      }
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: 'Error regenerating API key',
      error: error.message
    });
  }
});

// Get API usage statistics for a user
router.get('/users/:id/api-stats', async (req, res) => {
  try {
    const { id } = req.params;
    const { period = '7days' } = req.query;
    
    const user = await User.findById(id).select('apiAccess');
    if (!user) {
      return res.status(404).json({
        success: false,
        message: 'User not found'
      });
    }
    
    if (!user.apiAccess?.enabled) {
      return res.status(400).json({
        success: false,
        message: 'User does not have API access enabled'
      });
    }
    
    let startDate;
    switch (period) {
      case '24hours':
        startDate = new Date(Date.now() - 24 * 60 * 60 * 1000);
        break;
      case '7days':
        startDate = new Date(Date.now() - 7 * 24 * 60 * 60 * 1000);
        break;
      case '30days':
        startDate = new Date(Date.now() - 30 * 24 * 60 * 60 * 1000);
        break;
      default:
        startDate = new Date(Date.now() - 7 * 24 * 60 * 60 * 1000);
    }
    
    const apiLogs = await ApiLog.aggregate([
      {
        $match: {
          user: mongoose.Types.ObjectId(id),
          createdAt: { $gte: startDate }
        }
      },
      {
        $group: {
          _id: {
            $dateToString: { format: '%Y-%m-%d', date: '$createdAt' }
          },
          totalRequests: { $sum: 1 },
          successfulRequests: {
            $sum: { $cond: [{ $eq: ['$success', true] }, 1, 0] }
          },
          failedRequests: {
            $sum: { $cond: [{ $eq: ['$success', false] }, 1, 0] }
          },
          avgResponseTime: { $avg: '$response.responseTime' }
        }
      },
      { $sort: { _id: 1 } }
    ]);
    
    res.json({
      success: true,
      data: {
        apiKey: user.apiAccess.apiKey,
        enabled: user.apiAccess.enabled,
        requestCount: user.apiAccess.requestCount,
        rateLimit: user.apiAccess.rateLimit,
        lastUsed: user.apiAccess.lastUsed,
        createdAt: user.apiAccess.createdAt,
        stats: apiLogs
      }
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: 'Error fetching API statistics',
      error: error.message
    });
  }
});

// =============================================
// 6. EXPORT MANAGEMENT WITH SETTINGS
// =============================================

// Get export settings
router.get('/export-settings', async (req, res) => {
  try {
    const settings = await ExportSettings.find()
      .populate('createdBy', 'fullName')
      .populate('lastModifiedBy', 'fullName')
      .sort({ isActive: -1, createdAt: -1 });
    
    res.json({
      success: true,
      data: settings
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: 'Error fetching export settings',
      error: error.message
    });
  }
});

// Get active export settings
router.get('/export-settings/active', async (req, res) => {
  try {
    const activeSettings = await ExportSettings.findOne({ isActive: true });
    const systemStatus = await SystemStatus.findById('current_status')
      .populate('lastExport.exportedBy', 'fullName');
    
    res.json({
      success: true,
      data: {
        settings: activeSettings,
        systemStatus: systemStatus,
        lastExport: systemStatus?.lastExport,
        currentlyProcessing: systemStatus?.currentProcessing?.isProcessing || false
      }
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: 'Error fetching export settings',
      error: error.message
    });
  }
});

// Create or update export settings
router.post('/export-settings', async (req, res) => {
  try {
    const { settingName = 'default', ...settingsData } = req.body;
    
    // Deactivate other settings if this will be active
    if (settingsData.isActive) {
      await ExportSettings.updateMany(
        { settingName: { $ne: settingName } },
        { isActive: false }
      );
    }
    
    const settings = await ExportSettings.findOneAndUpdate(
      { settingName },
      {
        ...settingsData,
        settingName,
        lastModifiedBy: req.userId,
        createdBy: req.userId
      },
      { new: true, upsert: true }
    );
    
    res.json({
      success: true,
      message: 'Export settings updated successfully',
      data: settings
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: 'Error updating export settings',
      error: error.message
    });
  }
});

// Get export history
router.get('/export-history', async (req, res) => {
  try {
    const { 
      status,
      startDate,
      endDate,
      page = 1, 
      limit = 20 
    } = req.query;
    
    const filter = {};
    if (status) filter['status.current'] = status;
    if (startDate || endDate) {
      filter['timestamps.exportedAt'] = {};
      if (startDate) filter['timestamps.exportedAt'].$gte = new Date(startDate);
      if (endDate) filter['timestamps.exportedAt'].$lte = new Date(endDate);
    }
    
    const history = await ExportHistory.find(filter)
      .sort({ 'timestamps.exportedAt': -1 })
      .limit(limit * 1)
      .skip((page - 1) * limit)
      .populate('exportedBy', 'fullName email')
      .lean();
    
    const total = await ExportHistory.countDocuments(filter);
    
    res.json({
      success: true,
      data: history,
      pagination: {
        total,
        page: parseInt(page),
        pages: Math.ceil(total / limit)
      }
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: 'Error fetching export history',
      error: error.message
    });
  }
});

// Get system status
router.get('/system-status', async (req, res) => {
  try {
    const systemStatus = await SystemStatus.findById('current_status')
      .populate('lastExport.exportedBy', 'fullName');
    
    const activeSettings = await ExportSettings.findOne({ isActive: true });
    
    // Format last export time
    let lastExportDisplay = 'No exports yet';
    if (systemStatus?.lastExport?.exportedAt) {
      const timeDiff = Date.now() - new Date(systemStatus.lastExport.exportedAt);
      const minutes = Math.floor(timeDiff / 60000);
      const hours = Math.floor(minutes / 60);
      const days = Math.floor(hours / 24);
      
      if (days > 0) {
        lastExportDisplay = `${days} day${days > 1 ? 's' : ''} ago`;
      } else if (hours > 0) {
        lastExportDisplay = `${hours} hour${hours > 1 ? 's' : ''} ago`;
      } else if (minutes > 0) {
        lastExportDisplay = `${minutes} minute${minutes > 1 ? 's' : ''} ago`;
      } else {
        lastExportDisplay = 'Just now';
      }
      
      lastExportDisplay += ` - ${systemStatus.lastExport.totalOrders} orders by ${systemStatus.lastExport.exportedBy?.fullName || 'System'}`;
    }
    
    res.json({
      success: true,
      data: {
        systemHealth: systemStatus?.systemHealth,
        lastExport: systemStatus?.lastExport,
        lastExportDisplay,
        currentProcessing: systemStatus?.currentProcessing,
        statistics: systemStatus?.statistics,
        activeSettingsProfile: activeSettings?.settingName,
        userMessage: systemStatus?.userMessage
      }
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: 'Error fetching system status',
      error: error.message
    });
  }
});

// Preview export with impact analysis
router.post('/orders/export/preview', async (req, res) => {
  try {
    const { 
      startDate, 
      endDate, 
      status = 'pending'
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
      .limit(100)
      .populate('dataDetails.product', 'name capacity')
      .populate('user', 'fullName wallet')
      .lean();
    
    // Get active settings to show processing time
    const activeSettings = await ExportSettings.findOne({ isActive: true });
    
    const exportData = orders.map(order => ({
      transactionId: order.transactionId,
      beneficiaryNumber: order.dataDetails?.beneficiaryNumber || 'N/A',
      capacity: order.dataDetails?.capacity || 'N/A',
      currentStatus: order.status,
      userName: order.user?.fullName,
      amount: order.amount,
      date: order.createdAt
    }));
    
    const impactSummary = {
      totalOrdersToExport: exportData.length,
      totalAmount: orders.reduce((sum, o) => sum + o.amount, 0),
      estimatedProcessingTime: activeSettings?.autoComplete?.fixedTimeMinutes || activeSettings?.timeSettings?.totalProcessingMinutes || 30,
      autoCompleteEnabled: activeSettings?.autoComplete?.enabled || false,
      successRate: activeSettings?.autoComplete?.successRate || 95
    };
    
    res.json({
      success: true,
      message: `Found ${exportData.length} orders ready for export`,
      data: exportData,
      count: exportData.length,
      impactSummary
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: 'Error previewing export data',
      error: error.message
    });
  }
});

// MAIN EXPORT ROUTE - FIXED VERSION
// MAIN EXPORT ROUTE - FIXED VERSION (Number and Capacity Only)
router.post('/orders/export/excel', async (req, res) => {
  const session = await mongoose.startSession();
  session.startTransaction();
  
  let transactionCommitted = false;
  
  try {
    const { 
      startDate, 
      endDate, 
      status = 'pending',
      markAsSuccessful = false
    } = req.body;
    
    // Get active export settings
    let exportSettings = await ExportSettings.findOne({ isActive: true });
    
    if (!exportSettings) {
      exportSettings = await ExportSettings.create({
        settingName: 'default',
        isActive: true,
        createdBy: req.userId,
        autoComplete: {
          enabled: true,
          strategy: 'fixed_time',
          fixedTimeMinutes: 30,
          successRate: 95
        }
      });
    }
    
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
    
    // Fetch orders
    const orders = await Transaction.find(filter)
      .sort({ createdAt: -1 })
      .limit(100)
      .populate('dataDetails.product', 'name capacity')
      .populate('user', 'fullName phone wallet')
      .session(session);
    
    if (orders.length === 0) {
      await session.abortTransaction();
      session.endSession();
      return res.status(404).json({
        success: false,
        message: 'No orders found for export'
      });
    }
    
    // Generate export ID and batch ID
    const exportCount = await ExportHistory.countDocuments();
    const exportId = `EXP-${Date.now()}-${String(exportCount + 1).padStart(4, '0')}`;
    const batchId = `BATCH-${exportId}`;
    
    const processingMinutes = exportSettings.autoComplete?.fixedTimeMinutes || 30;
    const estimatedCompletionTime = new Date(Date.now() + processingMinutes * 60000);
    
    // Create export history
    const exportHistory = new ExportHistory({
      exportId,
      batchNumber: exportCount + 1,
      exportDetails: {
        totalOrders: orders.length,
        totalAmount: orders.reduce((sum, o) => sum + o.amount, 0),
        orderIds: orders.map(o => o._id),
        exportMethod: 'manual',
        triggerSource: 'admin_dashboard'
      },
      timestamps: {
        exportedAt: new Date(),
        estimatedCompletionTime: markAsSuccessful ? estimatedCompletionTime : null,
        phases: {
          processing: { 
            startedAt: new Date(),
            estimatedDuration: processingMinutes
          }
        }
      },
      status: {
        current: markAsSuccessful ? 'processing' : 'exported',
        history: [{
          status: markAsSuccessful ? 'processing' : 'exported',
          timestamp: new Date(),
          message: markAsSuccessful ? 'Orders sent to MTN for processing' : 'Orders exported',
          updatedBy: req.userId
        }]
      },
      settingsUsed: {
        settingName: exportSettings.settingName,
        totalProcessingMinutes: processingMinutes,
        autoCompleteEnabled: exportSettings.autoComplete?.enabled || false,
        successRate: exportSettings.autoComplete?.successRate || 95,
        messages: exportSettings.messages
      },
      exportedBy: req.userId
    });
    
    await exportHistory.save({ session });
    
    // Update orders to 'sent' status when markAsSuccessful is true
    if (markAsSuccessful) {
      const bulkOps = orders.map(order => ({
        updateOne: {
          filter: { _id: order._id },
          update: {
            $set: {
              status: 'sent',
              exportedAt: new Date(),
              'metadata.exportId': exportId,
              'metadata.batchId': batchId,
              'metadata.estimatedCompletion': estimatedCompletionTime,
              'metadata.processingMinutes': processingMinutes
            }
          }
        }
      }));
      
      await Transaction.bulkWrite(bulkOps, { session });
    }
    
    // Update system status
    await SystemStatus.findOneAndUpdate(
      { _id: 'current_status' },
      {
        $set: {
          lastExport: {
            exportId,
            exportedAt: new Date(),
            totalOrders: orders.length,
            status: markAsSuccessful ? 'processing' : 'exported',
            exportedBy: req.userId,
            processingMinutes: markAsSuccessful ? processingMinutes : 0,
            completedAt: null
          },
          'currentProcessing.isProcessing': markAsSuccessful,
          'currentProcessing.activeExports': markAsSuccessful ? [{
            exportId,
            startedAt: new Date(),
            estimatedCompletion: estimatedCompletionTime,
            processingMinutes,
            progress: 0,
            orderCount: orders.length
          }] : [],
          'statistics.today.lastUpdated': new Date()
        },
        $inc: {
          'statistics.today.totalExports': 1,
          'statistics.today.totalOrders': orders.length
        }
      },
      { upsert: true, session }
    );
    
    // Create batch record
    await Batch.create([{
      batchId,
      batchNumber: exportCount + 1,
      exportedBy: req.userId,
      exportDate: new Date(),
      processingStatus: markAsSuccessful ? 'sent_to_third_party' : 'exported',
      orders: orders.map(o => ({
        transactionId: o.transactionId,
        beneficiaryNumber: o.dataDetails?.beneficiaryNumber,
        capacity: o.dataDetails?.capacity,
        amount: o.amount,
        status: markAsSuccessful ? 'sent' : o.status,
        userName: o.user?.fullName,
        userId: o.user?._id
      })),
      stats: {
        totalOrders: orders.length,
        processedOrders: 0,
        failedOrders: 0,
        totalAmount: orders.reduce((sum, o) => sum + o.amount, 0)
      }
    }], { session });
    
    // Send notifications
    const userMessages = new Map();
    orders.forEach(order => {
      const userIdStr = order.user._id.toString();
      if (!userMessages.has(userIdStr)) {
        userMessages.set(userIdStr, { userId: order.user._id, orderCount: 0 });
      }
      userMessages.get(userIdStr).orderCount++;
    });
    
    const notifications = Array.from(userMessages.values()).map(msg => ({
      user: msg.userId,
      title: markAsSuccessful ? 'Orders Sent for Processing' : 'Orders Exported',
      message: markAsSuccessful 
        ? `${msg.orderCount} order(s) sent to MTN for processing. Estimated completion in ${processingMinutes} minutes.`
        : `${msg.orderCount} order(s) exported successfully.`,
      type: 'info',
      category: 'transaction'
    }));
    
    await Notification.insertMany(notifications, { session });
    
    // COMMIT TRANSACTION HERE
    await session.commitTransaction();
    transactionCommitted = true;
    session.endSession();
    
    // Schedule auto-completion AFTER transaction is committed
    if (markAsSuccessful && exportSettings.autoComplete?.enabled) {
      try {
        scheduleAutoCompletion(exportId, processingMinutes, exportSettings);
      } catch (scheduleError) {
        console.error('Error scheduling auto-completion:', scheduleError);
      }
    }
    
    // Generate Excel file - SIMPLIFIED VERSION WITH ONLY NUMBER AND CAPACITY
    const workbook = XLSX.utils.book_new();
    
    // Main data sheet - ONLY NUMBER AND CAPACITY
    const orderData = orders.map(o => ({
      'Number': o.dataDetails?.beneficiaryNumber || '',
      'Capacity': o.dataDetails?.capacity || ''
    }));
    
    // Filter out any rows where either Number or Capacity is empty
    const filteredOrderData = orderData.filter(row => 
      row.Number && row.Capacity
    );
    
    const orderSheet = XLSX.utils.json_to_sheet(filteredOrderData);
    
    // Set column widths for better readability
    orderSheet['!cols'] = [
      { wch: 15 }, // Number column
      { wch: 15 }  // Capacity column
    ];
    
    XLSX.utils.book_append_sheet(workbook, orderSheet, 'MTN_Orders');
    
    // Optional: Add a summary sheet with metadata (can be removed if not needed)
    const summaryData = [{
      'Export ID': exportId,
      'Export Date': new Date().toLocaleString(),
      'Total Orders': filteredOrderData.length,
      'Status': markAsSuccessful ? 'Sent to MTN' : 'Export Only'
    }];
    
    const summarySheet = XLSX.utils.json_to_sheet(summaryData);
    XLSX.utils.book_append_sheet(workbook, summarySheet, 'Summary');
    
    // Generate Excel buffer
    const excelBuffer = XLSX.write(workbook, { type: 'buffer', bookType: 'xlsx' });
    
    console.log(`✅ Export ${exportId} completed successfully with ${filteredOrderData.length} valid orders`);
    
    // Set response headers
    res.setHeader('Content-Type', 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet');
    res.setHeader('Content-Disposition', `attachment; filename="MTN_export_${exportId}.xlsx"`);
    res.setHeader('X-Export-ID', exportId); // Add export ID to headers for client reference
    
    res.send(excelBuffer);
    
  } catch (error) {
    // Only abort if not committed
    if (!transactionCommitted) {
      try {
        await session.abortTransaction();
      } catch (abortError) {
        console.error('Error aborting transaction:', abortError);
      }
    }
    
    try {
      session.endSession();
    } catch (sessionError) {
      console.error('Error ending session:', sessionError);
    }
    
    console.error('Export error:', error);
    res.status(500).json({
      success: false,
      message: 'Error exporting orders',
      error: error.message
    });
  }
});

// Check export status
router.get('/export-status/:exportId', async (req, res) => {
  try {
    const { exportId } = req.params;
    
    const exportHistory = await ExportHistory.findOne({ exportId })
      .populate('exportedBy', 'fullName');
    
    if (!exportHistory) {
      return res.status(404).json({
        success: false,
        message: 'Export not found'
      });
    }
    
    // Calculate progress
    const elapsed = Date.now() - exportHistory.timestamps.exportedAt;
    const elapsedMinutes = Math.floor(elapsed / 60000);
    const totalMinutes = exportHistory.settingsUsed.totalProcessingMinutes;
    const progress = Math.min(100, Math.round((elapsedMinutes / totalMinutes) * 100));
    
    res.json({
      success: true,
      data: {
        exportId: exportHistory.exportId,
        status: exportHistory.status.current,
        progress,
        elapsedMinutes,
        estimatedRemainingMinutes: Math.max(0, totalMinutes - elapsedMinutes),
        statistics: {
          totalOrders: exportHistory.exportDetails.totalOrders,
          successCount: exportHistory.status.successCount || 0,
          failedCount: exportHistory.status.failedCount || 0
        },
        timestamps: exportHistory.timestamps,
        exportedBy: exportHistory.exportedBy?.fullName
      }
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: 'Error fetching export status',
      error: error.message
    });
  }
});

// =============================================
// 7. WALLET MANAGEMENT APIs (continued...)
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
// 8. SYSTEM SETTINGS APIs (continued...)
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
    
    // Update system status
    await SystemStatus.findOneAndUpdate(
      { _id: 'current_status' },
      { 
        'maintenanceMode.enabled': enabled,
        'maintenanceMode.message': message,
        'maintenanceMode.startedAt': enabled ? new Date() : null
      }
    );
    
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
// 9. REPORTS APIs (continued...)
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
// 10. BATCH MANAGEMENT (continued...)
// =============================================

// Get all batches
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
    if (status) filter.processingStatus = status;
    if (startDate || endDate) {
      filter.exportDate = {};
      if (startDate) filter.exportDate.$gte = new Date(startDate);
      if (endDate) filter.exportDate.$lte = new Date(endDate);
    }
    if (search) {
      filter.$or = [
        { batchId: { $regex: search, $options: 'i' } },
        { 'orders.beneficiaryNumber': { $regex: search, $options: 'i' } }
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
// 11. NOTIFICATIONS
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

// =============================================
// CRON JOB FOR PERIODIC CHECKS
// =============================================

cron.schedule('* * * * *', async () => {  // Runs every minute
  try {
    const pendingExports = await ExportHistory.find({
      'status.current': { $in: ['exporting', 'processing'] },
      'timestamps.estimatedCompletionTime': { $lte: new Date() }
    });
    
    for (const exportData of pendingExports) {
      // Check if it's not already being processed
      if (!scheduledJobs.has(exportData.exportId)) {
        const settings = await ExportSettings.findOne({ 
          settingName: exportData.settingsUsed?.settingName || 'default'
        });
        
        if (settings && settings.autoComplete?.enabled) {
          console.log(`⚠️ Found overdue export ${exportData.exportId}, completing now`);
          await completeExport(exportData.exportId, settings);
        }
      }
    }
  } catch (error) {
    console.error('Cron job error:', error);
  }
});

// =============================================
// EXPORT ROUTER
// =============================================

module.exports = router;