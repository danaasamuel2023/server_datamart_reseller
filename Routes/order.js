// =============================================
// ORDER & PRODUCT ROUTES - GHANA MTN DATA PLATFORM
// Updated with Portal ID display support
// =============================================

const express = require('express');
const router = express.Router();
const mongoose = require('mongoose');
const crypto = require('crypto');

// Import models
const {
  User,
  Product,
  Transaction,
  PriceSetting,
  WalletTransaction,
  Notification
} = require('../schema/schema');

// Import middleware
const {
  auth,
  validate,
  wallet,
  security,
  rateLimit
} = require('../middleware/middleware');

// =============================================
// UTILITY FUNCTIONS FOR 6-DIGIT REFERENCES
// =============================================

// Generate 6-digit reference number
const generate6DigitReference = () => {
  return Math.floor(100000 + Math.random() * 900000).toString();
};

// Generate unique 6-digit reference with optional prefix
const generateUniqueReference = async (prefix = '') => {
  let reference;
  let isUnique = false;
  let attempts = 0;
  const maxAttempts = 10;
  
  while (!isUnique && attempts < maxAttempts) {
    const sixDigits = generate6DigitReference();
    reference = prefix + sixDigits;
    
    // Check if reference already exists
    const existing = await Transaction.findOne({ 
      $or: [
        { transactionId: reference },
        { reference: reference }
      ]
    });
    
    if (!existing) {
      isUnique = true;
    }
    attempts++;
  }
  
  if (!isUnique) {
    // Fallback: use last 6 digits of timestamp
    reference = prefix + Date.now().toString().slice(-6);
  }
  
  return reference;
};

// Updated middleware for generating 6-digit references
const generateReferenceMiddleware = async (req, res, next) => {
  try {
    req.transactionRef = await generateUniqueReference('');
    next();
  } catch (error) {
    return res.status(500).json({
      success: false,
      message: 'Error generating reference',
      error: error.message
    });
  }
};

// =============================================
// 1. PRODUCT DISPLAY ROUTES (WITH ROLE-BASED PRICING)
// =============================================

// Get all available products with prices based on user role
router.get('/products', auth.optionalAuth, async (req, res) => {
  try {
    const { category, search, sortBy = 'popular' } = req.query;
    const userRole = req.user?.role || 'guest';
    
    // Build filter
    const filter = { status: 'active' };
    if (category) filter.category = category;
    if (search) {
      filter.$or = [
        { name: { $regex: search, $options: 'i' } },
        { productCode: { $regex: search, $options: 'i' } }
      ];
    }
    
    // Get products
    const products = await Product.find(filter).lean();
    
    // Get pricing for each product based on user role
    const productsWithPricing = await Promise.all(
      products.map(async (product) => {
        // Get active pricing
        const pricing = await PriceSetting.findOne({
          product: product._id,
          isActive: true
        });
        
        // Determine price based on role
        let price = 0;
        let discount = 0;
        
        if (pricing) {
          switch (userRole) {
            case 'supplier':
              price = pricing.supplierPrice;
              discount = ((pricing.agentPrice - pricing.supplierPrice) / pricing.agentPrice * 100).toFixed(0);
              break;
            case 'dealer':
              price = pricing.dealerPrice;
              discount = ((pricing.agentPrice - pricing.dealerPrice) / pricing.agentPrice * 100).toFixed(0);
              break;
            case 'agent':
              price = pricing.agentPrice;
              discount = 0;
              break;
            default:
              // Guest sees agent price or hide product
              price = pricing.agentPrice;
              discount = 0;
          }
        }
        
        return {
          _id: product._id,
          name: product.name,
          productCode: product.productCode,
          category: product.category,
          capacity: product.capacity,
          validity: product.validity,
          description: product.description,
          features: product.features,
          price: price,
          originalPrice: pricing?.agentPrice || price,
          discount: discount,
          available: product.status === 'active',
          displayPrice: `GHS ${price.toFixed(2)}`,
          savings: pricing ? (pricing.agentPrice - price).toFixed(2) : 0
        };
      })
    );
    
    // Sort products
    let sortedProducts = [...productsWithPricing];
    switch (sortBy) {
      case 'price_low':
        sortedProducts.sort((a, b) => a.price - b.price);
        break;
      case 'price_high':
        sortedProducts.sort((a, b) => b.price - a.price);
        break;
      case 'popular':
        // Sort by most purchased (would need stats tracking)
        sortedProducts.sort((a, b) => (b.stats?.totalSold || 0) - (a.stats?.totalSold || 0));
        break;
      case 'capacity':
        sortedProducts.sort((a, b) => {
          const aValue = a.capacity.unit === 'GB' ? a.capacity.value * 1024 : a.capacity.value;
          const bValue = b.capacity.unit === 'GB' ? b.capacity.value * 1024 : b.capacity.value;
          return bValue - aValue;
        });
        break;
    }
    
    // Group by categories if requested
    const groupedProducts = {};
    if (req.query.grouped === 'true') {
      sortedProducts.forEach(product => {
        if (!groupedProducts[product.category]) {
          groupedProducts[product.category] = [];
        }
        groupedProducts[product.category].push(product);
      });
      
      res.json({
        success: true,
        role: userRole,
        data: groupedProducts,
        total: sortedProducts.length
      });
    } else {
      res.json({
        success: true,
        role: userRole,
        data: sortedProducts,
        total: sortedProducts.length
      });
    }
  } catch (error) {
    res.status(500).json({
      success: false,
      message: 'Error fetching products',
      error: error.message
    });
  }
});

// Get single product details with pricing
router.get('/products/:productId', auth.optionalAuth, async (req, res) => {
  try {
    const { productId } = req.params;
    const userRole = req.user?.role || 'guest';
    
    const product = await Product.findById(productId).lean();
    
    if (!product) {
      return res.status(404).json({
        success: false,
        message: 'Product not found'
      });
    }
    
    // Get pricing
    const pricing = await PriceSetting.findOne({
      product: product._id,
      isActive: true
    });
    
    // Calculate role-based price
    let priceDetails = {
      agent: pricing?.agentPrice || 0,
      dealer: pricing?.dealerPrice || 0,
      supplier: pricing?.supplierPrice || 0
    };
    
    let userPrice = priceDetails[userRole] || priceDetails.agent;
    
    res.json({
      success: true,
      data: {
        ...product,
        pricing: userRole === 'admin' ? priceDetails : undefined, // Only admin sees all prices
        userPrice: userPrice,
        displayPrice: `GHS ${userPrice.toFixed(2)}`,
        role: userRole
      }
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: 'Error fetching product',
      error: error.message
    });
  }
});

// Get price calculator (for checking prices before order)
router.post('/products/calculate-price', auth.verifyToken, async (req, res) => {
  try {
    const { items } = req.body; // Array of { productId, quantity }
    const userRole = req.user.role;
    
    let totalAmount = 0;
    const calculatedItems = [];
    
    for (const item of items) {
      const product = await Product.findById(item.productId);
      if (!product) {
        return res.status(400).json({
          success: false,
          message: `Product ${item.productId} not found`
        });
      }
      
      const pricing = await PriceSetting.findOne({
        product: item.productId,
        isActive: true
      });
      
      if (!pricing) {
        return res.status(400).json({
          success: false,
          message: `Pricing not set for ${product.name}`
        });
      }
      
      let unitPrice;
      switch (userRole) {
        case 'supplier':
          unitPrice = pricing.supplierPrice;
          break;
        case 'dealer':
          unitPrice = pricing.dealerPrice;
          break;
        case 'agent':
          unitPrice = pricing.agentPrice;
          break;
        default:
          unitPrice = pricing.agentPrice;
      }
      
      const lineTotal = unitPrice * (item.quantity || 1);
      totalAmount += lineTotal;
      
      calculatedItems.push({
        productId: item.productId,
        productName: product.name,
        quantity: item.quantity || 1,
        unitPrice: unitPrice,
        lineTotal: lineTotal
      });
    }
    
    res.json({
      success: true,
      data: {
        items: calculatedItems,
        totalAmount: totalAmount,
        walletBalance: req.user.wallet.balance,
        sufficientBalance: req.user.wallet.balance >= totalAmount
      }
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: 'Error calculating price',
      error: error.message
    });
  }
});

// =============================================
// 2. SINGLE ORDER PLACEMENT (WITH 6-DIGIT REFERENCE)
// =============================================

// Single Order with Portal ID support
router.post('/orders/single',
  auth.verifyToken,
  rateLimit.transaction,
  validate.validateDataPurchase,
  validate.handleValidationErrors,
  wallet.lockWallet,
  generateReferenceMiddleware,
  async (req, res) => {
    let session;
    
    try {
      // Start MongoDB session
      session = await mongoose.startSession();
      session.startTransaction();
      
      const { productId, beneficiaryNumber } = req.body;
      const userId = req.userId;
      const reference = req.transactionRef; // 6 digits
      
      // Step 1: Get product
      const product = await Product.findById(productId);
      
      if (!product) {
        await session.abortTransaction();
        return res.status(400).json({
          success: false,
          message: 'Product not found',
          productId: productId
        });
      }
      
      if (product.status !== 'active') {
        await session.abortTransaction();
        return res.status(400).json({
          success: false,
          message: 'Product not available',
          status: product.status
        });
      }
      
      // Step 2: Get pricing
      const pricing = await PriceSetting.findOne({
        product: productId,
        isActive: true
      });
      
      if (!pricing) {
        await session.abortTransaction();
        return res.status(400).json({
          success: false,
          message: 'Product pricing not available. Please contact admin to set pricing.',
          productId: productId
        });
      }
      
      // Step 3: Calculate price based on role
      const userRole = req.user.role || 'agent';
      
      let amount;
      switch (userRole) {
        case 'supplier':
          amount = pricing.supplierPrice;
          break;
        case 'dealer':
          amount = pricing.dealerPrice;
          break;
        case 'agent':
          amount = pricing.agentPrice;
          break;
        default:
          amount = pricing.agentPrice;
      }
      
      // Step 4: Check wallet balance
      const user = await User.findById(userId).session(session);
      
      if (!user) {
        await session.abortTransaction();
        return res.status(404).json({
          success: false,
          message: 'User not found'
        });
      }
      
      if (user.wallet.balance < amount) {
        await session.abortTransaction();
        return res.status(400).json({
          success: false,
          message: 'Insufficient wallet balance',
          required: amount,
          available: user.wallet.balance
        });
      }
      
      // Step 5: Deduct from wallet
      const balanceBefore = user.wallet.balance;
      user.wallet.balance -= amount;
      await user.save({ session });
      
      // Step 6: Create transaction record with metadata for portal tracking
      const transaction = new Transaction({
        transactionId: reference,
        user: userId,
        type: 'data_purchase',
        dataDetails: {
          product: productId,
          beneficiaryNumber: beneficiaryNumber,
          capacity: `${product.capacity.value}${product.capacity.unit}`,
          network: 'MTN'
        },
        amount: amount,
        balanceBefore: balanceBefore,
        balanceAfter: user.wallet.balance,
        status: 'pending',
        reference: reference,
        paymentMethod: 'wallet',
        // Initialize metadata for portal tracking
        metadata: {
          exportReady: true,
          portalStatus: 'pending'
        }
      });
      
      await transaction.save({ session });
      
      // Step 7: Create wallet transaction
      await WalletTransaction.create([{
        user: userId,
        type: 'debit',
        amount: amount,
        balanceBefore: balanceBefore,
        balanceAfter: user.wallet.balance,
        purpose: 'purchase',
        reference: reference,
        status: 'completed',
        description: `Purchase of ${product.name} for ${beneficiaryNumber}`,
        relatedTransaction: transaction._id
      }], { session });
      
      // Step 8: Update product stats
      if (product.stats) {
        product.stats.totalSold = (product.stats.totalSold || 0) + 1;
        product.stats.totalRevenue = (product.stats.totalRevenue || 0) + amount;
        await product.save({ session });
      }
      
      // Step 9: Commit transaction
      await session.commitTransaction();
      
      // Step 10: Send notification
      try {
        await Notification.create({
          user: userId,
          title: 'Data Purchase Initiated',
          message: `Your purchase of ${product.name} for ${beneficiaryNumber} is being processed`,
          type: 'info',
          category: 'transaction',
          relatedTransaction: transaction._id
        });
      } catch (notifError) {
        console.error('Notification error (non-critical):', notifError.message);
      }
      
      // Send success response
      res.json({
        success: true,
        message: 'Order placed successfully',
        data: {
          transactionId: reference,
          product: product.name,
          beneficiary: beneficiaryNumber,
          amount: amount,
          status: 'pending',
          balance: user.wallet.balance,
          metadata: {
            portalId: null, // Will be updated when exported to portal
            portalStatus: 'pending'
          }
        }
      });
      
    } catch (error) {
      if (session) {
        await session.abortTransaction();
      }
      
      res.status(500).json({
        success: false,
        message: 'Error processing order',
        error: process.env.NODE_ENV !== 'production' ? error.message : undefined
      });
    } finally {
      if (session) {
        session.endSession();
      }
    }
  }
);

// =============================================
// 3. BULK ORDER PLACEMENT (WITH 6-DIGIT REFERENCES AND PORTAL SUPPORT)
// =============================================

router.post('/orders/bulk',
  auth.verifyToken,
  rateLimit.transaction,
  wallet.lockWallet,
  async (req, res) => {
    const session = await mongoose.startSession();
    session.startTransaction();
    
    try {
      const { orders } = req.body;
      const userId = req.userId;
      
      if (!orders || !Array.isArray(orders) || orders.length === 0) {
        await session.abortTransaction();
        return res.status(400).json({
          success: false,
          message: 'Invalid bulk order format'
        });
      }
      
      if (orders.length > 100) {
        await session.abortTransaction();
        return res.status(400).json({
          success: false,
          message: 'Maximum 100 orders per bulk request'
        });
      }
      
      // Validate all beneficiary numbers
      for (const order of orders) {
        if (!order.beneficiaryNumber?.match(/^(\+233|0)[235][0-9]{8}$/)) {
          await session.abortTransaction();
          return res.status(400).json({
            success: false,
            message: `Invalid beneficiary number: ${order.beneficiaryNumber}`
          });
        }
      }
      
      const user = await User.findById(userId).session(session);
      let totalAmount = 0;
      const orderDetails = [];
      
      // Calculate total amount and validate products
      for (const order of orders) {
        const product = await Product.findById(order.productId);
        if (!product || product.status !== 'active') {
          await session.abortTransaction();
          return res.status(400).json({
            success: false,
            message: `Product not available: ${order.productId}`
          });
        }
        
        const pricing = await PriceSetting.findOne({
          product: order.productId,
          isActive: true
        });
        
        if (!pricing) {
          await session.abortTransaction();
          return res.status(400).json({
            success: false,
            message: `Pricing not available for: ${product.name}`
          });
        }
        
        // Get price based on role
        let unitPrice;
        switch (req.user.role) {
          case 'supplier':
            unitPrice = pricing.supplierPrice;
            break;
          case 'dealer':
            unitPrice = pricing.dealerPrice;
            break;
          case 'agent':
            unitPrice = pricing.agentPrice;
            break;
          default:
            unitPrice = pricing.agentPrice;
        }
        
        const quantity = order.quantity || 1;
        const lineTotal = unitPrice * quantity;
        totalAmount += lineTotal;
        
        orderDetails.push({
          product: product,
          pricing: unitPrice,
          quantity: quantity,
          beneficiaryNumber: order.beneficiaryNumber,
          amount: lineTotal
        });
      }
      
      // Check wallet balance
      if (user.wallet.balance < totalAmount) {
        await session.abortTransaction();
        return res.status(400).json({
          success: false,
          message: 'Insufficient wallet balance',
          required: totalAmount,
          available: user.wallet.balance
        });
      }
      
      // Process bulk order
      const balanceBefore = user.wallet.balance;
      user.wallet.balance -= totalAmount;
      await user.save({ session });
      
      // Generate 6-digit bulk reference with BLK prefix
      const bulkReference = 'BLK' + generate6DigitReference();
      const processedOrders = [];
      const failedOrders = [];
      
      // Process each order
      for (const orderDetail of orderDetails) {
        const orderRef = await generateUniqueReference('');
        
        try {
          // Create transaction with metadata for portal tracking
          const transaction = new Transaction({
            transactionId: orderRef,
            user: userId,
            type: 'data_purchase',
            dataDetails: {
              product: orderDetail.product._id,
              beneficiaryNumber: orderDetail.beneficiaryNumber,
              capacity: `${orderDetail.product.capacity.value}${orderDetail.product.capacity.unit}`,
              network: 'MTN',
              quantity: orderDetail.quantity
            },
            amount: orderDetail.amount,
            status: 'pending',
            reference: orderRef,
            paymentMethod: 'wallet',
            metadata: {
              bulkReference: bulkReference,
              exportReady: true,
              portalStatus: 'pending'
            }
          });
          
          await transaction.save({ session });
          
          // Update product stats
          if (orderDetail.product.stats) {
            orderDetail.product.stats.totalSold = (orderDetail.product.stats.totalSold || 0) + orderDetail.quantity;
            orderDetail.product.stats.totalRevenue = (orderDetail.product.stats.totalRevenue || 0) + orderDetail.amount;
            await orderDetail.product.save({ session });
          }
          
          processedOrders.push({
            transactionId: orderRef,
            product: orderDetail.product.name,
            beneficiary: orderDetail.beneficiaryNumber,
            quantity: orderDetail.quantity,
            amount: orderDetail.amount,
            status: 'pending',
            metadata: {
              portalId: null,
              portalStatus: 'pending'
            }
          });
        } catch (error) {
          failedOrders.push({
            product: orderDetail.product.name,
            beneficiary: orderDetail.beneficiaryNumber,
            error: error.message
          });
        }
      }
      
      // Create bulk wallet transaction
      await WalletTransaction.create([{
        user: userId,
        type: 'debit',
        amount: totalAmount,
        balanceBefore: balanceBefore,
        balanceAfter: user.wallet.balance,
        purpose: 'purchase',
        reference: bulkReference,
        status: 'completed',
        description: `Bulk purchase of ${orders.length} items`,
        metadata: {
          transactionIds: processedOrders.map(o => o.transactionId),
          count: processedOrders.length,
          bulkReference: bulkReference
        }
      }], { session });
      
      await session.commitTransaction();
      
      // Send notification
      await Notification.create({
        user: userId,
        title: 'Bulk Order Processed',
        message: `Your bulk order of ${processedOrders.length} items has been initiated`,
        type: 'info',
        category: 'transaction',
        metadata: {
          bulkReference: bulkReference
        }
      });
      
      res.json({
        success: true,
        message: 'Bulk order processed',
        data: {
          bulkReference: bulkReference,
          totalAmount: totalAmount,
          processedCount: processedOrders.length,
          failedCount: failedOrders.length,
          processedOrders: processedOrders,
          failedOrders: failedOrders,
          newBalance: user.wallet.balance
        }
      });
    } catch (error) {
      await session.abortTransaction();
      res.status(500).json({
        success: false,
        message: 'Error processing bulk order',
        error: error.message
      });
    } finally {
      session.endSession();
    }
  }
);

// =============================================
// 4. ORDER HISTORY & TRACKING WITH PORTAL ID
// =============================================

// Get user's order history - UPDATED WITH PORTAL ID
router.get('/orders',
  auth.verifyToken,
  async (req, res) => {
    try {
      const userId = req.userId;
      const { 
        status, 
        startDate, 
        endDate, 
        page = 1, 
        limit = 20,
        search
      } = req.query;
      
      const filter = { 
        user: userId,
        type: 'data_purchase'
      };
      
      if (status) filter.status = status;
      
      if (startDate || endDate) {
        filter.createdAt = {};
        if (startDate) filter.createdAt.$gte = new Date(startDate);
        if (endDate) filter.createdAt.$lte = new Date(endDate);
      }
      
      // UPDATED: Include metadata.portalId in search
      if (search) {
        filter.$or = [
          { transactionId: { $regex: search, $options: 'i' } },
          { reference: { $regex: search, $options: 'i' } },
          { 'dataDetails.beneficiaryNumber': { $regex: search, $options: 'i' } },
          { 'metadata.portalId': { $regex: search, $options: 'i' } }
        ];
      }
      
      const orders = await Transaction.find(filter)
        .sort({ createdAt: -1 })
        .limit(limit * 1)
        .skip((page - 1) * limit)
        .populate('dataDetails.product', 'name productCode capacity')
        .lean();
      
      const total = await Transaction.countDocuments(filter);
      
      // UPDATED: Include full metadata in response
      const formattedOrders = orders.map(order => ({
        id: order._id,
        transactionId: order.transactionId,
        createdAt: order.createdAt,
        date: order.createdAt,
        product: order.dataDetails?.product?.name,
        capacity: order.dataDetails?.capacity,
        beneficiary: order.dataDetails?.beneficiaryNumber,
        amount: order.amount,
        status: order.status,
        reference: order.reference,
        completedAt: order.completedAt,
        // Include metadata with portal information
        metadata: {
          portalId: order.metadata?.portalId,
          exportId: order.metadata?.exportId,
          batchId: order.metadata?.batchId,
          portalStatus: order.metadata?.portalStatus,
          portalSubmittedAt: order.metadata?.portalSubmittedAt,
          portalCompletedAt: order.metadata?.portalCompletedAt,
          estimatedCompletion: order.metadata?.estimatedCompletion,
          processingMinutes: order.metadata?.processingMinutes,
          bulkReference: order.metadata?.bulkReference
        }
      }));
      
      res.json({
        success: true,
        data: formattedOrders,
        pagination: {
          total,
          page: parseInt(page),
          pages: Math.ceil(total / limit)
        }
      });
    } catch (error) {
      res.status(500).json({
        success: false,
        message: 'Error fetching orders',
        error: error.message
      });
    }
  }
);

// Get single order details - UPDATED WITH PORTAL ID
router.get('/orders/:orderId',
  auth.verifyToken,
  async (req, res) => {
    try {
      const { orderId } = req.params;
      const userId = req.userId;
      
      const order = await Transaction.findOne({
        $or: [
          { _id: orderId },
          { transactionId: orderId },
          { reference: orderId }
        ],
        user: userId
      })
        .populate('dataDetails.product')
        .lean();
      
      if (!order) {
        return res.status(404).json({
          success: false,
          message: 'Order not found'
        });
      }
      
      // Format the order with full metadata
      const formattedOrder = {
        ...order,
        metadata: {
          portalId: order.metadata?.portalId,
          exportId: order.metadata?.exportId,
          batchId: order.metadata?.batchId,
          portalStatus: order.metadata?.portalStatus,
          portalSubmittedAt: order.metadata?.portalSubmittedAt,
          portalCompletedAt: order.metadata?.portalCompletedAt,
          estimatedCompletion: order.metadata?.estimatedCompletion,
          processingMinutes: order.metadata?.processingMinutes,
          bulkReference: order.metadata?.bulkReference
        }
      };
      
      res.json({
        success: true,
        data: formattedOrder
      });
    } catch (error) {
      res.status(500).json({
        success: false,
        message: 'Error fetching order',
        error: error.message
      });
    }
  }
);

// Track order status - UPDATED WITH PORTAL TRACKING
router.get('/orders/:orderId/track',
  auth.verifyToken,
  async (req, res) => {
    try {
      const { orderId } = req.params;
      const userId = req.userId;
      
      const order = await Transaction.findOne({
        $or: [
          { _id: orderId },
          { transactionId: orderId },
          { reference: orderId }
        ],
        user: userId
      }).lean();
      
      if (!order) {
        return res.status(404).json({
          success: false,
          message: 'Order not found'
        });
      }
      
      // Create enhanced tracking timeline with portal status
      const timeline = [
        {
          status: 'initiated',
          message: 'Order placed',
          timestamp: order.createdAt,
          completed: true
        },
        {
          status: 'processing',
          message: 'Processing payment',
          timestamp: order.createdAt,
          completed: true
        }
      ];
      
      // Add portal submission step if applicable
      if (order.metadata?.portalId) {
        timeline.push({
          status: 'portal_submitted',
          message: `Submitted to MTN Portal (ID: ${order.metadata.portalId})`,
          timestamp: order.metadata.portalSubmittedAt || order.exportedAt,
          completed: true
        });
      }
      
      // Add sending step
      timeline.push({
        status: 'sending',
        message: 'Sending data to beneficiary',
        timestamp: order.processedAt || order.createdAt,
        completed: order.status !== 'pending'
      });
      
      // Add completion step
      timeline.push({
        status: 'completed',
        message: 'Data delivered successfully',
        timestamp: order.completedAt,
        completed: order.status === 'successful'
      });
      
      res.json({
        success: true,
        data: {
          orderId: order.transactionId,
          currentStatus: order.status,
          beneficiary: order.dataDetails?.beneficiaryNumber,
          amount: order.amount,
          portalId: order.metadata?.portalId,
          portalStatus: order.metadata?.portalStatus,
          timeline: timeline
        }
      });
    } catch (error) {
      res.status(500).json({
        success: false,
        message: 'Error tracking order',
        error: error.message
      });
    }
  }
);

// =============================================
// 5. ORDER STATISTICS
// =============================================

// Get user's order statistics
router.get('/orders/stats/summary',
  auth.verifyToken,
  async (req, res) => {
    try {
      const userId = req.userId;
      const { period = '30days' } = req.query;
      
      let startDate;
      switch (period) {
        case '7days':
          startDate = new Date(Date.now() - 7 * 24 * 60 * 60 * 1000);
          break;
        case '30days':
          startDate = new Date(Date.now() - 30 * 24 * 60 * 60 * 1000);
          break;
        case 'all':
          startDate = new Date(0);
          break;
        default:
          startDate = new Date(Date.now() - 30 * 24 * 60 * 60 * 1000);
      }
      
      const stats = await Transaction.aggregate([
        {
          $match: {
            user: new mongoose.Types.ObjectId(userId),
            type: 'data_purchase',
            createdAt: { $gte: startDate }
          }
        },
        {
          $group: {
            _id: null,
            totalOrders: { $sum: 1 },
            totalSpent: { $sum: '$amount' },
            successfulOrders: {
              $sum: { $cond: [{ $eq: ['$status', 'successful'] }, 1, 0] }
            },
            failedOrders: {
              $sum: { $cond: [{ $eq: ['$status', 'failed'] }, 1, 0] }
            },
            pendingOrders: {
              $sum: { $cond: [{ $eq: ['$status', 'pending'] }, 1, 0] }
            },
            sentOrders: {
              $sum: { $cond: [{ $eq: ['$status', 'sent'] }, 1, 0] }
            },
            // Count orders with portal IDs
            portalSubmitted: {
              $sum: {
                $cond: [{ $ne: ['$metadata.portalId', null] }, 1, 0]
              }
            }
          }
        }
      ]);
      
      // Get most purchased products
      const topProducts = await Transaction.aggregate([
        {
          $match: {
            user: new mongoose.Types.ObjectId(userId),
            type: 'data_purchase',
            status: 'successful',
            createdAt: { $gte: startDate }
          }
        },
        {
          $group: {
            _id: '$dataDetails.product',
            count: { $sum: 1 },
            totalSpent: { $sum: '$amount' }
          }
        },
        { $sort: { count: -1 } },
        { $limit: 5 },
        {
          $lookup: {
            from: 'product_resellers',
            localField: '_id',
            foreignField: '_id',
            as: 'product'
          }
        },
        { $unwind: '$product' }
      ]);
      
      // Get frequent beneficiaries
      const frequentBeneficiaries = await Transaction.aggregate([
        {
          $match: {
            user: new mongoose.Types.ObjectId(userId),
            type: 'data_purchase',
            status: 'successful',
            createdAt: { $gte: startDate }
          }
        },
        {
          $group: {
            _id: '$dataDetails.beneficiaryNumber',
            count: { $sum: 1 },
            totalAmount: { $sum: '$amount' }
          }
        },
        { $sort: { count: -1 } },
        { $limit: 5 }
      ]);
      
      res.json({
        success: true,
        data: {
          summary: stats[0] || {
            totalOrders: 0,
            totalSpent: 0,
            successfulOrders: 0,
            failedOrders: 0,
            pendingOrders: 0,
            sentOrders: 0,
            portalSubmitted: 0
          },
          topProducts: topProducts.map(p => ({
            name: p.product.name,
            count: p.count,
            totalSpent: p.totalSpent
          })),
          frequentBeneficiaries: frequentBeneficiaries,
          period: period
        }
      });
    } catch (error) {
      res.status(500).json({
        success: false,
        message: 'Error fetching statistics',
        error: error.message
      });
    }
  }
);

// =============================================
// 6. QUICK REORDER
// =============================================

// Reorder from previous order
router.post('/orders/:orderId/reorder',
  auth.verifyToken,
  rateLimit.transaction,
  wallet.lockWallet,
  async (req, res) => {
    try {
      const { orderId } = req.params;
      const { beneficiaryNumber } = req.body;
      const userId = req.userId;
      
      // Find original order
      const originalOrder = await Transaction.findOne({
        $or: [
          { _id: orderId },
          { transactionId: orderId }
        ],
        user: userId
      });
      
      if (!originalOrder) {
        return res.status(404).json({
          success: false,
          message: 'Original order not found'
        });
      }
      
      // Create new order with same product
      req.body = {
        productId: originalOrder.dataDetails.product,
        beneficiaryNumber: beneficiaryNumber || originalOrder.dataDetails.beneficiaryNumber
      };
      
      // Generate new 6-digit reference for reorder
      req.transactionRef = await generateUniqueReference('');
      
      // Forward to single order handler
      next();
    } catch (error) {
      res.status(500).json({
        success: false,
        message: 'Error processing reorder',
        error: error.message
      });
    }
  }
);

// Get favorite/saved beneficiaries
router.get('/beneficiaries/frequent',
  auth.verifyToken,
  async (req, res) => {
    try {
      const userId = req.userId;
      const { limit = 10 } = req.query;
      
      const beneficiaries = await Transaction.aggregate([
        {
          $match: {
            user: new mongoose.Types.ObjectId(userId),
            type: 'data_purchase',
            status: 'successful'
          }
        },
        {
          $group: {
            _id: '$dataDetails.beneficiaryNumber',
            count: { $sum: 1 },
            lastUsed: { $max: '$createdAt' },
            totalAmount: { $sum: '$amount' }
          }
        },
        { $sort: { count: -1 } },
        { $limit: parseInt(limit) }
      ]);
      
      res.json({
        success: true,
        data: beneficiaries.map(b => ({
          number: b._id,
          usageCount: b.count,
          lastUsed: b.lastUsed,
          totalSpent: b.totalAmount
        }))
      });
    } catch (error) {
      res.status(500).json({
        success: false,
        message: 'Error fetching beneficiaries',
        error: error.message
      });
    }
  }
);

// =============================================
// 7. DOWNLOAD RECEIPTS WITH PORTAL INFO
// =============================================

// Get order receipt
router.get('/orders/:orderId/receipt',
  auth.verifyToken,
  async (req, res) => {
    try {
      const { orderId } = req.params;
      const userId = req.userId;
      
      const order = await Transaction.findOne({
        $or: [
          { _id: orderId },
          { transactionId: orderId }
        ],
        user: userId
      })
        .populate('user', 'fullName email phone')
        .populate('dataDetails.product', 'name capacity')
        .lean();
      
      if (!order) {
        return res.status(404).json({
          success: false,
          message: 'Order not found'
        });
      }
      
      const receipt = {
        receiptNumber: order.transactionId,
        date: order.createdAt,
        customer: {
          name: order.user.fullName,
          email: order.user.email,
          phone: order.user.phone
        },
        order: {
          product: order.dataDetails.product.name,
          capacity: order.dataDetails.capacity,
          beneficiary: order.dataDetails.beneficiaryNumber,
          amount: `GHS ${order.amount.toFixed(2)}`,
          status: order.status,
          paymentMethod: order.paymentMethod
        },
        reference: order.reference,
        portalId: order.metadata?.portalId,
        completedAt: order.completedAt
      };
      
      res.json({
        success: true,
        data: receipt
      });
    } catch (error) {
      res.status(500).json({
        success: false,
        message: 'Error generating receipt',
        error: error.message
      });
    }
  }
);

// =============================================
// TODAY'S STATISTICS ENDPOINT
// =============================================

// Get today's statistics for the user
router.get('/profile/today-stats', auth.verifyToken, async (req, res) => {
  try {
    const userId = req.userId;
    
    // Get start and end of today in user's timezone (Ghana)
    const today = new Date();
    today.setHours(0, 0, 0, 0);
    const tomorrow = new Date(today);
    tomorrow.setDate(tomorrow.getDate() + 1);
    
    // Fetch today's orders (data purchases)
    const todayOrdersPromise = Transaction.aggregate([
      {
        $match: {
          user: new mongoose.Types.ObjectId(userId),
          type: 'data_purchase',
          createdAt: {
            $gte: today,
            $lt: tomorrow
          }
        }
      },
      {
        $group: {
          _id: null,
          totalOrders: { $sum: 1 },
          totalSpent: { $sum: '$amount' },
          successfulOrders: {
            $sum: { $cond: [{ $eq: ['$status', 'successful'] }, 1, 0] }
          },
          pendingOrders: {
            $sum: { $cond: [{ $eq: ['$status', 'pending'] }, 1, 0] }
          },
          sentOrders: {
            $sum: { $cond: [{ $eq: ['$status', 'sent'] }, 1, 0] }
          },
          failedOrders: {
            $sum: { $cond: [{ $eq: ['$status', 'failed'] }, 1, 0] }
          },
          portalSubmitted: {
            $sum: {
              $cond: [{ $ne: ['$metadata.portalId', null] }, 1, 0]
            }
          }
        }
      }
    ]);
    
    // Fetch today's deposits/funding by admin
    const todayDepositsPromise = WalletTransaction.aggregate([
      {
        $match: {
          user: new mongoose.Types.ObjectId(userId),
          type: 'credit',
          purpose: { $in: ['funding', 'adjustment'] },
          createdAt: {
            $gte: today,
            $lt: tomorrow
          }
        }
      },
      {
        $lookup: {
          from: 'reseller_users',
          localField: 'createdBy',
          foreignField: '_id',
          as: 'creator'
        }
      },
      {
        $unwind: {
          path: '$creator',
          preserveNullAndEmptyArrays: true
        }
      },
      {
        $match: {
          $or: [
            { 'creator.role': 'admin' },
            { createdBy: { $exists: false } }
          ]
        }
      },
      {
        $group: {
          _id: null,
          totalDeposits: { $sum: '$amount' },
          depositCount: { $sum: 1 },
          deposits: {
            $push: {
              amount: '$amount',
              time: '$createdAt',
              description: '$description',
              reference: '$reference'
            }
          }
        }
      }
    ]);
    
    // Fetch recent orders for detailed view
    const recentOrdersPromise = Transaction.find({
      user: userId,
      type: 'data_purchase',
      createdAt: {
        $gte: today,
        $lt: tomorrow
      }
    })
    .populate('dataDetails.product', 'name capacity')
    .sort({ createdAt: -1 })
    .limit(10)
    .lean();
    
    // Execute all promises in parallel
    const [todayOrders, todayDeposits, recentOrders] = await Promise.all([
      todayOrdersPromise,
      todayDepositsPromise,
      recentOrdersPromise
    ]);
    
    // Get current wallet balance for context
    const user = await User.findById(userId).select('wallet.balance fullName email').lean();
    
    if (!user) {
      return res.status(404).json({
        success: false,
        message: 'User not found'
      });
    }
    
    // Calculate hourly distribution of orders
    const hourlyDistribution = await Transaction.aggregate([
      {
        $match: {
          user: new mongoose.Types.ObjectId(userId),
          type: 'data_purchase',
          createdAt: {
            $gte: today,
            $lt: tomorrow
          }
        }
      },
      {
        $group: {
          _id: { $hour: '$createdAt' },
          count: { $sum: 1 },
          amount: { $sum: '$amount' }
        }
      },
      {
        $sort: { '_id': 1 }
      }
    ]);
    
    // Format the response
    const stats = {
      // User Info
      user: {
        fullName: user.fullName || 'N/A',
        email: user.email || 'N/A',
        currentBalance: user.wallet?.balance || 0
      },
      
      // Date Info
      date: {
        today: today.toISOString().split('T')[0],
        timezone: 'Africa/Accra'
      },
      
      // Order Statistics
      orders: {
        total: todayOrders[0]?.totalOrders || 0,
        successful: todayOrders[0]?.successfulOrders || 0,
        pending: todayOrders[0]?.pendingOrders || 0,
        sent: todayOrders[0]?.sentOrders || 0,
        failed: todayOrders[0]?.failedOrders || 0,
        portalSubmitted: todayOrders[0]?.portalSubmitted || 0,
        totalAmount: todayOrders[0]?.totalSpent || 0,
        formattedAmount: `GHS ${(todayOrders[0]?.totalSpent || 0).toFixed(2)}`
      },
      
      // Deposit Statistics
      deposits: {
        totalAmount: todayDeposits[0]?.totalDeposits || 0,
        formattedAmount: `GHS ${(todayDeposits[0]?.totalDeposits || 0).toFixed(2)}`,
        count: todayDeposits[0]?.depositCount || 0,
        transactions: todayDeposits[0]?.deposits?.map(dep => ({
          amount: `GHS ${dep.amount.toFixed(2)}`,
          time: dep.time,
          description: dep.description || 'Wallet funding',
          reference: dep.reference
        })) || []
      },
      
      // Recent Orders Detail with Portal IDs
      recentOrders: recentOrders.map(order => ({
        transactionId: order.transactionId,
        beneficiary: order.dataDetails?.beneficiaryNumber,
        product: order.dataDetails?.product?.name || 'N/A',
        capacity: order.dataDetails?.capacity,
        amount: `GHS ${order.amount.toFixed(2)}`,
        status: order.status,
        time: order.createdAt,
        portalId: order.metadata?.portalId
      })),
      
      // Hourly Distribution
      hourlyActivity: hourlyDistribution.map(hour => ({
        hour: `${hour._id}:00`,
        orders: hour.count,
        amount: hour.amount
      })),
      
      // Summary
      summary: {
        netActivity: (todayDeposits[0]?.totalDeposits || 0) - (todayOrders[0]?.totalSpent || 0),
        formattedNetActivity: `GHS ${((todayDeposits[0]?.totalDeposits || 0) - (todayOrders[0]?.totalSpent || 0)).toFixed(2)}`,
        averageOrderValue: todayOrders[0]?.totalOrders > 0 
          ? `GHS ${(todayOrders[0].totalSpent / todayOrders[0].totalOrders).toFixed(2)}`
          : 'GHS 0.00',
        successRate: todayOrders[0]?.totalOrders > 0
          ? `${((todayOrders[0].successfulOrders / todayOrders[0].totalOrders) * 100).toFixed(1)}%`
          : '0%'
      }
    };
    
    res.json({
      success: true,
      message: 'Today\'s statistics retrieved successfully',
      data: stats
    });
    
  } catch (error) {
    console.error('Error fetching today\'s statistics:', error);
    res.status(500).json({
      success: false,
      message: 'Error fetching today\'s statistics',
      error: error.message
    });
  }
});

// Get statistics for a date range
router.get('/profile/date-range-stats', auth.verifyToken, async (req, res) => {
  try {
    const userId = req.userId;
    const { startDate, endDate } = req.query;
    
    if (!startDate || !endDate) {
      return res.status(400).json({
        success: false,
        message: 'Start date and end date are required'
      });
    }
    
    const start = new Date(startDate);
    start.setHours(0, 0, 0, 0);
    const end = new Date(endDate);
    end.setHours(23, 59, 59, 999);
    
    // Validate date range
    if (start > end) {
      return res.status(400).json({
        success: false,
        message: 'Start date cannot be after end date'
      });
    }
    
    if ((end - start) > 90 * 24 * 60 * 60 * 1000) {
      return res.status(400).json({
        success: false,
        message: 'Date range cannot exceed 90 days'
      });
    }
    
    const filter = { 
      user: new mongoose.Types.ObjectId(userId),
      type: 'data_purchase',
      createdAt: {
        $gte: start,
        $lte: end
      }
    };
    
    // Fetch orders for date range
    const ordersStatsPromise = Transaction.aggregate([
      {
        $match: filter
      },
      {
        $group: {
          _id: {
            $dateToString: {
              format: '%Y-%m-%d',
              date: '$createdAt'
            }
          },
          totalOrders: { $sum: 1 },
          totalSpent: { $sum: '$amount' },
          successfulOrders: {
            $sum: { $cond: [{ $eq: ['$status', 'successful'] }, 1, 0] }
          }
        }
      },
      {
        $sort: { '_id': 1 }
      }
    ]);
    
    // Fetch deposits for date range
    const depositsStatsPromise = WalletTransaction.aggregate([
      {
        $match: {
          user: new mongoose.Types.ObjectId(userId),
          type: 'credit',
          purpose: { $in: ['funding', 'adjustment'] },
          createdAt: {
            $gte: start,
            $lte: end
          }
        }
      },
      {
        $lookup: {
          from: 'reseller_users',
          localField: 'createdBy',
          foreignField: '_id',
          as: 'creator'
        }
      },
      {
        $unwind: {
          path: '$creator',
          preserveNullAndEmptyArrays: true
        }
      },
      {
        $match: {
          $or: [
            { 'creator.role': 'admin' },
            { createdBy: { $exists: false } }
          ]
        }
      },
      {
        $group: {
          _id: {
            $dateToString: {
              format: '%Y-%m-%d',
              date: '$createdAt'
            }
          },
          totalDeposits: { $sum: '$amount' },
          depositCount: { $sum: 1 }
        }
      },
      {
        $sort: { '_id': 1 }
      }
    ]);
    
    const [ordersStats, depositsStats] = await Promise.all([
      ordersStatsPromise,
      depositsStatsPromise
    ]);
    
    // Combine stats by date
    const dailyStats = {};
    
    // Add orders data
    ordersStats.forEach(day => {
      dailyStats[day._id] = {
        date: day._id,
        orders: {
          total: day.totalOrders,
          successful: day.successfulOrders,
          amount: day.totalSpent
        },
        deposits: {
          amount: 0,
          count: 0
        }
      };
    });
    
    // Add deposits data
    depositsStats.forEach(day => {
      if (!dailyStats[day._id]) {
        dailyStats[day._id] = {
          date: day._id,
          orders: {
            total: 0,
            successful: 0,
            amount: 0
          },
          deposits: {
            amount: 0,
            count: 0
          }
        };
      }
      dailyStats[day._id].deposits = {
        amount: day.totalDeposits,
        count: day.depositCount
      };
    });
    
    // Calculate totals
    const totals = {
      totalOrders: ordersStats.reduce((sum, day) => sum + day.totalOrders, 0),
      totalSpent: ordersStats.reduce((sum, day) => sum + day.totalSpent, 0),
      totalDeposits: depositsStats.reduce((sum, day) => sum + day.totalDeposits, 0),
      totalDepositCount: depositsStats.reduce((sum, day) => sum + day.depositCount, 0)
    };
    
    res.json({
      success: true,
      data: {
        dateRange: {
          start: start.toISOString().split('T')[0],
          end: end.toISOString().split('T')[0],
          days: Math.ceil((end - start) / (1000 * 60 * 60 * 24))
        },
        totals: {
          orders: totals.totalOrders,
          ordersAmount: `GHS ${totals.totalSpent.toFixed(2)}`,
          deposits: totals.totalDepositCount,
          depositsAmount: `GHS ${totals.totalDeposits.toFixed(2)}`,
          netActivity: `GHS ${(totals.totalDeposits - totals.totalSpent).toFixed(2)}`
        },
        dailyBreakdown: Object.values(dailyStats).sort((a, b) => 
          new Date(a.date) - new Date(b.date)
        )
      }
    });
    
  } catch (error) {
    console.error('Error fetching date range statistics:', error);
    res.status(500).json({
      success: false,
      message: 'Error fetching date range statistics',
      error: error.message
    });
  }
});

// =============================================
// EXPORT ROUTER
// =============================================

module.exports = router;