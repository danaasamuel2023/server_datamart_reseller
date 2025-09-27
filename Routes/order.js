// =============================================
// ORDER & PRODUCT ROUTES - GHANA MTN DATA PLATFORM
// For Agents, Dealers, Suppliers & Customers
// Updated with 6-digit reference numbers
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

// DEBUG VERSION - Single Order with detailed logging
router.post('/orders/single',
  auth.verifyToken,
  rateLimit.transaction,
  validate.validateDataPurchase,
  validate.handleValidationErrors,
  wallet.lockWallet,
  generateReferenceMiddleware, // Updated to generate 6-digit reference
  async (req, res) => {
    console.log('\n=== ORDER PROCESSING START ===');
    console.log('Request Body:', JSON.stringify(req.body, null, 2));
    console.log('User ID:', req.userId);
    console.log('User Role:', req.user?.role);
    console.log('Transaction Ref (6-digit):', req.transactionRef);
    
    let session;
    
    try {
      // Start MongoDB session
      console.log('Starting MongoDB session...');
      session = await mongoose.startSession();
      session.startTransaction();
      console.log('Transaction started');
      
      const { productId, beneficiaryNumber } = req.body;
      const userId = req.userId;
      const reference = req.transactionRef; // Now 6 digits
      
      // Step 1: Get product
      console.log('\nStep 1: Fetching product:', productId);
      const product = await Product.findById(productId);
      console.log('Product found:', product ? 'Yes' : 'No');
      
      if (!product) {
        console.error('Product not found:', productId);
        await session.abortTransaction();
        return res.status(400).json({
          success: false,
          message: 'Product not found',
          productId: productId
        });
      }
      
      if (product.status !== 'active') {
        console.error('Product not active:', product.status);
        await session.abortTransaction();
        return res.status(400).json({
          success: false,
          message: 'Product not available',
          status: product.status
        });
      }
      
      console.log('Product details:', {
        name: product.name,
        code: product.productCode,
        capacity: product.capacity
      });
      
      // Step 2: Get pricing
      console.log('\nStep 2: Fetching pricing for product...');
      const pricing = await PriceSetting.findOne({
        product: productId,
        isActive: true
      });
      console.log('Pricing found:', pricing ? 'Yes' : 'No');
      
      if (!pricing) {
        console.error('No active pricing for product:', productId);
        await session.abortTransaction();
        return res.status(400).json({
          success: false,
          message: 'Product pricing not available. Please contact admin to set pricing.',
          productId: productId
        });
      }
      
      console.log('Pricing details:', {
        costPrice: pricing.costPrice,
        agentPrice: pricing.agentPrice,
        dealerPrice: pricing.dealerPrice,
        supplierPrice: pricing.supplierPrice
      });
      
      // Step 3: Calculate price based on role
      const userRole = req.user.role || 'agent';
      console.log('\nStep 3: Calculating price for role:', userRole);
      
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
      
      console.log('Calculated amount:', amount);
      
      // Step 4: Check wallet balance
      console.log('\nStep 4: Checking wallet balance...');
      const user = await User.findById(userId).session(session);
      
      if (!user) {
        console.error('User not found:', userId);
        await session.abortTransaction();
        return res.status(404).json({
          success: false,
          message: 'User not found'
        });
      }
      
      console.log('Current balance:', user.wallet.balance);
      console.log('Required amount:', amount);
      console.log('Sufficient balance:', user.wallet.balance >= amount);
      
      if (user.wallet.balance < amount) {
        console.error('Insufficient balance');
        await session.abortTransaction();
        return res.status(400).json({
          success: false,
          message: 'Insufficient wallet balance',
          required: amount,
          available: user.wallet.balance
        });
      }
      
      // Step 5: Deduct from wallet
      console.log('\nStep 5: Deducting from wallet...');
      const balanceBefore = user.wallet.balance;
      user.wallet.balance -= amount;
      await user.save({ session });
      console.log('New balance:', user.wallet.balance);
      
      // Step 6: Create transaction record
      console.log('\nStep 6: Creating transaction record...');
      const transaction = new Transaction({
        transactionId: reference, // 6-digit reference
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
        reference: reference, // 6-digit reference
        paymentMethod: 'wallet'
      });
      
      await transaction.save({ session });
      console.log('Transaction created with 6-digit ID:', transaction.transactionId);
      
      // Step 7: Create wallet transaction
      console.log('\nStep 7: Creating wallet transaction...');
      const walletTx = await WalletTransaction.create([{
        user: userId,
        type: 'debit',
        amount: amount,
        balanceBefore: balanceBefore,
        balanceAfter: user.wallet.balance,
        purpose: 'purchase',
        reference: reference, // 6-digit reference
        status: 'completed',
        description: `Purchase of ${product.name} for ${beneficiaryNumber}`
      }], { session });
      console.log('Wallet transaction created');
      
      // Step 8: Simulate MTN API call (for now, just mark as successful)
      console.log('\nStep 8: Processing with MTN API (simulated)...');
      transaction.status = 'pending';
      transaction.completedAt = new Date();
      await transaction.save({ session });
      console.log('Transaction marked as successful');
      
      // Step 9: Update product stats if they exist
      if (product.stats) {
        console.log('\nStep 9: Updating product stats...');
        product.stats.totalSold = (product.stats.totalSold || 0) + 1;
        product.stats.totalRevenue = (product.stats.totalRevenue || 0) + amount;
        await product.save({ session });
        console.log('Product stats updated');
      }
      
      // Step 10: Commit transaction
      console.log('\nStep 10: Committing transaction...');
      await session.commitTransaction();
      console.log('Transaction committed successfully');
      
      // Step 11: Send notification (outside of transaction)
      console.log('\nStep 11: Creating notification...');
      try {
        await Notification.create({
          user: userId,
          title: 'Data Purchase Successful',
          message: `Your purchase of ${product.name} for ${beneficiaryNumber} was successful`,
          type: 'success',
          category: 'transaction',
          relatedTransaction: transaction._id
        });
        console.log('Notification created');
      } catch (notifError) {
        console.error('Notification error (non-critical):', notifError.message);
      }
      
      // Send success response
      console.log('\n=== ORDER PROCESSING COMPLETE ===\n');
      res.json({
        success: true,
        message: 'Order placed successfully',
        data: {
          transactionId: reference, // 6-digit reference
          product: product.name,
          beneficiary: beneficiaryNumber,
          amount: amount,
          status: 'successful',
          balance: user.wallet.balance
        }
      });
      
    } catch (error) {
      console.error('\n=== ERROR OCCURRED ===');
      console.error('Error Type:', error.name);
      console.error('Error Message:', error.message);
      console.error('Error Stack:', error.stack);
      
      if (session) {
        console.log('Aborting transaction...');
        await session.abortTransaction();
      }
      
      // Send detailed error in development, generic in production
      const errorResponse = {
        success: false,
        message: 'Error processing order'
      };
      
      // In development, add more details
      if (process.env.NODE_ENV !== 'production') {
        errorResponse.error = error.message;
        errorResponse.stack = error.stack;
        errorResponse.details = {
          errorName: error.name,
          userId: req.userId,
          productId: req.body.productId,
          beneficiary: req.body.beneficiaryNumber
        };
      }
      
      res.status(500).json(errorResponse);
    } finally {
      if (session) {
        console.log('Ending session...');
        session.endSession();
      }
    }
  }
);

// =============================================
// 3. BULK ORDER PLACEMENT (WITH 6-DIGIT REFERENCES)
// =============================================

// Place bulk data order
router.post('/orders/bulk',
  auth.verifyToken,
  rateLimit.transaction,
  wallet.lockWallet,
  async (req, res) => {
    const session = await mongoose.startSession();
    session.startTransaction();
    
    try {
      const { orders } = req.body; // Array of { productId, beneficiaryNumber, quantity }
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
        // Generate unique 6-digit reference for each order
        const orderRef = await generateUniqueReference('');
        
        try {
          // Create transaction for each order
          const transaction = new Transaction({
            transactionId: orderRef, // 6-digit reference
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
            reference: orderRef, // 6-digit reference
            paymentMethod: 'wallet',
            metadata: {
              bulkReference: bulkReference // BLK + 6 digits
            }
          });
          
          
          await transaction.save({ session });
          
          // TODO: Call MTN API for each number
          // For now, simulate success
          transaction.status = 'pending';
          transaction.completedAt = new Date();
          await transaction.save({ session });
          
          // Update product stats
          if (orderDetail.product.stats) {
            orderDetail.product.stats.totalSold = (orderDetail.product.stats.totalSold || 0) + orderDetail.quantity;
            orderDetail.product.stats.totalRevenue = (orderDetail.product.stats.totalRevenue || 0) + orderDetail.amount;
            await orderDetail.product.save({ session });
          }
          
          processedOrders.push({
            transactionId: orderRef, // 6-digit reference
            product: orderDetail.product.name,
            beneficiary: orderDetail.beneficiaryNumber,
            quantity: orderDetail.quantity,
            amount: orderDetail.amount,
            status: 'successful'
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
        reference: bulkReference, // BLK + 6 digits
        status: 'completed',
        description: `Bulk purchase of ${orders.length} items`
      }], { session });
      
      await session.commitTransaction();
      
      // Send notification
      await Notification.create({
        user: userId,
        title: 'Bulk Order Processed',
        message: `Your bulk order of ${processedOrders.length} items has been processed`,
        type: 'success',
        category: 'transaction',
        metadata: {
          bulkReference: bulkReference
        }
      });
      
      res.json({
        success: true,
        message: 'Bulk order processed',
        data: {
          bulkReference: bulkReference, // BLK + 6 digits
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

// Upload CSV for bulk order
router.post('/orders/bulk/csv',
  auth.verifyToken,
  async (req, res) => {
    try {
      const { csvData } = req.body;
      
      // Parse CSV data
      // Expected format: productCode,beneficiaryNumber,quantity
      const lines = csvData.split('\n').filter(line => line.trim());
      const orders = [];
      
      for (let i = 1; i < lines.length; i++) { // Skip header
        const [productCode, beneficiaryNumber, quantity] = lines[i].split(',').map(s => s.trim());
        
        const product = await Product.findOne({ productCode });
        if (!product) {
          return res.status(400).json({
            success: false,
            message: `Product not found: ${productCode}`,
            line: i + 1
          });
        }
        
        orders.push({
          productId: product._id,
          beneficiaryNumber,
          quantity: parseInt(quantity) || 1
        });
      }
      
      // Process as bulk order
      req.body.orders = orders;
      
      // Call the bulk order handler
      return router.post('/orders/bulk', auth.verifyToken, rateLimit.transaction, wallet.lockWallet)(req, res);
    } catch (error) {
      res.status(500).json({
        success: false,
        message: 'Error processing CSV',
        error: error.message
      });
    }
  }
);

// =============================================
// 4. ORDER HISTORY & TRACKING
// =============================================

// Get user's order history
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
      
      if (search) {
        filter.$or = [
          { transactionId: { $regex: search, $options: 'i' } },
          { reference: { $regex: search, $options: 'i' } },
          { 'dataDetails.beneficiaryNumber': { $regex: search, $options: 'i' } }
        ];
      }
      
      const orders = await Transaction.find(filter)
        .sort({ createdAt: -1 })
        .limit(limit * 1)
        .skip((page - 1) * limit)
        .populate('dataDetails.product', 'name productCode capacity')
        .lean();
      
      const total = await Transaction.countDocuments(filter);
      
      // Format orders
      const formattedOrders = orders.map(order => ({
        id: order._id,
        transactionId: order.transactionId,
        date: order.createdAt,
        product: order.dataDetails?.product?.name,
        capacity: order.dataDetails?.capacity,
        beneficiary: order.dataDetails?.beneficiaryNumber,
        amount: order.amount,
        status: order.status,
        reference: order.reference,
        completedAt: order.completedAt
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

// Get single order details
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
      
      res.json({
        success: true,
        data: order
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

// Track order status
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
      
      // Create tracking timeline
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
        },
        {
          status: 'sending',
          message: 'Sending data to beneficiary',
          timestamp: order.processedAt || order.createdAt,
          completed: order.status !== 'pending'
        },
        {
          status: 'completed',
          message: 'Data delivered successfully',
          timestamp: order.completedAt,
          completed: order.status === 'successful'
        }
      ];
      
      res.json({
        success: true,
        data: {
          orderId: order.transactionId,
          currentStatus: order.status,
          beneficiary: order.dataDetails?.beneficiaryNumber,
          amount: order.amount,
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
            user: mongoose.Types.ObjectId(userId),
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
            }
          }
        }
      ]);
      
      // Get most purchased products
      const topProducts = await Transaction.aggregate([
        {
          $match: {
            user: mongoose.Types.ObjectId(userId),
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
            from: 'products',
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
            user: mongoose.Types.ObjectId(userId),
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
            pendingOrders: 0
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
      const { beneficiaryNumber } = req.body; // Optional new beneficiary
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
      return router.post('/orders/single', 
        auth.verifyToken, 
        rateLimit.transaction, 
        validate.validateDataPurchase,
        validate.handleValidationErrors,
        wallet.lockWallet
      )(req, res);
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
            user: mongoose.Types.ObjectId(userId),
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
// 7. DOWNLOAD RECEIPTS
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
        receiptNumber: order.transactionId, // 6-digit reference
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
        reference: order.reference, // 6-digit reference
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
// EXPORT ROUTER
// =============================================

module.exports = router;