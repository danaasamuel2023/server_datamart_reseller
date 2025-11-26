// =============================================
// EXTERNAL API ROUTES - GHANA MTN DATA PLATFORM
// INTEGRATED WITH DATAMART API - YELLO NETWORK ONLY
// =============================================

const express = require('express');
const router = express.Router();
const mongoose = require('mongoose');
const axios = require('axios');
const crypto = require('crypto');

// Import models
const {
  User,
  Product,
  Transaction,
  PriceSetting,
  WalletTransaction,
  ApiLog,
  Notification
} = require('../schema/schema');

// Import middleware
const { apiKey, rateLimit } = require('../middleware/middleware');

// =============================================
// DATAMART API CONFIGURATION
// =============================================
const DATAMART_BASE_URL = 'https://api.datamartgh.shop';
const DATAMART_API_KEY = process.env.DATAMART_API_KEY || 'f9329bb51dd27c41fe3b85c7eb916a8e88821e07fd0565e1ff2558e7be3be7b4';

const datamartClient = axios.create({
  baseURL: DATAMART_BASE_URL,
  headers: {
    'x-api-key': DATAMART_API_KEY,
    'Content-Type': 'application/json'
  },
  timeout: 30000
});

// Helper to convert capacity to DataMart format (just the number)
const parseCapacityForDatamart = (capacity) => {
  const match = capacity.toUpperCase().match(/^(\d+(?:\.\d+)?)(MB|GB)$/i);
  if (!match) return null;
  
  const value = parseFloat(match[1]);
  const unit = match[2].toUpperCase();
  
  // DataMart expects capacity in GB as string number
  if (unit === 'MB') {
    return (value / 1000).toString(); // Convert MB to GB
  }
  return value.toString(); // Already in GB
};

// Process order through DataMart API
const processWithDatamart = async (phoneNumber, capacity, reference) => {
  try {
    const datamartCapacity = parseCapacityForDatamart(capacity);
    
    if (!datamartCapacity) {
      return { success: false, error: 'Invalid capacity format' };
    }

    const payload = {
      phoneNumber: phoneNumber,
      network: 'YELLO', // All requests go to YELLO (MTN)
      capacity: datamartCapacity,
      gateway: 'wallet',
      ref: reference
    };

    console.log('[DATAMART] Sending request:', payload);

    const response = await datamartClient.post('/api/developer/purchase', payload);

    console.log('[DATAMART] Response:', response.data);

    if (response.data && response.data.status === 'success') {
      return {
        success: true,
        purchaseId: response.data.data?.purchaseId,
        message: response.data.message || 'Success',
        data: response.data
      };
    } else {
      return {
        success: false,
        error: response.data?.message || 'DataMart processing failed',
        data: response.data
      };
    }
  } catch (error) {
    console.error('[DATAMART] Error:', error.response?.data || error.message);
    return {
      success: false,
      error: error.response?.data?.message || error.message,
      data: error.response?.data
    };
  }
};

// Apply API authentication and rate limiting
router.use(apiKey);
router.use(rateLimit.api);

// Middleware to log API response
const logApiResponse = async (req, res, next) => {
  const startTime = Date.now();
  const originalSend = res.send;
  
  res.send = function(data) {
    res.send = originalSend;
    
    ApiLog.create({
      user: req.userId,
      apiKey: req.header('X-API-Key'),
      endpoint: req.originalUrl,
      method: req.method,
      request: {
        body: req.body,
        headers: {
          'x-api-key': req.header('X-API-Key'),
          'content-type': req.header('Content-Type')
        }
      },
      response: {
        statusCode: res.statusCode,
        body: typeof data === 'string' ? JSON.parse(data) : data,
        responseTime: Date.now() - startTime
      },
      success: res.statusCode < 400,
      ipAddress: req.ip
    }).catch(err => console.error('API Log Error:', err));
    
    User.findByIdAndUpdate(req.userId, {
      $inc: { 'apiAccess.requestCount': 1 },
      'apiAccess.lastUsed': new Date()
    }).catch(err => console.error('API Usage Update Error:', err));
    
    return res.send(data);
  };
  
  next();
};

router.use(logApiResponse);

// =============================================
// API RESPONSE HELPERS
// =============================================

const apiResponse = {
  success: (res, message, data = {}, statusCode = 200) => {
    return res.status(statusCode).json({
      success: true,
      message,
      data,
      timestamp: new Date().toISOString()
    });
  },
  
  error: (res, message, error = {}, statusCode = 400) => {
    return res.status(statusCode).json({
      success: false,
      message,
      error,
      timestamp: new Date().toISOString()
    });
  }
};

// =============================================
// WEBHOOK HELPER - WITH OPTIONAL SIGNATURE
// =============================================

const sendWebhook = async (user, event, data) => {
  if (!user.apiAccess?.webhookUrl) return;
  
  try {
    const payload = {
      event,
      data,
      timestamp: new Date().toISOString()
    };
    
    const headers = {
      'Content-Type': 'application/json',
      'X-Platform-Event': event
    };
    
    if (user.apiAccess.apiSecret) {
      payload.signature = crypto
        .createHmac('sha256', user.apiAccess.apiSecret)
        .update(JSON.stringify(data))
        .digest('hex');
      
      headers['X-Platform-Signature'] = payload.signature;
    }
    
    await axios.post(user.apiAccess.webhookUrl, payload, {
      headers,
      timeout: 5000
    });
    
    console.log(`✅ Webhook sent: ${event} to ${user.apiAccess.webhookUrl}`);
  } catch (error) {
    console.error('❌ Webhook error:', error.message);
  }
};

// =============================================
// PRODUCT LOOKUP HELPER
// =============================================

const findProductByCapacityAndName = async (capacity, productName) => {
  try {
    const capacityRegex = /^(\d+(?:\.\d+)?)(MB|GB)$/i;
    const capacityMatch = capacity.toUpperCase().match(capacityRegex);
    
    if (!capacityMatch) {
      return {
        error: true,
        code: 'INVALID_CAPACITY_FORMAT',
        message: 'Invalid capacity format',
        details: {
          format: 'Valid formats: 500MB, 1GB, 2.5GB',
          provided: capacity
        }
      };
    }
    
    const capacityValue = parseFloat(capacityMatch[1]);
    const capacityUnit = capacityMatch[2];
    
    const product = await Product.findOne({
      name: new RegExp(productName, 'i'),
      'capacity.value': capacityValue,
      'capacity.unit': capacityUnit,
      status: 'active'
    });
    
    if (!product) {
      const alternativeProducts = await Product.find({
        'capacity.value': capacityValue,
        'capacity.unit': capacityUnit,
        status: 'active'
      }).select('name productCode');
      
      if (alternativeProducts.length > 0) {
        return {
          error: true,
          code: 'PRODUCT_NOT_FOUND',
          message: 'Product not found with specified name and capacity',
          details: {
            requested: { name: productName, capacity: capacity },
            available_alternatives: alternativeProducts.map(p => ({
              name: p.name,
              product_code: p.productCode
            }))
          }
        };
      }
      
      return {
        error: true,
        code: 'CAPACITY_NOT_AVAILABLE',
        message: 'No products available with specified capacity',
        details: { requested_capacity: capacity }
      };
    }
    
    return {
      error: false,
      product: product,
      capacityValue: capacityValue,
      capacityUnit: capacityUnit
    };
  } catch (error) {
    return {
      error: true,
      code: 'PRODUCT_LOOKUP_ERROR',
      message: 'Error looking up product',
      details: { error: error.message }
    };
  }
};

// =============================================
// 1. ACCOUNT & BALANCE APIs
// =============================================

router.get('/v1/account', async (req, res) => {
  try {
    const user = await User.findById(req.userId)
      .select('fullName email phone role wallet status apiAccess')
      .lean();
    
    return apiResponse.success(res, 'Account information retrieved', {
      account: {
        name: user.fullName,
        email: user.email,
        phone: user.phone,
        role: user.role,
        status: user.status
      },
      wallet: {
        balance: user.wallet.balance,
        currency: user.wallet.currency || 'GHS'
      },
      api: {
        requestCount: user.apiAccess.requestCount,
        rateLimit: user.apiAccess.rateLimit || 100,
        webhookUrl: user.apiAccess.webhookUrl,
        webhookSignatureEnabled: !!user.apiAccess.apiSecret
      },
      supported_networks: ['YELLO (MTN)'] // Only YELLO supported
    });
  } catch (error) {
    console.error('Account API Error:', error);
    return apiResponse.error(res, 'Error fetching account information', {
      code: 'ACCOUNT_ERROR',
      details: error.message
    }, 500);
  }
});

router.get('/v1/balance', async (req, res) => {
  try {
    const user = await User.findById(req.userId).select('wallet').lean();
    
    return apiResponse.success(res, 'Balance retrieved', {
      balance: user.wallet.balance,
      currency: user.wallet.currency || 'GHS',
      formatted: `GHS ${user.wallet.balance.toFixed(2)}`
    });
  } catch (error) {
    console.error('Balance API Error:', error);
    return apiResponse.error(res, 'Error fetching balance', {
      code: 'BALANCE_ERROR',
      details: error.message
    }, 500);
  }
});

// =============================================
// 2. PRODUCT LISTING API
// =============================================

router.get('/v1/products', async (req, res) => {
  try {
    const { category, min_capacity, max_capacity } = req.query;
    const userRole = req.userRole;
    
    const filter = { status: 'active' };
    if (category) filter.category = category;
    
    const products = await Product.find(filter).lean();
    
    const productsWithPricing = await Promise.all(
      products.map(async (product) => {
        const pricing = await PriceSetting.findOne({
          product: product._id,
          isActive: true
        });
        
        if (!pricing) return null;
        
        let price;
        switch (userRole) {
          case 'supplier': price = pricing.supplierPrice; break;
          case 'dealer': price = pricing.dealerPrice; break;
          case 'agent': price = pricing.agentPrice; break;
          default: price = pricing.agentPrice;
        }
        
        if (min_capacity || max_capacity) {
          const capacityInMB = product.capacity.unit === 'GB' 
            ? product.capacity.value * 1024 
            : product.capacity.value;
          
          if (min_capacity && capacityInMB < parseInt(min_capacity)) return null;
          if (max_capacity && capacityInMB > parseInt(max_capacity)) return null;
        }
        
        return {
          product_code: product.productCode,
          name: product.name,
          category: product.category,
          capacity: `${product.capacity.value}${product.capacity.unit}`,
          capacity_value: product.capacity.value,
          capacity_unit: product.capacity.unit,
          validity: `${product.validity.value} ${product.validity.unit}`,
          price: price,
          currency: 'GHS',
          network: 'YELLO', // All products are YELLO
          status: product.status
        };
      })
    );
    
    const validProducts = productsWithPricing.filter(p => p !== null);
    
    return apiResponse.success(res, 'Products retrieved', {
      products: validProducts,
      total: validProducts.length,
      supported_network: 'YELLO (MTN)'
    });
  } catch (error) {
    console.error('Products API Error:', error);
    return apiResponse.error(res, 'Error fetching products', {
      code: 'PRODUCT_ERROR',
      details: error.message
    }, 500);
  }
});

// =============================================
// 3. SINGLE PURCHASE API - DATAMART INTEGRATED
// =============================================

router.post('/v1/purchase', async (req, res) => {
  const session = await mongoose.startSession();
  session.startTransaction();
  
  try {
    const {
      capacity,
      product_name,
      beneficiary_number,
      reference,
      callback_url
    } = req.body;
    
    // Validate inputs
    if (!capacity) {
      await session.abortTransaction();
      return apiResponse.error(res, 'Capacity is required', {
        code: 'MISSING_CAPACITY',
        example: '2GB, 500MB, 1GB'
      });
    }
    
    if (!product_name) {
      await session.abortTransaction();
      return apiResponse.error(res, 'Product name is required', {
        code: 'MISSING_PRODUCT_NAME',
        available: 'YELLOW'
      });
    }
    
    if (!beneficiary_number) {
      await session.abortTransaction();
      return apiResponse.error(res, 'Beneficiary number is required', {
        code: 'MISSING_BENEFICIARY'
      });
    }
    
    // Validate Ghana MTN number format
    if (!beneficiary_number.match(/^(\+233|0)(24|25|53|54|55|59)[0-9]{7}$/)) {
      await session.abortTransaction();
      return apiResponse.error(res, 'Invalid MTN Ghana phone number', {
        code: 'INVALID_PHONE_NUMBER',
        format: 'Valid MTN prefixes: 024, 025, 053, 054, 055, 059',
        provided: beneficiary_number
      });
    }
    
    // Find product
    const productResult = await findProductByCapacityAndName(capacity, product_name);
    
    if (productResult.error) {
      await session.abortTransaction();
      return apiResponse.error(res, productResult.message, {
        code: productResult.code,
        ...productResult.details
      }, 404);
    }
    
    const product = productResult.product;
    
    // Get pricing
    const pricing = await PriceSetting.findOne({
      product: product._id,
      isActive: true
    });
    
    if (!pricing) {
      await session.abortTransaction();
      return apiResponse.error(res, 'Product pricing not available', {
        code: 'PRICING_UNAVAILABLE'
      });
    }
    
    // Calculate price based on user role
    let amount;
    switch (req.userRole) {
      case 'supplier': amount = pricing.supplierPrice; break;
      case 'dealer': amount = pricing.dealerPrice; break;
      case 'agent': amount = pricing.agentPrice; break;
      default: amount = pricing.agentPrice;
    }
    
    // Check wallet balance
    const user = await User.findById(req.userId).session(session);
    if (user.wallet.balance < amount) {
      await session.abortTransaction();
      return apiResponse.error(res, 'Insufficient wallet balance', {
        code: 'INSUFFICIENT_BALANCE',
        required_amount: amount,
        current_balance: user.wallet.balance,
        shortage: amount - user.wallet.balance
      });
    }
    
    // Check duplicate reference
    if (reference) {
      const existingTransaction = await Transaction.findOne({ reference });
      if (existingTransaction) {
        await session.abortTransaction();
        return apiResponse.error(res, 'Duplicate reference', {
          code: 'DUPLICATE_REFERENCE',
          reference: reference
        });
      }
    }
    
    // Generate reference
    const transactionRef = reference || 'API' + Date.now() + crypto.randomBytes(4).toString('hex').toUpperCase();
    
    // Deduct from wallet
    const balanceBefore = user.wallet.balance;
    user.wallet.balance -= amount;
    await user.save({ session });
    
    // Create transaction as pending
    const transaction = new Transaction({
      transactionId: transactionRef,
      user: req.userId,
      type: 'data_purchase',
      dataDetails: {
        product: product._id,
        beneficiaryNumber: beneficiary_number,
        capacity: `${product.capacity.value}${product.capacity.unit}`,
        network: 'YELLO' // Always YELLO
      },
      amount: amount,
      balanceBefore: balanceBefore,
      balanceAfter: user.wallet.balance,
      status: 'pending',
      reference: transactionRef,
      paymentMethod: 'wallet',
      channel: 'api',
      metadata: {
        apiKey: req.header('X-API-Key'),
        callbackUrl: callback_url,
        requestedCapacity: capacity,
        requestedProductName: product_name,
        processingProvider: 'datamart'
      }
    });
    
    await transaction.save({ session });
    
    // Create wallet transaction
    await WalletTransaction.create([{
      user: req.userId,
      type: 'debit',
      amount: amount,
      balanceBefore: balanceBefore,
      balanceAfter: user.wallet.balance,
      purpose: 'purchase',
      reference: transactionRef,
      status: 'completed',
      relatedTransaction: transaction._id
    }], { session });
    
    // Commit the database transaction first
    await session.commitTransaction();
    
    // Now process with DataMart API
    console.log(`[API] Processing order ${transactionRef} through DataMart...`);
    
    const datamartResult = await processWithDatamart(
      beneficiary_number,
      capacity,
      transactionRef
    );
    
    if (datamartResult.success) {
      // Update transaction as completed
      await Transaction.findByIdAndUpdate(transaction._id, {
        status: 'completed',
        completedAt: new Date(),
        'metadata.datamartPurchaseId': datamartResult.purchaseId,
        'metadata.datamartResponse': datamartResult.data
      });
      
      // Send success webhook
      sendWebhook(user, 'transaction.completed', {
        reference: transactionRef,
        transaction_id: transaction._id,
        status: 'completed',
        product: { name: product.name, capacity: capacity },
        beneficiary: beneficiary_number,
        amount: amount,
        balance_after: user.wallet.balance,
        provider_reference: datamartResult.purchaseId,
        completed_at: new Date()
      });
      
      // Send callback
      if (callback_url) {
        axios.post(callback_url, {
          reference: transactionRef,
          status: 'completed',
          message: 'Data purchase completed successfully',
          transaction_id: transaction._id,
          provider_reference: datamartResult.purchaseId
        }).catch(err => console.error('Callback Error:', err));
      }
      
      return apiResponse.success(res, 'Purchase completed successfully', {
        reference: transactionRef,
        transaction_id: transaction._id,
        product: {
          name: product.name,
          capacity: capacity,
          validity: `${product.validity.value} ${product.validity.unit}`,
          product_code: product.productCode
        },
        network: 'YELLO',
        beneficiary: beneficiary_number,
        amount: amount,
        price_tier: req.userRole,
        currency: 'GHS',
        status: 'completed',
        provider_reference: datamartResult.purchaseId,
        balance_after: user.wallet.balance,
        webhook_sent: !!user.apiAccess?.webhookUrl
      }, 201);
      
    } else {
      // DataMart failed - refund user
      console.error(`[API] DataMart failed for ${transactionRef}:`, datamartResult.error);
      
      await User.findByIdAndUpdate(req.userId, {
        $inc: { 'wallet.balance': amount }
      });
      
      // Update transaction as failed
      await Transaction.findByIdAndUpdate(transaction._id, {
        status: 'failed',
        failureReason: datamartResult.error,
        'metadata.datamartError': datamartResult.data
      });
      
      // Create refund wallet transaction
      await WalletTransaction.create({
        user: req.userId,
        type: 'credit',
        amount: amount,
        balanceBefore: user.wallet.balance,
        balanceAfter: user.wallet.balance + amount,
        purpose: 'refund',
        reference: transactionRef + '_REFUND',
        status: 'completed',
        description: `Refund for failed order: ${datamartResult.error}`
      });
      
      // Send failure webhook
      sendWebhook(user, 'transaction.failed', {
        reference: transactionRef,
        transaction_id: transaction._id,
        status: 'failed',
        error: datamartResult.error,
        amount_refunded: amount,
        balance_after: user.wallet.balance + amount
      });
      
      return apiResponse.error(res, 'Purchase failed - amount refunded', {
        code: 'PROVIDER_ERROR',
        reference: transactionRef,
        error: datamartResult.error,
        amount_refunded: amount,
        balance_after: user.wallet.balance + amount
      }, 500);
    }
    
  } catch (error) {
    await session.abortTransaction();
    console.error('Purchase API Error:', error);
    return apiResponse.error(res, 'Error processing purchase', {
      code: 'PROCESSING_ERROR',
      details: error.message
    }, 500);
  } finally {
    session.endSession();
  }
});

// =============================================
// 4. BULK PURCHASE API - DATAMART INTEGRATED
// =============================================

router.post('/v1/purchase/bulk', async (req, res) => {
  const session = await mongoose.startSession();
  session.startTransaction();
  
  try {
    const { orders, reference, callback_url } = req.body;
    
    // Validate input
    if (!orders || !Array.isArray(orders) || orders.length === 0) {
      await session.abortTransaction();
      return apiResponse.error(res, 'Orders array is required', {
        code: 'INVALID_ORDERS'
      });
    }
    
    if (orders.length > 100) {
      await session.abortTransaction();
      return apiResponse.error(res, 'Maximum 100 orders per request', {
        code: 'EXCEEDS_LIMIT',
        max_allowed: 100,
        provided: orders.length
      });
    }
    
    // Validate all orders first
    const validatedOrders = [];
    let totalAmount = 0;
    
    for (let i = 0; i < orders.length; i++) {
      const order = orders[i];
      
      // Validate MTN number
      if (!order.beneficiary_number?.match(/^(\+233|0)(24|25|53|54|55|59)[0-9]{7}$/)) {
        await session.abortTransaction();
        return apiResponse.error(res, `Invalid MTN phone number in order ${i + 1}`, {
          code: 'INVALID_PHONE_NUMBER',
          order_index: i,
          beneficiary: order.beneficiary_number,
          valid_prefixes: '024, 025, 053, 054, 055, 059'
        });
      }
      
      if (!order.capacity) {
        await session.abortTransaction();
        return apiResponse.error(res, `Missing capacity in order ${i + 1}`, {
          code: 'MISSING_CAPACITY',
          order_index: i
        });
      }
      
      if (!order.product_name) {
        await session.abortTransaction();
        return apiResponse.error(res, `Missing product name in order ${i + 1}`, {
          code: 'MISSING_PRODUCT_NAME',
          order_index: i
        });
      }
      
      const productResult = await findProductByCapacityAndName(order.capacity, order.product_name);
      
      if (productResult.error) {
        await session.abortTransaction();
        return apiResponse.error(res, `Order ${i + 1}: ${productResult.message}`, {
          code: productResult.code,
          order_index: i,
          ...productResult.details
        });
      }
      
      const product = productResult.product;
      
      const pricing = await PriceSetting.findOne({
        product: product._id,
        isActive: true
      });
      
      if (!pricing) {
        await session.abortTransaction();
        return apiResponse.error(res, `Pricing unavailable for order ${i + 1}`, {
          code: 'PRICING_UNAVAILABLE',
          order_index: i,
          product: product.name
        });
      }
      
      let unitPrice;
      switch (req.userRole) {
        case 'supplier': unitPrice = pricing.supplierPrice; break;
        case 'dealer': unitPrice = pricing.dealerPrice; break;
        case 'agent': unitPrice = pricing.agentPrice; break;
        default: unitPrice = pricing.agentPrice;
      }
      
      const quantity = order.quantity || 1;
      const orderAmount = unitPrice * quantity;
      totalAmount += orderAmount;
      
      validatedOrders.push({
        product: product,
        pricing: unitPrice,
        quantity: quantity,
        beneficiaryNumber: order.beneficiary_number,
        amount: orderAmount,
        reference: order.reference,
        requestedCapacity: order.capacity,
        requestedProductName: order.product_name
      });
    }
    
    // Check wallet balance for total
    const user = await User.findById(req.userId).session(session);
    if (user.wallet.balance < totalAmount) {
      await session.abortTransaction();
      return apiResponse.error(res, 'Insufficient wallet balance for bulk order', {
        code: 'INSUFFICIENT_BALANCE',
        required_amount: totalAmount,
        current_balance: user.wallet.balance,
        shortage: totalAmount - user.wallet.balance
      });
    }
    
    // Generate bulk reference
    const bulkReference = reference || 'BULK_API' + Date.now() + crypto.randomBytes(4).toString('hex').toUpperCase();
    const balanceBefore = user.wallet.balance;
    
    // Deduct total amount upfront
    user.wallet.balance -= totalAmount;
    await user.save({ session });
    
    // Create all transactions
    const createdTransactions = [];
    for (const orderDetail of validatedOrders) {
      const orderRef = orderDetail.reference || 
                      'API' + Date.now() + crypto.randomBytes(4).toString('hex').toUpperCase();
      
      const transaction = new Transaction({
        transactionId: orderRef,
        user: req.userId,
        type: 'data_purchase',
        dataDetails: {
          product: orderDetail.product._id,
          beneficiaryNumber: orderDetail.beneficiaryNumber,
          capacity: `${orderDetail.product.capacity.value}${orderDetail.product.capacity.unit}`,
          network: 'YELLO',
          quantity: orderDetail.quantity
        },
        amount: orderDetail.amount,
        status: 'pending',
        reference: orderRef,
        paymentMethod: 'wallet',
        channel: 'api',
        metadata: {
          bulkReference: bulkReference,
          apiKey: req.header('X-API-Key'),
          requestedCapacity: orderDetail.requestedCapacity,
          requestedProductName: orderDetail.requestedProductName,
          processingProvider: 'datamart'
        }
      });
      
      await transaction.save({ session });
      createdTransactions.push({ transaction, orderDetail, orderRef });
    }
    
    // Create wallet transaction for bulk
    await WalletTransaction.create([{
      user: req.userId,
      type: 'debit',
      amount: totalAmount,
      balanceBefore: balanceBefore,
      balanceAfter: user.wallet.balance,
      purpose: 'purchase',
      reference: bulkReference,
      status: 'completed',
      description: `Bulk API: ${validatedOrders.length} orders`
    }], { session });
    
    // Commit database transaction
    await session.commitTransaction();
    
    // Now process each order with DataMart
    const processedOrders = [];
    const failedOrders = [];
    let totalRefund = 0;
    
    for (const { transaction, orderDetail, orderRef } of createdTransactions) {
      const datamartResult = await processWithDatamart(
        orderDetail.beneficiaryNumber,
        orderDetail.requestedCapacity,
        orderRef
      );
      
      if (datamartResult.success) {
        await Transaction.findByIdAndUpdate(transaction._id, {
          status: 'completed',
          completedAt: new Date(),
          'metadata.datamartPurchaseId': datamartResult.purchaseId
        });
        
        processedOrders.push({
          reference: orderRef,
          transaction_id: transaction._id,
          product_name: orderDetail.product.name,
          capacity: orderDetail.requestedCapacity,
          beneficiary: orderDetail.beneficiaryNumber,
          quantity: orderDetail.quantity,
          amount: orderDetail.amount,
          status: 'completed',
          provider_reference: datamartResult.purchaseId
        });
      } else {
        await Transaction.findByIdAndUpdate(transaction._id, {
          status: 'failed',
          failureReason: datamartResult.error
        });
        
        totalRefund += orderDetail.amount;
        
        failedOrders.push({
          reference: orderRef,
          product_name: orderDetail.requestedProductName,
          capacity: orderDetail.requestedCapacity,
          beneficiary: orderDetail.beneficiaryNumber,
          amount: orderDetail.amount,
          error: datamartResult.error,
          status: 'failed'
        });
      }
      
      // Small delay between orders to avoid rate limiting
      await new Promise(resolve => setTimeout(resolve, 100));
    }
    
    // Refund failed orders
    if (totalRefund > 0) {
      await User.findByIdAndUpdate(req.userId, {
        $inc: { 'wallet.balance': totalRefund }
      });
      
      await WalletTransaction.create({
        user: req.userId,
        type: 'credit',
        amount: totalRefund,
        balanceBefore: user.wallet.balance,
        balanceAfter: user.wallet.balance + totalRefund,
        purpose: 'refund',
        reference: bulkReference + '_REFUND',
        status: 'completed',
        description: `Refund for ${failedOrders.length} failed orders in bulk ${bulkReference}`
      });
    }
    
    const finalBalance = user.wallet.balance + totalRefund;
    
    // Send webhook
    sendWebhook(user, 'bulk_purchase.completed', {
      bulk_reference: bulkReference,
      status: 'completed',
      summary: {
        total_orders: orders.length,
        successful_count: processedOrders.length,
        failed_count: failedOrders.length,
        total_requested_amount: totalAmount,
        amount_charged: totalAmount - totalRefund,
        amount_refunded: totalRefund
      },
      successful_orders: processedOrders,
      failed_orders: failedOrders,
      balance_after: finalBalance
    });
    
    if (callback_url) {
      axios.post(callback_url, {
        reference: bulkReference,
        status: 'completed',
        summary: {
          total: orders.length,
          successful: processedOrders.length,
          failed: failedOrders.length,
          amount_charged: totalAmount - totalRefund,
          amount_refunded: totalRefund
        }
      }).catch(err => console.error('Callback Error:', err));
    }
    
    return apiResponse.success(res, 'Bulk purchase processed', {
      bulk_reference: bulkReference,
      network: 'YELLO',
      summary: {
        total_orders: orders.length,
        successful_count: processedOrders.length,
        failed_count: failedOrders.length,
        total_requested: totalAmount,
        amount_charged: totalAmount - totalRefund,
        amount_refunded: totalRefund
      },
      successful_orders: processedOrders,
      failed_orders: failedOrders,
      balance_after: finalBalance,
      webhook_sent: !!user.apiAccess?.webhookUrl
    }, 201);
    
  } catch (error) {
    await session.abortTransaction();
    console.error('Bulk API Error:', error);
    return apiResponse.error(res, 'Error processing bulk purchase', {
      code: 'BULK_PROCESSING_ERROR',
      details: error.message
    }, 500);
  } finally {
    session.endSession();
  }
});

// =============================================
// 5. TRANSACTION STATUS API
// =============================================

router.get('/v1/transactions/:reference', async (req, res) => {
  try {
    const { reference } = req.params;
    
    const transaction = await Transaction.findOne({
      $or: [
        { transactionId: reference },
        { reference: reference }
      ],
      user: req.userId
    })
      .populate('dataDetails.product', 'name productCode capacity')
      .lean();
    
    if (!transaction) {
      return apiResponse.error(res, 'Transaction not found', {
        code: 'TRANSACTION_NOT_FOUND',
        reference: reference
      }, 404);
    }
    
    return apiResponse.success(res, 'Transaction retrieved', {
      reference: transaction.reference,
      transaction_id: transaction._id,
      status: transaction.status,
      network: 'YELLO',
      product: {
        name: transaction.dataDetails.product?.name,
        capacity: transaction.dataDetails.capacity
      },
      beneficiary: transaction.dataDetails.beneficiaryNumber,
      amount: transaction.amount,
      currency: 'GHS',
      provider_reference: transaction.metadata?.datamartPurchaseId,
      created_at: transaction.createdAt,
      completed_at: transaction.completedAt,
      failure_reason: transaction.failureReason
    });
  } catch (error) {
    console.error('Transaction Status Error:', error);
    return apiResponse.error(res, 'Error fetching transaction', {
      code: 'TRANSACTION_ERROR',
      details: error.message
    }, 500);
  }
});

router.get('/v1/transactions', async (req, res) => {
  try {
    const { status, start_date, end_date, page = 1, limit = 20 } = req.query;
    
    const filter = { user: req.userId, channel: 'api' };
    
    if (status) filter.status = status;
    if (start_date || end_date) {
      filter.createdAt = {};
      if (start_date) filter.createdAt.$gte = new Date(start_date);
      if (end_date) filter.createdAt.$lte = new Date(end_date);
    }
    
    const transactions = await Transaction.find(filter)
      .sort({ createdAt: -1 })
      .limit(parseInt(limit))
      .skip((parseInt(page) - 1) * parseInt(limit))
      .populate('dataDetails.product', 'name')
      .lean();
    
    const total = await Transaction.countDocuments(filter);
    
    const formattedTransactions = transactions.map(tx => ({
      reference: tx.reference,
      transaction_id: tx._id,
      product_name: tx.dataDetails.product?.name,
      capacity: tx.metadata?.requestedCapacity || tx.dataDetails.capacity,
      network: 'YELLO',
      beneficiary: tx.dataDetails.beneficiaryNumber,
      amount: tx.amount,
      status: tx.status,
      provider_reference: tx.metadata?.datamartPurchaseId,
      created_at: tx.createdAt,
      completed_at: tx.completedAt
    }));
    
    return apiResponse.success(res, 'Transactions retrieved', {
      transactions: formattedTransactions,
      pagination: {
        page: parseInt(page),
        limit: parseInt(limit),
        total: total,
        pages: Math.ceil(total / parseInt(limit))
      }
    });
  } catch (error) {
    console.error('Transactions List Error:', error);
    return apiResponse.error(res, 'Error fetching transactions', {
      code: 'TRANSACTION_ERROR',
      details: error.message
    }, 500);
  }
});

// =============================================
// 6. WEBHOOK CONFIGURATION
// =============================================

router.put('/v1/webhook', async (req, res) => {
  try {
    const { webhook_url } = req.body;
    
    if (!webhook_url) {
      return apiResponse.error(res, 'Webhook URL is required', {
        code: 'MISSING_WEBHOOK_URL'
      });
    }
    
    try {
      new URL(webhook_url);
    } catch (err) {
      return apiResponse.error(res, 'Invalid webhook URL format', {
        code: 'INVALID_URL',
        provided: webhook_url
      });
    }
    
    await User.findByIdAndUpdate(req.userId, {
      'apiAccess.webhookUrl': webhook_url
    });
    
    try {
      const user = await User.findById(req.userId).select('apiAccess');
      
      const testPayload = {
        event: 'webhook.test',
        data: {
          message: 'Webhook configured successfully',
          supported_network: 'YELLO (MTN)',
          timestamp: new Date().toISOString()
        },
        timestamp: new Date().toISOString()
      };
      
      const headers = {
        'Content-Type': 'application/json',
        'X-Platform-Event': 'webhook.test'
      };
      
      if (user.apiAccess?.apiSecret) {
        testPayload.signature = crypto
          .createHmac('sha256', user.apiAccess.apiSecret)
          .update(JSON.stringify(testPayload.data))
          .digest('hex');
        headers['X-Platform-Signature'] = testPayload.signature;
      }
      
      await axios.post(webhook_url, testPayload, { headers, timeout: 5000 });
      
      return apiResponse.success(res, 'Webhook configured and tested', {
        webhook_url: webhook_url,
        test_status: 'successful',
        signature_enabled: !!user.apiAccess?.apiSecret
      });
    } catch (error) {
      return apiResponse.success(res, 'Webhook configured but test failed', {
        webhook_url: webhook_url,
        test_status: 'failed',
        test_error: error.message,
        note: 'Webhook will still work - ensure your endpoint is accessible'
      });
    }
  } catch (error) {
    console.error('Webhook Config Error:', error);
    return apiResponse.error(res, 'Error updating webhook', {
      code: 'WEBHOOK_ERROR',
      details: error.message
    }, 500);
  }
});

router.post('/v1/webhook/test', async (req, res) => {
  try {
    const user = await User.findById(req.userId);
    
    if (!user.apiAccess?.webhookUrl) {
      return apiResponse.error(res, 'No webhook URL configured', {
        code: 'NO_WEBHOOK'
      });
    }
    
    await sendWebhook(user, 'webhook.test', {
      message: 'This is a test webhook',
      supported_network: 'YELLO (MTN)',
      timestamp: new Date().toISOString()
    });
    
    return apiResponse.success(res, 'Test webhook sent', {
      webhook_url: user.apiAccess.webhookUrl,
      signature_enabled: !!user.apiAccess?.apiSecret,
      note: 'Check your webhook endpoint for the test event'
    });
  } catch (error) {
    console.error('Webhook Test Error:', error);
    return apiResponse.error(res, 'Error sending test webhook', {
      code: 'WEBHOOK_ERROR',
      details: error.message
    }, 500);
  }
});

// =============================================
// 7. API STATISTICS
// =============================================

router.get('/v1/statistics', async (req, res) => {
  try {
    const { period = '7days' } = req.query;
    
    let startDate;
    switch (period) {
      case '24hours': startDate = new Date(Date.now() - 24 * 60 * 60 * 1000); break;
      case '7days': startDate = new Date(Date.now() - 7 * 24 * 60 * 60 * 1000); break;
      case '30days': startDate = new Date(Date.now() - 30 * 24 * 60 * 60 * 1000); break;
      default: startDate = new Date(Date.now() - 7 * 24 * 60 * 60 * 1000);
    }
    
    const apiStats = await ApiLog.aggregate([
      {
        $match: {
          user: mongoose.Types.ObjectId(req.userId),
          createdAt: { $gte: startDate }
        }
      },
      {
        $group: {
          _id: null,
          total_requests: { $sum: 1 },
          successful_requests: { $sum: { $cond: [{ $eq: ['$success', true] }, 1, 0] } },
          failed_requests: { $sum: { $cond: [{ $eq: ['$success', false] }, 1, 0] } },
          avg_response_time: { $avg: '$response.responseTime' }
        }
      }
    ]);
    
    const transactionStats = await Transaction.aggregate([
      {
        $match: {
          user: mongoose.Types.ObjectId(req.userId),
          channel: 'api',
          createdAt: { $gte: startDate }
        }
      },
      {
        $group: {
          _id: '$status',
          count: { $sum: 1 },
          total_amount: { $sum: '$amount' }
        }
      }
    ]);
    
    const formattedStats = {
      api_usage: apiStats[0] || {
        total_requests: 0,
        successful_requests: 0,
        failed_requests: 0,
        avg_response_time: 0
      },
      transactions: {
        completed: 0,
        failed: 0,
        pending: 0,
        total_amount: 0
      },
      supported_network: 'YELLO (MTN)'
    };
    
    transactionStats.forEach(stat => {
      formattedStats.transactions[stat._id] = stat.count;
      formattedStats.transactions.total_amount += stat.total_amount;
    });
    
    return apiResponse.success(res, 'Statistics retrieved', {
      period: period,
      statistics: formattedStats
    });
  } catch (error) {
    console.error('Statistics Error:', error);
    return apiResponse.error(res, 'Error fetching statistics', {
      code: 'STATISTICS_ERROR',
      details: error.message
    }, 500);
  }
});

// =============================================
// ERROR HANDLING
// =============================================

router.use((req, res) => {
  return apiResponse.error(res, 'API endpoint not found', {
    code: 'ENDPOINT_NOT_FOUND',
    endpoint: req.originalUrl,
    method: req.method,
    supported_network: 'YELLO (MTN)',
    available_endpoints: [
      'GET /v1/account',
      'GET /v1/balance',
      'GET /v1/products',
      'POST /v1/purchase',
      'POST /v1/purchase/bulk',
      'GET /v1/transactions/:reference',
      'GET /v1/transactions',
      'PUT /v1/webhook',
      'POST /v1/webhook/test',
      'GET /v1/statistics'
    ]
  }, 404);
});

router.use((error, req, res, next) => {
  console.error('API Global Error:', error);
  return apiResponse.error(res, 'Internal server error', {
    code: 'INTERNAL_ERROR',
    message: process.env.NODE_ENV === 'development' ? error.message : 'An unexpected error occurred'
  }, 500);
});

module.exports = router; 