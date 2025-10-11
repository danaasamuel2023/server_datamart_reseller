// =============================================
// EXTERNAL API ROUTES - GHANA MTN DATA PLATFORM
// COMPLETE - Fixed bulk orders + webhook status updates + OPTIONAL SIGNATURE
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
    
    // Only add signature if apiSecret exists (OPTIONAL)
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

// Function to send transaction status update
const sendTransactionStatusWebhook = async (userId, transactionData) => {
  try {
    const user = await User.findById(userId).select('apiAccess');
    if (!user || !user.apiAccess?.webhookUrl) return;
    
    await sendWebhook(user, 'transaction.status_update', transactionData);
  } catch (error) {
    console.error('Transaction webhook error:', error.message);
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
      }
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
          case 'supplier':
            price = pricing.supplierPrice;
            break;
          case 'dealer':
            price = pricing.dealerPrice;
            break;
          case 'agent':
            price = pricing.agentPrice;
            break;
          default:
            price = pricing.agentPrice;
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
          status: product.status
        };
      })
    );
    
    const validProducts = productsWithPricing.filter(p => p !== null);
    
    return apiResponse.success(res, 'Products retrieved', {
      products: validProducts,
      total: validProducts.length
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
// 3. SINGLE PURCHASE API - WITH WEBHOOK STATUS
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
    
    if (!beneficiary_number.match(/^(\+233|0)[235][0-9]{8}$/)) {
      await session.abortTransaction();
      return apiResponse.error(res, 'Invalid Ghana phone number', {
        code: 'INVALID_PHONE_NUMBER',
        format: 'Valid format: 0241234567 or +233241234567',
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
    
    // Calculate price
    let amount;
    switch (req.userRole) {
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
    
    // Create transaction
    const transaction = new Transaction({
      transactionId: transactionRef,
      user: req.userId,
      type: 'data_purchase',
      dataDetails: {
        product: product._id,
        beneficiaryNumber: beneficiary_number,
        capacity: `${product.capacity.value}${product.capacity.unit}`,
        network: 'MTN'
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
        requestedProductName: product_name
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
    
    await session.commitTransaction();
    
    // Send webhook with transaction status (signature optional)
    sendWebhook(user, 'transaction.created', {
      reference: transactionRef,
      transaction_id: transaction._id,
      status: 'pending',
      product: {
        name: product.name,
        capacity: capacity
      },
      beneficiary: beneficiary_number,
      amount: amount,
      balance_after: user.wallet.balance,
      created_at: transaction.createdAt
    });
    
    // Send callback
    if (callback_url) {
      axios.post(callback_url, {
        reference: transactionRef,
        status: 'pending',
        message: 'Data purchase pending manual processing',
        transaction_id: transaction._id
      }).catch(err => console.error('Callback Error:', err));
    }
    
    return apiResponse.success(res, 'Purchase successful - pending manual processing', {
      reference: transactionRef,
      transaction_id: transaction._id,
      product: {
        name: product.name,
        capacity: capacity,
        validity: `${product.validity.value} ${product.validity.unit}`,
        product_code: product.productCode
      },
      beneficiary: beneficiary_number,
      amount: amount,
      price_tier: req.userRole,
      currency: 'GHS',
      status: 'pending',
      balance_after: user.wallet.balance,
      webhook_sent: !!user.apiAccess?.webhookUrl
    }, 201);
    
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
// 4. BULK PURCHASE API - FIXED + WEBHOOK STATUS
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
    
    // Validate all orders
    const validatedOrders = [];
    let totalAmount = 0;
    
    for (let i = 0; i < orders.length; i++) {
      const order = orders[i];
      
      if (!order.beneficiary_number?.match(/^(\+233|0)[235][0-9]{8}$/)) {
        await session.abortTransaction();
        return apiResponse.error(res, `Invalid phone number in order ${i + 1}`, {
          code: 'INVALID_PHONE_NUMBER',
          order_index: i,
          beneficiary: order.beneficiary_number
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
    
    // Check wallet balance
    const user = await User.findById(req.userId).session(session);
    if (user.wallet.balance < totalAmount) {
      await session.abortTransaction();
      return apiResponse.error(res, 'Insufficient wallet balance', {
        code: 'INSUFFICIENT_BALANCE',
        required_amount: totalAmount,
        current_balance: user.wallet.balance,
        shortage: totalAmount - user.wallet.balance
      });
    }
    
    // Generate bulk reference
    const bulkReference = reference || 'BULK_API' + Date.now() + crypto.randomBytes(4).toString('hex').toUpperCase();
    const balanceBefore = user.wallet.balance;
    
    const processedOrders = [];
    const failedOrders = [];
    let actualAmountCharged = 0;
    
    // Process each order
    for (const orderDetail of validatedOrders) {
      const orderRef = orderDetail.reference || 
                      'API' + Date.now() + crypto.randomBytes(4).toString('hex').toUpperCase();
      
      try {
        const transaction = new Transaction({
          transactionId: orderRef,
          user: req.userId,
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
          channel: 'api',
          metadata: {
            bulkReference: bulkReference,
            apiKey: req.header('X-API-Key'),
            requestedCapacity: orderDetail.requestedCapacity,
            requestedProductName: orderDetail.requestedProductName
          }
        });
        
        await transaction.save({ session });
        
        // TODO: Call MTN API
        const mtnSuccess = true;
        
        if (mtnSuccess) {
          if (orderDetail.product.stats) {
            orderDetail.product.stats.totalSold = (orderDetail.product.stats.totalSold || 0) + orderDetail.quantity;
            orderDetail.product.stats.totalRevenue = (orderDetail.product.stats.totalRevenue || 0) + orderDetail.amount;
            await orderDetail.product.save({ session });
          }
          
          actualAmountCharged += orderDetail.amount;
          
          processedOrders.push({
            reference: orderRef,
            transaction_id: transaction._id,
            product_name: orderDetail.product.name,
            capacity: orderDetail.requestedCapacity,
            beneficiary: orderDetail.beneficiaryNumber,
            quantity: orderDetail.quantity,
            amount: orderDetail.amount,
            status: 'pending'
          });
        } else {
          throw new Error('MTN processing failed');
        }
        
      } catch (error) {
        failedOrders.push({
          product_name: orderDetail.requestedProductName,
          capacity: orderDetail.requestedCapacity,
          beneficiary: orderDetail.beneficiaryNumber,
          amount: orderDetail.amount,
          error: error.message,
          status: 'failed'
        });
      }
    }
    
    // Only deduct for successful orders
    if (actualAmountCharged > 0) {
      user.wallet.balance -= actualAmountCharged;
      await user.save({ session });
      
      await WalletTransaction.create([{
        user: req.userId,
        type: 'debit',
        amount: actualAmountCharged,
        balanceBefore: balanceBefore,
        balanceAfter: user.wallet.balance,
        purpose: 'purchase',
        reference: bulkReference,
        status: 'completed',
        description: `Bulk API: ${processedOrders.length} success, ${failedOrders.length} failed`
      }], { session });
    }
    
    // Only commit if at least one succeeded
    if (processedOrders.length > 0) {
      await session.commitTransaction();
      
      // Send webhook with detailed status (signature optional)
      sendWebhook(user, 'bulk_purchase.completed', {
        bulk_reference: bulkReference,
        status: 'completed',
        summary: {
          total_orders: orders.length,
          successful_count: processedOrders.length,
          failed_count: failedOrders.length,
          total_requested_amount: totalAmount,
          amount_charged: actualAmountCharged,
          amount_saved: totalAmount - actualAmountCharged
        },
        successful_orders: processedOrders,
        failed_orders: failedOrders,
        balance_after: user.wallet.balance,
        created_at: new Date()
      });
      
      if (callback_url) {
        axios.post(callback_url, {
          reference: bulkReference,
          status: 'completed',
          summary: {
            total: orders.length,
            successful: processedOrders.length,
            failed: failedOrders.length,
            amount_charged: actualAmountCharged
          }
        }).catch(err => console.error('Callback Error:', err));
      }
      
      return apiResponse.success(res, 'Bulk purchase processed', {
        bulk_reference: bulkReference,
        summary: {
          total_orders: orders.length,
          successful_count: processedOrders.length,
          failed_count: failedOrders.length,
          total_requested: totalAmount,
          amount_charged: actualAmountCharged,
          amount_saved: totalAmount - actualAmountCharged
        },
        successful_orders: processedOrders,
        failed_orders: failedOrders,
        balance_after: user.wallet.balance,
        webhook_sent: !!user.apiAccess?.webhookUrl
      }, 201);
    } else {
      await session.abortTransaction();
      return apiResponse.error(res, 'All orders failed to process', {
        code: 'ALL_ORDERS_FAILED',
        failed_orders: failedOrders,
        balance_unchanged: balanceBefore
      }, 400);
    }
    
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
      product: {
        name: transaction.dataDetails.product?.name,
        capacity: transaction.dataDetails.capacity
      },
      beneficiary: transaction.dataDetails.beneficiaryNumber,
      amount: transaction.amount,
      currency: 'GHS',
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
    const { 
      status, 
      start_date, 
      end_date, 
      page = 1, 
      limit = 20 
    } = req.query;
    
    const filter = {
      user: req.userId,
      channel: 'api'
    };
    
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
      beneficiary: tx.dataDetails.beneficiaryNumber,
      amount: tx.amount,
      status: tx.status,
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
          timestamp: new Date().toISOString()
        },
        timestamp: new Date().toISOString()
      };
      
      const headers = {
        'Content-Type': 'application/json',
        'X-Platform-Event': 'webhook.test'
      };
      
      // Add signature if apiSecret exists
      if (user.apiAccess?.apiSecret) {
        testPayload.signature = crypto
          .createHmac('sha256', user.apiAccess.apiSecret)
          .update(JSON.stringify(testPayload.data))
          .digest('hex');
        headers['X-Platform-Signature'] = testPayload.signature;
      }
      
      await axios.post(webhook_url, testPayload, { 
        headers,
        timeout: 5000 
      });
      
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
          successful_requests: {
            $sum: { $cond: [{ $eq: ['$success', true] }, 1, 0] }
          },
          failed_requests: {
            $sum: { $cond: [{ $eq: ['$success', false] }, 1, 0] }
          },
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
        successful: 0,
        failed: 0,
        pending: 0,
        total_amount: 0
      }
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