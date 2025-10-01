// =============================================
// GHANA MTN DATA RESELLING PLATFORM - MAIN SCHEMA
// WITH PORTAL ID TRACKING INTEGRATION
// File: schema/schema.js
// =============================================

const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');

// =============================================
// 1. USER SCHEMA (Admin, Suppliers, Dealers, Agents)
// =============================================

const userSchema = new mongoose.Schema({
  // Basic Info
  fullName: {
    type: String,
    required: true,
    trim: true
  },
  email: {
    type: String,
    required: true,
    unique: true,
    lowercase: true,
    trim: true
  },
  phone: {
    type: String,
    required: true,
    unique: true,
    trim: true,
    match: [/^(\+233|0)[235][0-9]{8}$/, 'Invalid Ghana phone number']
  },
  password: {
    type: String,
    required: true,
    minlength: 6
  },
  
  // Role Management
  role: {
    type: String,
    enum: ['admin', 'supplier', 'dealer', 'agent'],
    required: true
  },
  
  // Account Status
  status: {
    type: String,
    enum: ['active', 'suspended', 'pending'],
    default: 'pending'
  },
  
  // Wallet
  wallet: {
    balance: {
      type: Number,
      default: 0,
      min: 0
    },
    currency: {
      type: String,
      default: 'GHS'
    },
    locked: {
      type: Boolean,
      default: false
    }
  },
  
  // API Access for integration
  apiAccess: {
    enabled: {
      type: Boolean,
      default: false
    },
    apiKey: String,
    apiSecret: String,
    webhookUrl: String,
    rateLimit: {
      type: Number,
      default: 100
    },
    requestCount: {
      type: Number,
      default: 0
    },
    lastUsed: Date,
    createdAt: Date,
    regeneratedAt: Date,
    revokedAt: Date
  },
  
  // Timestamps
  lastLogin: Date,
  createdBy: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'reseller_users'
  },
  deletedAt: Date
}, {
  timestamps: true
});

// Create indexes
userSchema.index({ email: 1 });
userSchema.index({ phone: 1 });
userSchema.index({ role: 1, status: 1 });

// Password hashing middleware
userSchema.pre('save', async function(next) {
  if (!this.isModified('password')) return next();
  this.password = await bcrypt.hash(this.password, 10);
  next();
});

// Password comparison method
userSchema.methods.comparePassword = async function(candidatePassword) {
  return await bcrypt.compare(candidatePassword, this.password);
};

// =============================================
// 2. MTN PRODUCT SCHEMA (Data Bundles)
// =============================================

const productSchema = new mongoose.Schema({
  // Product Info
  name: {
    type: String,
    required: true
  },
  productCode: {
    type: String,
    required: true,
    unique: true
  },
  
  // Data Capacity
  capacity: {
    value: {
      type: Number,
      required: true
    },
    unit: {
      type: String,
      enum: ['MB', 'GB'],
      required: true
    }
  },
  
  // Validity Period
  validity: {
    value: {
      type: Number,
      required: true
    },
    unit: {
      type: String,
      enum: ['hours', 'days', 'weeks', 'months'],
      default: 'days'
    }
  },
  
  // Category
  category: {
    type: String,
    enum: ['daily', 'weekly', 'monthly', 'midnight', 'special'],
    default: 'daily'
  },
  
  // Description and features
  description: String,
  features: [String],
  
  // Product Status
  status: {
    type: String,
    enum: ['active', 'inactive'],
    default: 'active'
  },
  
  // Pricing (populated from PriceSetting)
  pricing: [{
    role: String,
    price: Number
  }],
  
  // Statistics
  stats: {
    totalSold: {
      type: Number,
      default: 0
    },
    totalRevenue: {
      type: Number,
      default: 0
    }
  },
  
  // Added by Admin
  createdBy: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'reseller_users',
    required: true
  },
  lastModifiedBy: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'reseller_users'
  }
}, {
  timestamps: true
});

productSchema.index({ productCode: 1 });
productSchema.index({ status: 1 });
productSchema.index({ category: 1 });

// =============================================
// 3. TRANSACTION SCHEMA - WITH PORTAL TRACKING
// =============================================

const transactionSchema = new mongoose.Schema({
  // Transaction ID (6-digit reference)
  transactionId: {
    type: String,
    required: true,
    unique: true
  },
  
  // User who made the purchase
  user: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'reseller_users',
    required: true
  },
  
  // Transaction Type
  type: {
    type: String,
    enum: ['data_purchase', 'wallet_funding', 'withdrawal'],
    required: true
  },
  
  // Data Purchase Details
  dataDetails: {
    product: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'Product_reseller'
    },
    beneficiaryNumber: {
      type: String,
      required: function() { return this.type === 'data_purchase'; },
      match: [/^(\+233|0)[235][0-9]{8}$/, 'Invalid Ghana phone number']
    },
    capacity: String,
    network: {
      type: String,
      default: 'MTN'
    },
    quantity: {
      type: Number,
      default: 1
    }
  },
  
  // Amount in GHS
  amount: {
    type: Number,
    required: true,
    min: 0
  },
  
  // Wallet balances
  balanceBefore: Number,
  balanceAfter: Number,
  
  // Status - Added 'sent' to enum
  status: {
    type: String,
    enum: ['pending', 'sent', 'processing', 'successful', 'failed', 'reversed'],
    default: 'pending'
  },
  
  // Payment Method
  paymentMethod: {
    type: String,
    enum: ['wallet', 'card', 'mobile_money'],
    default: 'wallet'
  },
  
  // Reference (6-digit)
  reference: {
    type: String,
    unique: true,
    sparse: true
  },
  
  // ENHANCED METADATA WITH PORTAL TRACKING
  metadata: {
    // Export tracking
    exportId: {
      type: String,
      index: true
    },
    batchId: {
      type: String,
      index: true
    },
    batchPage: Number,
    bulkReference: String,
    
    // Portal tracking
    portalId: {
      type: String,
      index: true
    },
    portalSubmittedAt: Date,
    portalCompletedAt: Date,
    portalStatus: {
      type: String,
      enum: ['pending', 'submitted', 'processing', 'completed', 'failed']
    },
    
    // Processing info
    estimatedCompletion: Date,
    processingMinutes: Number,
    
    // Export readiness
    exportReady: {
      type: Boolean,
      default: true
    },
    exportedInBatch: Number,
    
    // Additional tracking
    note: String,
    isReExport: Boolean
  },
  
  // Export tracking fields
  exportedAt: Date,
  
  // Status update tracking
  statusUpdatedBy: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'reseller_users'
  },
  statusUpdatedAt: Date,
  statusUpdateReason: String,
  
  // Error tracking
  failureReason: String,
  
  // Reversal tracking
  reversedAt: Date,
  reversedBy: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'reseller_users'
  },
  
  // Notes
  notes: String,
  
  // Timestamps
  processedAt: Date,
  completedAt: Date
}, {
  timestamps: true
});

// Indexes for better query performance
transactionSchema.index({ transactionId: 1 });
transactionSchema.index({ user: 1, createdAt: -1 });
transactionSchema.index({ status: 1 });
transactionSchema.index({ type: 1 });
transactionSchema.index({ 'dataDetails.beneficiaryNumber': 1 });
transactionSchema.index({ 'metadata.exportId': 1 });
transactionSchema.index({ 'metadata.batchId': 1 });
transactionSchema.index({ 'metadata.portalId': 1 });
transactionSchema.index({ status: 1, 'metadata.exportId': 1 });
transactionSchema.index({ 'metadata.exportReady': 1, status: 1 });

// Auto-generate transaction ID
transactionSchema.pre('save', function(next) {
  if (!this.transactionId) {
    // Generate 6-digit ID
    this.transactionId = Math.floor(100000 + Math.random() * 900000).toString();
  }
  if (!this.reference) {
    this.reference = this.transactionId;
  }
  next();
});

// =============================================
// 4. PRICE SETTING SCHEMA
// =============================================

const priceSettingSchema = new mongoose.Schema({
  product: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Product_reseller',
    required: true
  },
  
  // Base cost price (what platform pays to MTN)
  costPrice: {
    type: Number,
    required: true,
    min: 0
  },
  
  // Prices for different roles
  agentPrice: {
    type: Number,
    required: true,
    min: 0
  },
  dealerPrice: {
    type: Number,
    required: true,
    min: 0
  },
  supplierPrice: {
    type: Number,
    required: true,
    min: 0
  },
  
  // Status
  isActive: {
    type: Boolean,
    default: true
  },
  
  // Set by admin
  setBy: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'reseller_users',
    required: true
  },
  
  // Effective dates
  effectiveFrom: {
    type: Date,
    default: Date.now
  },
  effectiveTo: Date
}, {
  timestamps: true
});

priceSettingSchema.index({ product: 1, isActive: 1 });
priceSettingSchema.index({ effectiveFrom: 1, effectiveTo: 1 });

// =============================================
// 5. WALLET TRANSACTION SCHEMA
// =============================================

const walletTransactionSchema = new mongoose.Schema({
  user: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'reseller_users',
    required: true
  },
  
  type: {
    type: String,
    enum: ['credit', 'debit'],
    required: true
  },
  
  amount: {
    type: Number,
    required: true,
    min: 0
  },
  
  balanceBefore: Number,
  balanceAfter: Number,
  
  purpose: {
    type: String,
    enum: ['funding', 'purchase', 'refund', 'withdrawal', 'commission', 'adjustment', 'reprocess_charge', 'bulk_reprocess'],
    required: true
  },
  
  reference: {
    type: String,
    unique: true,
    required: true
  },
  
  status: {
    type: String,
    enum: ['pending', 'completed', 'failed'],
    default: 'pending'
  },
  
  description: String,
  
  // Related transaction if any
  relatedTransaction: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Transaction_reseller'
  },
  
  // Metadata for bulk operations
  metadata: {
    transactionIds: [String],
    count: Number,
    bulkReference: String
  },
  
  // Admin tracking
  createdBy: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'reseller_users'
  }
}, {
  timestamps: true
});

walletTransactionSchema.index({ user: 1, createdAt: -1 });
walletTransactionSchema.index({ reference: 1 });
walletTransactionSchema.index({ status: 1 });

// =============================================
// 6. SYSTEM SETTINGS SCHEMA
// =============================================

const systemSettingSchema = new mongoose.Schema({
  key: {
    type: String,
    required: true,
    unique: true
  },
  value: mongoose.Schema.Types.Mixed,
  description: String,
  category: {
    type: String,
    enum: ['general', 'maintenance', 'api', 'payment', 'export'],
    required: true
  },
  lastModifiedBy: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'reseller_users'
  }
}, {
  timestamps: true
});

// Default settings
const defaultSettings = [
  {
    key: 'maintenance_mode',
    value: false,
    category: 'maintenance',
    description: 'System maintenance mode'
  },
  {
    key: 'user_registration',
    value: true,
    category: 'general',
    description: 'Allow new user registration'
  },
  {
    key: 'min_wallet_funding',
    value: 10,
    category: 'payment',
    description: 'Minimum wallet funding amount in GHS'
  },
  {
    key: 'max_wallet_funding',
    value: 10000,
    category: 'payment',
    description: 'Maximum wallet funding amount in GHS'
  },
  {
    key: 'mtn_api_url',
    value: 'https://api.mtn.com.gh/data',
    category: 'api',
    description: 'MTN API endpoint'
  },
  {
    key: 'mtn_api_key',
    value: '',
    category: 'api',
    description: 'MTN API key'
  },
  {
    key: 'max_orders_per_export',
    value: 40,
    category: 'export',
    description: 'Maximum orders per export batch'
  }
];

// =============================================
// 7. API REQUEST LOG SCHEMA
// =============================================

const apiLogSchema = new mongoose.Schema({
  user: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'reseller_users',
    required: true
  },
  
  apiKey: String,
  endpoint: String,
  method: String,
  
  request: {
    body: Object,
    headers: Object,
    ip: String
  },
  
  response: {
    statusCode: Number,
    body: Object,
    responseTime: Number // milliseconds
  },
  
  success: Boolean,
  errorMessage: String,
  
  ipAddress: String
}, {
  timestamps: true
});

apiLogSchema.index({ user: 1, createdAt: -1 });
apiLogSchema.index({ apiKey: 1 });
apiLogSchema.index({ success: 1 });

// =============================================
// 8. NOTIFICATION SCHEMA
// =============================================

const notificationSchema = new mongoose.Schema({
  user: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'reseller_users',
    required: true
  },
  
  title: {
    type: String,
    required: true
  },
  
  message: {
    type: String,
    required: true
  },
  
  type: {
    type: String,
    enum: ['info', 'success', 'warning', 'error'],
    default: 'info'
  },
  
  category: {
    type: String,
    enum: ['transaction', 'wallet', 'system', 'promotion', 'export', 'portal'],
    default: 'system'
  },
  
  read: {
    type: Boolean,
    default: false
  },
  
  readAt: Date,
  
  relatedTransaction: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Transaction_reseller'
  },
  
  relatedBatch: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Batch_reseller'
  },
  
  metadata: Object
}, {
  timestamps: true
});

notificationSchema.index({ user: 1, read: 1 });
notificationSchema.index({ createdAt: -1 });

// =============================================
// 9. BATCH SCHEMA - WITH PORTAL TRACKING
// =============================================

const batchSchema = new mongoose.Schema({
  batchId: {
    type: String,
    required: true,
    unique: true
  },
  
  batchNumber: {
    type: Number,
    required: true
  },
  
  // Export details
  exportedBy: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'reseller_users',
    required: true
  },
  
  exportDate: {
    type: Date,
    default: Date.now
  },
  
  // Processing status
  processingStatus: {
    type: String,
    enum: ['exported', 'sent_to_third_party', 're-exported'],
    default: 'exported'
  },
  
  // Orders in this batch
  orders: [{
    transactionId: String,
    beneficiaryNumber: String,
    capacity: String,
    amount: Number,
    status: String,
    userName: String,
    userId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'reseller_users'
    }
  }],
  
  // Batch statistics
  stats: {
    totalOrders: {
      type: Number,
      default: 0
    },
    processedOrders: {
      type: Number,
      default: 0
    },
    failedOrders: {
      type: Number,
      default: 0
    },
    totalAmount: {
      type: Number,
      default: 0
    },
    originalStatus: {
      type: String,
      enum: ['pending', 'successful', 'failed']
    },
    markedAsSuccessful: {
      type: Boolean,
      default: false
    }
  },
  
  // PORTAL TRACKING
  portalTracking: {
    portalId: {
      type: String,
      index: true,
      unique: true,
      sparse: true // Allows null but ensures uniqueness when set
    },
    enteredBy: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'reseller_users'
    },
    enteredAt: Date,
    estimatedCompletionTime: Date,
    actualCompletionTime: Date,
    status: {
      type: String,
      enum: ['pending', 'submitted', 'processing', 'completed', 'failed'],
      default: 'pending'
    },
    notes: String,
    lastUpdated: Date,
    lastUpdatedBy: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'reseller_users'
    },
    updateHistory: [{
      status: String,
      notes: String,
      updatedBy: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'reseller_users'
      },
      updatedAt: Date
    }]
  },
  
  // Metadata for batch details
  metadata: {
    batchPage: Number,
    totalBatches: Number,
    ordersPerBatch: Number,
    isPartialBatch: Boolean,
    hasMoreBatches: Boolean,
    isReExport: Boolean,
    originalBatchId: String,
    limitApplied: Boolean
  },
  
  // File details
  fileName: String,
  fileUrl: String,
  
  // Status
  status: {
    type: String,
    enum: ['exported', 'processing', 'completed', 'partial'],
    default: 'exported'
  },
  
  notes: String
}, {
  timestamps: true
});

// Indexes
batchSchema.index({ batchId: 1 });
batchSchema.index({ exportedBy: 1 });
batchSchema.index({ exportDate: -1 });
batchSchema.index({ 'portalTracking.portalId': 1 });
batchSchema.index({ 'portalTracking.status': 1 });

// =============================================
// SAFE MODEL CREATION - PREVENTS OVERWRITE ERROR
// =============================================

const User = mongoose.models['reseller_users'] || mongoose.model('reseller_users', userSchema);
const Product = mongoose.models['Product_reseller'] || mongoose.model('Product_reseller', productSchema);
const Transaction = mongoose.models['Transaction_reseller'] || mongoose.model('Transaction_reseller', transactionSchema);
const PriceSetting = mongoose.models['PriceSetting_reseller'] || mongoose.model('PriceSetting_reseller', priceSettingSchema);
const WalletTransaction = mongoose.models['WalletTransaction_reseller'] || mongoose.model('WalletTransaction_reseller', walletTransactionSchema);
const SystemSetting = mongoose.models['SystemSetting'] || mongoose.model('SystemSetting', systemSettingSchema);
const ApiLog = mongoose.models['ApiLog'] || mongoose.model('ApiLog', apiLogSchema);
const Notification = mongoose.models['Notification'] || mongoose.model('Notification', notificationSchema);
const Batch = mongoose.models['Batch_reseller'] || mongoose.model('Batch_reseller', batchSchema);

// =============================================
// EXPORT MODELS
// =============================================

module.exports = {
  User,
  Product,
  Transaction,
  PriceSetting,
  WalletTransaction,
  SystemSetting,
  ApiLog,
  Notification,
  Batch,
  defaultSettings
};