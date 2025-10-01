// =============================================
// GHANA MTN DATA RESELLING PLATFORM - EXPORT SCHEMAS
// EXPORT MANAGEMENT & SYSTEM STATUS SCHEMAS
// File: EXPORTSchema/schema.js
// =============================================

const mongoose = require('mongoose');

// =============================================
// IMPORT CORE MODELS FROM MAIN SCHEMA
// =============================================

// Import all core models from the main schema file
// This prevents duplicate model definitions
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
  defaultSettings
} = require('../schema/schema');

// =============================================
// EXPORT-SPECIFIC SCHEMAS
// =============================================

// =============================================
// 1. EXPORT SETTINGS SCHEMA
// =============================================

const exportSettingsSchema = new mongoose.Schema({
  settingName: {
    type: String,
    required: true,
    unique: true
  },
  
  isActive: {
    type: Boolean,
    default: false
  },
  
  // Export limits configuration
  exportLimits: {
    maxOrdersPerBatch: {
      type: Number,
      default: 40
    },
    maxBatchesPerDay: {
      type: Number,
      default: 100
    },
    cooldownMinutes: {
      type: Number,
      default: 5
    }
  },
  
  // Time settings for processing phases
  timeSettings: {
    phases: {
      initial: {
        duration: {
          type: Number,
          default: 5
        },
        unit: {
          type: String,
          default: 'minutes'
        },
        message: {
          type: String,
          default: 'Orders received and being prepared for processing...'
        }
      },
      processing: {
        duration: {
          type: Number,
          default: 15
        },
        unit: {
          type: String,
          default: 'minutes'
        },
        message: {
          type: String,
          default: 'Orders are being processed by MTN system...'
        }
      },
      finalizing: {
        duration: {
          type: Number,
          default: 10
        },
        unit: {
          type: String,
          default: 'minutes'
        },
        message: {
          type: String,
          default: 'Finalizing your orders. Almost complete...'
        }
      }
    },
    totalProcessingMinutes: {
      type: Number,
      default: 30
    },
    bufferMinutes: {
      type: Number,
      default: 5
    }
  },
  
  // User-facing messages
  messages: {
    beforeExport: {
      type: String,
      default: 'Preparing to export orders to processing system...'
    },
    exportSuccess: {
      type: String,
      default: 'Your orders have been successfully sent to MTN for processing.'
    },
    stages: {
      queued: {
        title: {
          type: String,
          default: 'Queued for Processing'
        },
        description: {
          type: String,
          default: 'Your orders are in the queue and will be processed shortly.'
        },
        icon: {
          type: String,
          default: 'clock'
        }
      },
      sent: {
        title: {
          type: String,
          default: 'Sent to MTN'
        },
        description: {
          type: String,
          default: 'Orders have been transmitted to MTN processing system.'
        },
        icon: {
          type: String,
          default: 'send'
        }
      },
      processing: {
        title: {
          type: String,
          default: 'Processing'
        },
        description: {
          type: String,
          default: 'Your orders are being processed. This usually takes 15-30 minutes.'
        },
        icon: {
          type: String,
          default: 'loader'
        }
      },
      completed: {
        title: {
          type: String,
          default: 'Completed'
        },
        description: {
          type: String,
          default: 'Your orders have been successfully processed and delivered.'
        },
        icon: {
          type: String,
          default: 'check-circle'
        }
      },
      failed: {
        title: {
          type: String,
          default: 'Processing Failed'
        },
        description: {
          type: String,
          default: 'Some orders could not be processed. Please contact support.'
        },
        icon: {
          type: String,
          default: 'alert-circle'
        }
      }
    }
  },
  
  // Auto-completion configuration
  autoComplete: {
    enabled: {
      type: Boolean,
      default: true
    },
    strategy: {
      type: String,
      enum: ['fixed_time', 'progressive', 'manual'],
      default: 'fixed_time'
    },
    fixedTimeMinutes: {
      type: Number,
      default: 30
    },
    progressiveIntervals: [{
      afterMinutes: Number,
      completePercentage: Number
    }],
    successRate: {
      type: Number,
      default: 95,
      min: 0,
      max: 100
    }
  },
  
  // Excel file format configuration
  fileFormat: {
    includeHeaders: {
      type: Boolean,
      default: true
    },
    columns: [{
      field: String,
      header: String,
      format: String
    }],
    dateFormat: {
      type: String,
      default: 'YYYY-MM-DD HH:mm:ss'
    },
    numberFormat: {
      extractNumericOnly: {
        type: Boolean,
        default: true
      }
    }
  },
  
  // Portal integration settings
  portalIntegration: {
    enabled: {
      type: Boolean,
      default: true
    },
    autoSubmitToPortal: {
      type: Boolean,
      default: false
    },
    portalUrl: String,
    apiEndpoint: String,
    requiresManualPortalId: {
      type: Boolean,
      default: true
    }
  },
  
  // Notification settings
  notifications: {
    notifyOnExport: {
      type: Boolean,
      default: true
    },
    notifyOnCompletion: {
      type: Boolean,
      default: true
    },
    notifyOnFailure: {
      type: Boolean,
      default: true
    },
    adminAlerts: {
      enabled: {
        type: Boolean,
        default: true
      },
      alertEmails: [String],
      alertThreshold: {
        failurePercentage: {
          type: Number,
          default: 10
        },
        minimumOrders: {
          type: Number,
          default: 5
        }
      }
    }
  },
  
  // Admin tracking
  createdBy: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'reseller_users'
  },
  lastModifiedBy: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'reseller_users'
  }
}, {
  timestamps: true
});

// =============================================
// 2. EXPORT HISTORY SCHEMA
// =============================================

const exportHistorySchema = new mongoose.Schema({
  exportId: {
    type: String,
    required: true,
    unique: true
  },
  
  batchNumber: {
    type: Number,
    required: true
  },
  
  // Export details
  exportDetails: {
    totalOrders: {
      type: Number,
      required: true
    },
    totalAmount: Number,
    orderIds: [{
      type: mongoose.Schema.Types.ObjectId,
      ref: 'Transaction_reseller'
    }],
    exportMethod: {
      type: String,
      enum: ['manual', 'automatic', 'scheduled'],
      default: 'manual'
    },
    triggerSource: {
      type: String,
      enum: ['admin_dashboard', 'api', 'scheduler', 'system'],
      default: 'admin_dashboard'
    },
    // Batch pagination metadata
    metadata: {
      batchPage: Number,
      totalBatches: Number,
      ordersPerBatch: Number,
      totalAvailableOrders: Number,
      remainingOrders: Number,
      isReExport: Boolean,
      originalBatchId: String,
      limitedTo40: {
        type: Boolean,
        default: true
      },
      excludedOrders: Number
    }
  },
  
  // Timestamps for tracking
  timestamps: {
    exportedAt: {
      type: Date,
      default: Date.now
    },
    estimatedCompletionTime: Date,
    completedAt: Date,
    phases: {
      initial: {
        startedAt: Date,
        completedAt: Date
      },
      processing: {
        startedAt: Date,
        completedAt: Date,
        estimatedDuration: Number
      },
      finalizing: {
        startedAt: Date,
        completedAt: Date
      }
    }
  },
  
  // Status tracking
  status: {
    current: {
      type: String,
      enum: ['exporting', 'exported', 'processing', 'completed', 'failed', 're-export'],
      default: 'exporting'
    },
    progressPercentage: {
      type: Number,
      default: 0,
      min: 0,
      max: 100
    },
    successCount: {
      type: Number,
      default: 0
    },
    failedCount: {
      type: Number,
      default: 0
    },
    pendingCount: {
      type: Number,
      default: 0
    },
    history: [{
      status: String,
      timestamp: Date,
      message: String,
      updatedBy: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'reseller_users'
      }
    }]
  },
  
  // Settings snapshot at time of export
  settingsUsed: {
    settingName: String,
    totalProcessingMinutes: Number,
    autoCompleteEnabled: Boolean,
    successRate: Number,
    messages: mongoose.Schema.Types.Mixed
  },
  
  // Who exported
  exportedBy: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'reseller_users',
    required: true
  },
  
  // File details
  fileDetails: {
    fileName: String,
    fileSize: Number,
    fileUrl: String,
    downloadCount: {
      type: Number,
      default: 0
    }
  },
  
  // Portal link if submitted
  portalSubmission: {
    portalId: String,
    submittedAt: Date,
    submittedBy: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'reseller_users'
    }
  }
}, {
  timestamps: true
});

// Indexes
exportHistorySchema.index({ exportId: 1 });
exportHistorySchema.index({ 'status.current': 1 });
exportHistorySchema.index({ 'timestamps.exportedAt': -1 });
exportHistorySchema.index({ exportedBy: 1 });

// =============================================
// 3. SYSTEM STATUS SCHEMA
// =============================================

const systemStatusSchema = new mongoose.Schema({
  _id: {
    type: String,
    default: 'current_status'
  },
  
  // System health monitoring
  systemHealth: {
    status: {
      type: String,
      enum: ['healthy', 'degraded', 'critical'],
      default: 'healthy'
    },
    lastCheckedAt: Date,
    issues: [String],
    metrics: {
      cpuUsage: Number,
      memoryUsage: Number,
      diskSpace: Number,
      activeConnections: Number
    }
  },
  
  // Current processing state
  currentProcessing: {
    isProcessing: {
      type: Boolean,
      default: false
    },
    activeExports: [{
      exportId: String,
      startedAt: Date,
      estimatedCompletion: Date,
      processingMinutes: Number,
      progress: Number,
      orderCount: Number,
      batchInfo: String
    }],
    queuedExports: {
      type: Number,
      default: 0
    },
    processingCapacity: {
      current: Number,
      maximum: Number
    }
  },
  
  // Last export information
  lastExport: {
    exportId: String,
    exportedAt: Date,
    totalOrders: Number,
    status: String,
    exportedBy: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'reseller_users'
    },
    processingMinutes: Number,
    completedAt: Date,
    successCount: Number,
    failedCount: Number,
    batchInfo: {
      currentBatch: Number,
      totalBatches: Number,
      totalAvailable: Number,
      remainingOrders: Number
    }
  },
  
  lastExportDisplay: String,
  
  // Statistics
  statistics: {
    today: {
      totalExports: {
        type: Number,
        default: 0
      },
      totalOrders: {
        type: Number,
        default: 0
      },
      successRate: {
        type: Number,
        default: 100
      },
      averageProcessingTime: Number,
      lastUpdated: Date
    },
    thisWeek: {
      totalExports: {
        type: Number,
        default: 0
      },
      totalOrders: {
        type: Number,
        default: 0
      },
      avgProcessingTime: Number
    },
    thisMonth: {
      totalExports: {
        type: Number,
        default: 0
      },
      totalOrders: {
        type: Number,
        default: 0
      },
      totalAmount: {
        type: Number,
        default: 0
      }
    },
    allTime: {
      totalExports: {
        type: Number,
        default: 0
      },
      totalOrders: {
        type: Number,
        default: 0
      },
      totalAmount: {
        type: Number,
        default: 0
      }
    }
  },
  
  // Maintenance mode
  maintenanceMode: {
    enabled: {
      type: Boolean,
      default: false
    },
    message: String,
    startedAt: Date,
    estimatedEndTime: Date,
    allowedRoles: [String]
  },
  
  // User message for dashboard
  userMessage: String,
  adminMessage: String,
  
  // Portal statistics
  portalStatistics: {
    totalSubmissions: {
      type: Number,
      default: 0
    },
    pendingSubmissions: {
      type: Number,
      default: 0
    },
    averageCompletionTime: Number,
    lastSubmissionAt: Date
  }
}, {
  timestamps: true
});

// =============================================
// 4. EXPORT QUEUE SCHEMA
// =============================================

const exportQueueSchema = new mongoose.Schema({
  queueId: {
    type: String,
    required: true,
    unique: true
  },
  
  // Queue priority
  priority: {
    type: Number,
    default: 0
  },
  
  // Export configuration
  exportConfig: {
    filterCriteria: {
      status: String,
      dateFrom: Date,
      dateTo: Date,
      userRole: String,
      userId: mongoose.Schema.Types.ObjectId
    },
    expectedOrders: Number,
    orderIds: [String],
    maxOrders: {
      type: Number,
      default: 40
    }
  },
  
  // Queue status
  status: {
    type: String,
    enum: ['queued', 'processing', 'completed', 'failed', 'cancelled'],
    default: 'queued'
  },
  
  // Scheduling
  scheduledFor: Date,
  recurringSchedule: {
    enabled: {
      type: Boolean,
      default: false
    },
    pattern: {
      type: String,
      enum: ['daily', 'weekly', 'monthly']
    },
    time: String, // e.g., "14:30"
    daysOfWeek: [Number], // 0-6, Sunday to Saturday
    dayOfMonth: Number // 1-31
  },
  
  // Retry configuration
  attempts: {
    type: Number,
    default: 0
  },
  maxAttempts: {
    type: Number,
    default: 3
  },
  lastAttemptAt: Date,
  nextRetryAt: Date,
  
  // Error tracking
  errors: [{
    message: String,
    timestamp: Date,
    stack: String
  }],
  lastError: String,
  
  // Results
  results: {
    exportId: String,
    processedOrders: Number,
    successCount: Number,
    failedCount: Number,
    fileUrl: String
  },
  
  // Metadata
  createdBy: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'reseller_users'
  },
  processedAt: Date,
  completedAt: Date,
  cancelledAt: Date,
  cancelledBy: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'reseller_users'
  }
}, {
  timestamps: true
});

// Indexes
exportQueueSchema.index({ status: 1, priority: -1 });
exportQueueSchema.index({ scheduledFor: 1 });
exportQueueSchema.index({ createdBy: 1 });

// =============================================
// SAFE MODEL CREATION - PREVENTS OVERWRITE ERROR
// =============================================

const ExportSettings = mongoose.models['ExportSettings'] || mongoose.model('ExportSettings', exportSettingsSchema);
const ExportHistory = mongoose.models['ExportHistory'] || mongoose.model('ExportHistory', exportHistorySchema);
const SystemStatus = mongoose.models['SystemStatus'] || mongoose.model('SystemStatus', systemStatusSchema);
const ExportQueue = mongoose.models['ExportQueue'] || mongoose.model('ExportQueue', exportQueueSchema);

// =============================================
// EXPORT ALL MODELS
// =============================================

module.exports = {
  // Re-export core models from main schema
  User,
  Product,
  Transaction,
  PriceSetting,
  WalletTransaction,
  SystemSetting,
  ApiLog,
  Notification,
  Batch,
  defaultSettings,
  
  // Export-specific models
  ExportSettings,
  ExportHistory,
  SystemStatus,
  ExportQueue
};