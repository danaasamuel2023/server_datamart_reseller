// =============================================
// EXPORT SETTINGS & TRACKING SCHEMA
// Ghana MTN Data Reselling Platform
// =============================================

const mongoose = require('mongoose');

// =============================================
// 1. EXPORT SETTINGS SCHEMA - SIMPLIFIED
// =============================================

const exportSettingsSchema = new mongoose.Schema({
  // Settings Identification
  settingName: {
    type: String,
    required: true,
    unique: true,
    enum: ['default', 'peak_hours', 'off_peak', 'weekend', 'maintenance'],
    default: 'default'
  },
  
  isActive: {
    type: Boolean,
    default: false
  },
  
  // SIMPLIFIED Time Settings - Now focuses on single time value
  timeSettings: {
    // Legacy phases (kept for compatibility but not used)
    phases: {
      initial: {
        duration: { type: Number, default: 0 },
        unit: { type: String, default: 'minutes' },
        message: { type: String, default: '' }
      },
      processing: {
        duration: { type: Number, default: 0 },
        unit: { type: String, default: 'minutes' },
        message: { type: String, default: '' }
      },
      finalizing: {
        duration: { type: Number, default: 0 },
        unit: { type: String, default: 'minutes' },
        message: { type: String, default: '' }
      }
    },
    
    // Total processing time - THIS IS NOW CALCULATED FROM fixedTimeMinutes
    totalProcessingMinutes: {
      type: Number,
      default: 30
    },
    
    // Buffer time for safety
    bufferMinutes: {
      type: Number,
      default: 0
    },
    
    // Working hours configuration
    workingHours: {
      enabled: {
        type: Boolean,
        default: false
      },
      startTime: {
        type: String,
        default: '08:00'
      },
      endTime: {
        type: String,
        default: '20:00'
      },
      timezone: {
        type: String,
        default: 'Africa/Accra'
      },
      outsideHoursMessage: {
        type: String,
        default: 'Orders placed outside working hours will be processed when service resumes.'
      }
    }
  },
  
  // System Messages
  messages: {
    // Pre-export messages
    beforeExport: {
      type: String,
      default: 'Preparing to export orders to processing system...'
    },
    
    // Export confirmation
    exportSuccess: {
      type: String,
      default: 'Your orders have been successfully sent to MTN for processing.'
    },
    
    // Processing stages
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
          default: 'Your orders are being processed.'
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
    },
    
    // Error messages
    errors: {
      exportFailed: {
        type: String,
        default: 'Failed to export orders. Please try again.'
      },
      connectionLost: {
        type: String,
        default: 'Connection to processing system lost. Retrying...'
      },
      timeout: {
        type: String,
        default: 'Processing is taking longer than expected. Please be patient.'
      }
    }
  },
  
  // SIMPLIFIED Auto-completion settings
  autoComplete: {
    enabled: {
      type: Boolean,
      default: true
    },
    
    strategy: {
      type: String,
      enum: ['fixed_time', 'percentage_based', 'api_check', 'manual'],
      default: 'fixed_time'
    },
    
    // PRIMARY TIME CONTROL - This is the main setting now
    fixedTimeMinutes: {
      type: Number,
      default: 30,
      min: 1,      // Minimum 1 minute
      max: 1440    // Maximum 24 hours (1440 minutes)
    },
    
    // Success rate configuration
    successRate: {
      type: Number,
      default: 95,
      min: 0,
      max: 100
    },
    
    // Retry settings for failed orders
    retrySettings: {
      enabled: {
        type: Boolean,
        default: false
      },
      maxAttempts: {
        type: Number,
        default: 3
      },
      delayMinutes: {
        type: Number,
        default: 5
      }
    }
  },
  
  // FIXED: Made createdBy optional for system-created settings
  createdBy: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'reseller_users',
    required: false  // Changed from true to false
  },
  
  lastModifiedBy: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'reseller_users'
  },
  
  // Activation schedule (optional)
  schedule: {
    activateAt: Date,
    deactivateAt: Date,
    recurring: {
      enabled: {
        type: Boolean,
        default: false
      },
      pattern: {
        type: String,
        enum: ['daily', 'weekly', 'custom']
      },
      customCron: String
    }
  }
}, {
  timestamps: true
});

// SIMPLIFIED: Calculate total processing time from fixedTimeMinutes
exportSettingsSchema.pre('save', function(next) {
  // Use fixedTimeMinutes as the primary time source
  if (this.autoComplete && this.autoComplete.fixedTimeMinutes) {
    this.timeSettings.totalProcessingMinutes = this.autoComplete.fixedTimeMinutes;
  }
  next();
});

// =============================================
// 2. EXPORT HISTORY SCHEMA
// =============================================

const exportHistorySchema = new mongoose.Schema({
  // Export identification
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
    
    totalAmount: {
      type: Number,
      required: true
    },
    
    orderIds: [{
      type: mongoose.Schema.Types.ObjectId,
      ref: 'Transaction_reseller'
    }],
    
    exportMethod: {
      type: String,
      enum: ['manual', 'automatic', 'scheduled', 'api'],
      default: 'manual'
    },
    
    triggerSource: {
      type: String,
      enum: ['admin_dashboard', 'api', 'scheduler', 'system'],
      default: 'admin_dashboard'
    }
  },
  
  // SIMPLIFIED Timing information
  timestamps: {
    exportedAt: {
      type: Date,
      required: true,
      default: Date.now
    },
    
    startedProcessingAt: Date,
    completedAt: Date,
    
    // Simplified phase tracking
    phases: {
      processing: {
        startedAt: Date,
        estimatedDuration: Number  // In minutes
      }
    },
    
    // Actual vs estimated
    estimatedCompletionTime: Date,
    actualProcessingMinutes: Number
  },
  
  // Status tracking
  status: {
    current: {
      type: String,
      enum: ['pending', 'exporting', 'exported', 'processing', 'completed', 'failed', 'partial'],
      default: 'pending'
    },
    
    history: [{
      status: String,
      timestamp: Date,
      message: String,
      updatedBy: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'reseller_users'
      }
    }],
    
    // Success metrics
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
    
    successRate: Number
  },
  
  // SIMPLIFIED Settings used for this export
  settingsUsed: {
    settingName: String,
    totalProcessingMinutes: Number,    // Single time value
    autoCompleteEnabled: Boolean,
    successRate: Number,               // Success rate percentage
    messages: Object
  },
  
  // External system info
  externalSystem: {
    name: {
      type: String,
      default: 'MTN Gateway'
    },
    referenceId: String,
    responseCode: String,
    responseMessage: String,
    rawResponse: mongoose.Schema.Types.Mixed
  },
  
  // User who initiated export
  exportedBy: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'reseller_users',
    required: true
  },
  
  // Files generated
  files: [{
    type: {
      type: String,
      enum: ['csv', 'excel', 'json', 'pdf']
    },
    filename: String,
    url: String,
    size: Number,
    generatedAt: Date
  }],
  
  // Notes and comments
  notes: [{
    text: String,
    addedBy: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'reseller_users'
    },
    addedAt: {
      type: Date,
      default: Date.now
    }
  }],
  
  // Error tracking
  errors: [{
    timestamp: Date,
    type: String,
    message: String,
    details: mongoose.Schema.Types.Mixed
  }]
}, {
  timestamps: true
});

// Indexes for efficient queries
exportHistorySchema.index({ exportedAt: -1 });
exportHistorySchema.index({ 'status.current': 1 });
exportHistorySchema.index({ exportedBy: 1 });
exportHistorySchema.index({ 'timestamps.exportedAt': -1 });

// =============================================
// 3. SYSTEM STATUS SCHEMA
// =============================================

const systemStatusSchema = new mongoose.Schema({
  // Single document for current system status
  _id: {
    type: String,
    default: 'current_status'
  },
  
  // Last export information
  lastExport: {
    exportId: String,
    exportedAt: Date,
    totalOrders: Number,
    status: String,
    processingMinutes: Number,  // Added single time value
    exportedBy: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'reseller_users'
    },
    completedAt: Date
  },
  
  // Current processing
  currentProcessing: {
    isProcessing: {
      type: Boolean,
      default: false
    },
    
    activeExports: [{
      exportId: String,
      startedAt: Date,
      estimatedCompletion: Date,
      processingMinutes: Number,  // Added single time value
      progress: Number,
      orderCount: Number
    }],
    
    queuedExports: Number,
    
    processingSpeed: {
      ordersPerMinute: Number,
      averageProcessingTime: Number
    }
  },
  
  // System health
  systemHealth: {
    status: {
      type: String,
      enum: ['healthy', 'degraded', 'down', 'maintenance'],
      default: 'healthy'
    },
    
    lastCheckedAt: Date,
    
    thirdPartyStatus: {
      available: Boolean,
      lastSuccessfulConnection: Date,
      responseTime: Number,
      errorRate: Number
    },
    
    exportServiceStatus: {
      available: Boolean,
      queueLength: Number,
      processingRate: Number
    }
  },
  
  // Statistics
  statistics: {
    today: {
      totalExports: Number,
      totalOrders: Number,
      successRate: Number,
      averageProcessingTime: Number,
      lastUpdated: Date
    },
    
    thisWeek: {
      totalExports: Number,
      totalOrders: Number,
      successRate: Number,
      averageProcessingTime: Number
    },
    
    thisMonth: {
      totalExports: Number,
      totalOrders: Number,
      successRate: Number,
      averageProcessingTime: Number
    }
  },
  
  // Active settings
  activeSettings: {
    settingName: String,
    activeSince: Date,
    nextScheduledChange: Date
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
    allowExports: {
      type: Boolean,
      default: false
    }
  },
  
  // Display message for users
  userMessage: {
    enabled: {
      type: Boolean,
      default: false
    },
    message: String,
    type: {
      type: String,
      enum: ['info', 'warning', 'success', 'error'],
      default: 'info'
    },
    showUntil: Date
  }
}, {
  timestamps: true
});

// =============================================
// 4. EXPORT QUEUE SCHEMA
// =============================================

const exportQueueSchema = new mongoose.Schema({
  // Queue management
  priority: {
    type: Number,
    default: 0,
    min: 0,
    max: 10
  },
  
  scheduledFor: {
    type: Date,
    required: true
  },
  
  // Orders to export
  orders: [{
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Transaction_reseller'
  }],
  
  // Queue status
  status: {
    type: String,
    enum: ['waiting', 'processing', 'completed', 'failed', 'cancelled'],
    default: 'waiting'
  },
  
  attempts: {
    type: Number,
    default: 0
  },
  
  maxAttempts: {
    type: Number,
    default: 3
  },
  
  // Processing details
  processingStartedAt: Date,
  processingCompletedAt: Date,
  
  // Created by
  createdBy: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'reseller_users'
  },
  
  // Error handling
  lastError: {
    message: String,
    occurredAt: Date
  },
  
  // Settings to use
  settingsToUse: {
    type: String,
    default: 'default'
  }
}, {
  timestamps: true
});

exportQueueSchema.index({ status: 1, scheduledFor: 1 });
exportQueueSchema.index({ priority: -1 });

// =============================================
// EXPORT MODELS
// =============================================

module.exports = {
  ExportSettings: mongoose.model('ExportSettings', exportSettingsSchema),
  ExportHistory: mongoose.model('ExportHistory', exportHistorySchema),
  SystemStatus: mongoose.model('SystemStatus', systemStatusSchema),
  ExportQueue: mongoose.model('ExportQueue', exportQueueSchema)
};