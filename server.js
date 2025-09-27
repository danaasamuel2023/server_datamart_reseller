// ==================== index.js ====================
// MAIN SERVER FILE - SIMPLIFIED VERSION

const express = require('express');
const dotenv = require('dotenv');
const cors = require('cors');

// Load environment variables first
dotenv.config();

// Import database connection
const ConnectDB = require('./database/connection.js');

// Import routes
const authRoutes = require('./Routes/auth.js');
const dataOrderRoutes = require('./Routes/order.js');
const adminManagement = require('./Routes/Admin.js');
const api = require('./Routes/api.js');
const UserProfile = require('./Routes/user.js');
const User_action = require('./Routes/Useractions.js');

// Uncomment these as you need them
// const SystemSettings = require('./routes/settings/setting.js');
// const profile = require('./routes/User/User.js');
// const Uaer_transactions = require('./routes/transaction/user_transactions.js');
// const agent_store = require('./routes/agent_store/agent_store.js');
// const UserDeposite = require('./routes/deposite/deposite.js');
// const wallet = require('./routes/user_walllet/page.js');
// const user_dashboard = require('./routes/user_dashboard/page.js');
// const checkers = require('./routes/result_checkers/page.js');
// const telecel_token = require('./routes/admin_telecel_auth/admin.js');

const app = express();

// Middleware
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));
app.use(cors({
  origin: process.env.FRONTEND_URL || '*',
  credentials: true
}));

// Request logging middleware
app.use((req, res, next) => {
  console.log(`${new Date().toISOString()} - ${req.method} ${req.path}`);
  next();
});

// Health check endpoint
app.get('/health', (req, res) => {
  res.json({ 
    status: 'ok', 
    timestamp: new Date().toISOString(),
    environment: process.env.NODE_ENV || 'development'
  });
});

// Setup all routes
const setupRoutes = () => {
  // API routes
  app.use('/api/auth', authRoutes);
  app.use('/api/purchase', dataOrderRoutes);
  app.use('/api/admin', adminManagement);
  app.use('/api', api);
  app.use('/api/user', UserProfile);
  app.use('/api/useractions', User_action);
  
  // Uncomment these as you need them
  // app.use('/api/admin/settings', SystemSettings);
  // app.use('/api/auth', profile);
  // app.use('/api', Uaer_transactions);
  // app.use('/api/store', agent_store);
  // app.use('/api/deposites', UserDeposite);
  // app.use('/api/users', wallet);
  // app.use('/api', user_dashboard);
  // app.use('/api/checkers', checkers);
  // app.use('/api/admin/telecel', telecel_token);
  
  // Default route
  app.get('/', (req, res) => {
    res.json({
      message: 'API is running',
      version: '1.0.0',
      timestamp: new Date().toISOString()
    });
  });
  
  // 404 handler
  app.use((req, res) => {
    res.status(404).json({
      success: false,
      message: 'Route not found',
      path: req.path
    });
  });
  
  // Global error handler
  app.use((err, req, res, next) => {
    console.error('Global error:', err);
    res.status(err.status || 500).json({
      success: false,
      message: err.message || 'Internal server error',
      ...(process.env.NODE_ENV === 'development' && { stack: err.stack })
    });
  });
};

// Initialize server
const initializeServer = async () => {
  try {
    // Connect to MongoDB
    console.log('🔄 Connecting to MongoDB...');
    await ConnectDB();
    console.log('✅ Database connected successfully');
    
    // Setup routes
    setupRoutes();
    
    // Start Express server
    const PORT = process.env.PORT || 5000;
    const server = app.listen(PORT, () => {
      console.log('\n========================================');
      console.log(`🚀 Server running on port ${PORT}`);
      console.log(`🌐 Environment: ${process.env.NODE_ENV || 'development'}`);
      console.log('========================================');
      console.log('📍 Endpoints:');
      console.log(`   Health Check: http://localhost:${PORT}/health`);
      console.log(`   API Base: http://localhost:${PORT}/api`);
      console.log('========================================\n');
    });
    
    // Graceful shutdown handling
    process.on('SIGTERM', () => gracefulShutdown(server));
    process.on('SIGINT', () => gracefulShutdown(server));
    
  } catch (error) {
    console.error('❌ Failed to initialize server:', error);
    process.exit(1);
  }
};

// Graceful shutdown
const gracefulShutdown = (server) => {
  console.log('\n📍 Received shutdown signal...');
  
  // Close server
  server.close(() => {
    console.log('✅ HTTP server closed');
    
    // Close database connection
    const mongoose = require('mongoose');
    mongoose.connection.close(false, () => {
      console.log('✅ MongoDB connection closed');
      console.log('👋 Goodbye!');
      process.exit(0);
    });
  });
  
  // Force shutdown after 10 seconds
  setTimeout(() => {
    console.error('⚠️ Could not close connections in time, forcefully shutting down');
    process.exit(1);
  }, 10000);
};

// Handle uncaught exceptions
process.on('uncaughtException', (error) => {
  console.error('❌ Uncaught Exception:', error);
  process.exit(1);
});

// Handle unhandled promise rejections
process.on('unhandledRejection', (reason, promise) => {
  console.error('❌ Unhandled Rejection at:', promise, 'reason:', reason);
  process.exit(1);
});

// Start the server
initializeServer();