/**
 * ConFuse Platform - Authentication Middleware Service
 * 
 * Provides JWT-based authentication and authorization services
 * Publishes authentication events to Kafka
 */

const express = require('express');
const jwt = require('jsonwebtoken');
const { Kafka } = require('kafkajs');
const { v4: uuidv4 } = require('uuid');
const bcrypt = require('bcrypt');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');

class AuthService {
  constructor() {
    this.app = express();
    this.port = process.env.PORT || 3010;
    this.jwtSecret = process.env.JWT_SECRET || 'your-super-secret-jwt-key';
    this.kafkaEnabled = process.env.KAFKA_ENABLED === 'true';
    
    // Initialize Kafka if enabled
    if (this.kafkaEnabled) {
      this.kafka = new Kafka({
        clientId: 'auth-middleware',
        brokers: (process.env.KAFKA_BOOTSTRAP_SERVERS || 'localhost:9092').split(',')
      });
      this.producer = this.kafka.producer();
    }
    
    this.setupMiddleware();
    this.setupRoutes();
  }

  setupMiddleware() {
    // Security middleware
    this.app.use(helmet());
    this.app.use(cors({
      origin: (process.env.CORS_ORIGINS || 'http://localhost:3000').split(','),
      credentials: true
    }));
    
    // Rate limiting
    const limiter = rateLimit({
      windowMs: 15 * 60 * 1000, // 15 minutes
      max: 100, // limit each IP to 100 requests per windowMs
      message: 'Too many authentication requests, please try again later.'
    });
    this.app.use('/api', limiter);
    
    // Body parsing
    this.app.use(express.json());
    this.app.use(express.urlencoded({ extended: true }));
    
    // Request logging
    this.app.use((req, res, next) => {
      console.log(`${new Date().toISOString()} - ${req.method} ${req.path}`);
      next();
    });
  }

  setupRoutes() {
    // Health check
    this.app.get('/health', (req, res) => {
      res.json({
        status: 'healthy',
        service: 'auth-middleware',
        version: '1.0.0',
        timestamp: new Date().toISOString()
      });
    });

    // Authentication endpoints
    this.app.post('/api/auth/login', this.handleLogin.bind(this));
    this.app.post('/api/auth/register', this.handleRegister.bind(this));
    this.app.post('/api/auth/refresh', this.handleRefresh.bind(this));
    this.app.post('/api/auth/logout', this.handleLogout.bind(this));
    this.app.get('/api/auth/verify', this.handleVerify.bind(this));
    
    // User management
    this.app.get('/api/users/profile', this.authenticateToken, this.handleGetProfile.bind(this));
    this.app.put('/api/users/profile', this.authenticateToken, this.handleUpdateProfile.bind(this));
    
    // Admin endpoints
    this.app.get('/api/admin/users', this.authenticateToken, this.requireAdmin, this.handleListUsers.bind(this));
    this.app.delete('/api/admin/users/:id', this.authenticateToken, this.requireAdmin, this.handleDeleteUser.bind(this));
    
    // Error handling
    this.app.use(this.handleErrors.bind(this));
  }

  // Authentication middleware
  authenticateToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1]; // Bearer TOKEN

    if (!token) {
      return res.status(401).json({
        success: false,
        error: 'Access token required'
      });
    }

    jwt.verify(token, this.jwtSecret, (err, user) => {
      if (err) {
        return res.status(403).json({
          success: false,
          error: 'Invalid or expired token'
        });
      }
      req.user = user;
      next();
    });
  }

  // Admin role check
  requireAdmin(req, res, next) {
    if (!req.user.roles.includes('admin')) {
      return res.status(403).json({
        success: false,
        error: 'Admin access required'
      });
    }
    next();
  }

  // Route handlers
  async handleLogin(req, res) {
    try {
      const { email, password } = req.body;

      if (!email || !password) {
        return res.status(400).json({
          success: false,
          error: 'Email and password are required'
        });
      }

      // In a real implementation, verify against database
      const user = await this.findUserByEmail(email);
      
      if (!user || !await bcrypt.compare(password, user.passwordHash)) {
        return res.status(401).json({
          success: false,
          error: 'Invalid email or password'
        });
      }

      // Generate tokens
      const accessToken = this.generateAccessToken(user);
      const refreshToken = this.generateRefreshToken(user);
      
      // Update user's refresh token
      await this.updateUserRefreshToken(user.id, refreshToken);

      // Publish authentication event
      if (this.kafkaEnabled) {
        await this.publishAuthEvent('USER_AUTHENTICATED', {
          user_id: user.id,
          email: user.email,
          auth_method: 'password',
          session_id: uuidv4()
        });
      }

      res.json({
        success: true,
        data: {
          user: {
            id: user.id,
            email: user.email,
            name: user.name,
            roles: user.roles,
            created_at: user.created_at
          },
          tokens: {
            access_token: accessToken,
            refresh_token: refreshToken,
            expires_in: 3600 // 1 hour
          }
        }
      });

    } catch (error) {
      console.error('Login error:', error);
      res.status(500).json({
        success: false,
        error: 'Internal server error'
      });
    }
  }

  async handleRegister(req, res) {
    try {
      const { email, password, name } = req.body;

      if (!email || !password) {
        return res.status(400).json({
          success: false,
          error: 'Email and password are required'
        });
      }

      // Check if user already exists
      const existingUser = await this.findUserByEmail(email);
      if (existingUser) {
        return res.status(409).json({
          success: false,
          error: 'User already exists'
        });
      }

      // Hash password
      const passwordHash = await bcrypt.hash(password, 10);

      // Create user
      const user = await this.createUser({
        email,
        passwordHash,
        name: name || email.split('@')[0],
        roles: ['user']
      });

      // Generate tokens
      const accessToken = this.generateAccessToken(user);
      const refreshToken = this.generateRefreshToken(user);

      // Publish user created event
      if (this.kafkaEnabled) {
        await this.publishAuthEvent('USER_CREATED', {
          user_id: user.id,
          email: user.email,
          name: user.name,
          roles: user.roles,
          created_by: 'self'
        });
      }

      res.status(201).json({
        success: true,
        data: {
          user: {
            id: user.id,
            email: user.email,
            name: user.name,
            roles: user.roles,
            created_at: user.created_at
          },
          tokens: {
            access_token: accessToken,
            refresh_token: refreshToken,
            expires_in: 3600
          }
        }
      });

    } catch (error) {
      console.error('Registration error:', error);
      res.status(500).json({
        success: false,
        error: 'Internal server error'
      });
    }
  }

  async handleRefresh(req, res) {
    try {
      const { refresh_token } = req.body;

      if (!refresh_token) {
        return res.status(400).json({
          success: false,
          error: 'Refresh token required'
        });
      }

      // Verify refresh token
      const decoded = jwt.verify(refresh_token, this.jwtSecret);
      const user = await this.findUserById(decoded.userId);

      if (!user || user.refreshToken !== refresh_token) {
        return res.status(403).json({
          success: false,
          error: 'Invalid refresh token'
        });
      }

      // Generate new access token
      const accessToken = this.generateAccessToken(user);

      res.json({
        success: true,
        data: {
          access_token: accessToken,
          expires_in: 3600
        }
      });

    } catch (error) {
      console.error('Token refresh error:', error);
      res.status(403).json({
        success: false,
        error: 'Invalid or expired refresh token'
      });
    }
  }

  async handleLogout(req, res) {
    try {
      const { refresh_token } = req.body;

      if (refresh_token) {
        // Remove refresh token from user
        const decoded = jwt.decode(refresh_token);
        if (decoded && decoded.userId) {
          await this.updateUserRefreshToken(decoded.userId, null);
        }
      }

      res.json({
        success: true,
        message: 'Logged out successfully'
      });

    } catch (error) {
      console.error('Logout error:', error);
      res.status(500).json({
        success: false,
        error: 'Internal server error'
      });
    }
  }

  async handleVerify(req, res) {
    try {
      const authHeader = req.headers['authorization'];
      const token = authHeader && authHeader.split(' ')[1];

      if (!token) {
        return res.status(400).json({
          success: false,
          error: 'Token required'
        });
      }

      const decoded = jwt.verify(token, this.jwtSecret);
      const user = await this.findUserById(decoded.userId);

      if (!user) {
        return res.status(403).json({
          success: false,
          error: 'User not found'
        });
      }

      res.json({
        success: true,
        data: {
          user: {
            id: user.id,
            email: user.email,
            name: user.name,
            roles: user.roles
          },
          valid: true
        }
      });

    } catch (error) {
      res.status(403).json({
        success: false,
        error: 'Invalid token',
        valid: false
      });
    }
  }

  async handleGetProfile(req, res) {
    try {
      const user = await this.findUserById(req.user.userId);
      
      if (!user) {
        return res.status(404).json({
          success: false,
          error: 'User not found'
        });
      }

      res.json({
        success: true,
        data: {
          id: user.id,
          email: user.email,
          name: user.name,
          roles: user.roles,
          created_at: user.created_at,
          updated_at: user.updated_at
        }
      });

    } catch (error) {
      console.error('Get profile error:', error);
      res.status(500).json({
        success: false,
        error: 'Internal server error'
      });
    }
  }

  async handleUpdateProfile(req, res) {
    try {
      const { name } = req.body;
      const userId = req.user.userId;

      const updatedUser = await this.updateUser(userId, { name });

      res.json({
        success: true,
        data: {
          id: updatedUser.id,
          email: updatedUser.email,
          name: updatedUser.name,
          roles: updatedUser.roles,
          updated_at: updatedUser.updated_at
        }
      });

    } catch (error) {
      console.error('Update profile error:', error);
      res.status(500).json({
        success: false,
        error: 'Internal server error'
      });
    }
  }

  async handleListUsers(req, res) {
    try {
      const users = await this.listAllUsers();
      
      res.json({
        success: true,
        data: users.map(user => ({
          id: user.id,
          email: user.email,
          name: user.name,
          roles: user.roles,
          created_at: user.created_at,
          last_login: user.last_login
        }))
      });

    } catch (error) {
      console.error('List users error:', error);
      res.status(500).json({
        success: false,
        error: 'Internal server error'
      });
    }
  }

  async handleDeleteUser(req, res) {
    try {
      const userId = req.params.id;
      
      await this.deleteUser(userId);

      res.json({
        success: true,
        message: 'User deleted successfully'
      });

    } catch (error) {
      console.error('Delete user error:', error);
      res.status(500).json({
        success: false,
        error: 'Internal server error'
      });
    }
  }

  // Utility methods
  generateAccessToken(user) {
    return jwt.sign(
      { 
        userId: user.id, 
        email: user.email, 
        roles: user.roles 
      },
      this.jwtSecret,
      { expiresIn: '1h' }
    );
  }

  generateRefreshToken(user) {
    return jwt.sign(
      { userId: user.id },
      this.jwtSecret,
      { expiresIn: '7d' }
    );
  }

  async publishAuthEvent(eventType, data) {
    if (!this.kafkaEnabled) return;

    try {
      await this.producer.send({
        topic: eventType === 'USER_CREATED' ? 'auth.user.created' : 'auth.user.authenticated',
        messages: [{
          key: data.user_id,
          value: JSON.stringify({
            event_id: uuidv4(),
            event_type: eventType,
            timestamp: new Date().toISOString(),
            correlation_id: uuidv4(),
            source_service: 'auth-middleware',
            data: data
          })
        }]
      });
    } catch (error) {
      console.error('Failed to publish auth event:', error);
    }
  }

  // Mock database methods (replace with real database implementation)
  async findUserByEmail(email) {
    // Mock implementation - replace with real database query
    return null;
  }

  async findUserById(id) {
    // Mock implementation - replace with real database query
    return null;
  }

  async createUser(userData) {
    // Mock implementation - replace with real database insertion
    return {
      id: uuidv4(),
      ...userData,
      created_at: new Date().toISOString(),
      updated_at: new Date().toISOString()
    };
  }

  async updateUser(userId, updates) {
    // Mock implementation - replace with real database update
    return {
      id: userId,
      email: 'user@example.com',
      ...updates,
      updated_at: new Date().toISOString()
    };
  }

  async updateUserRefreshToken(userId, refreshToken) {
    // Mock implementation - replace with real database update
  }

  async listAllUsers() {
    // Mock implementation - replace with real database query
    return [];
  }

  async deleteUser(userId) {
    // Mock implementation - replace with real database deletion
  }

  handleErrors(err, req, res, next) {
    console.error('Unhandled error:', err);
    res.status(500).json({
      success: false,
      error: 'Internal server error'
    });
  }

  async start() {
    try {
      // Start Kafka producer if enabled
      if (this.kafkaEnabled) {
        await this.producer.connect();
        console.log('Kafka producer connected');
      }

      // Start HTTP server
      this.app.listen(this.port, () => {
        console.log(`Auth middleware service listening on port ${this.port}`);
        console.log(`Kafka enabled: ${this.kafkaEnabled}`);
      });

    } catch (error) {
      console.error('Failed to start auth service:', error);
      process.exit(1);
    }
  }

  async shutdown() {
    try {
      if (this.kafkaEnabled && this.producer) {
        await this.producer.disconnect();
        console.log('Kafka producer disconnected');
      }
    } catch (error) {
      console.error('Error during shutdown:', error);
    }
  }
}

// Graceful shutdown
process.on('SIGTERM', async () => {
  console.log('SIGTERM received, shutting down gracefully');
  if (authService) {
    await authService.shutdown();
  }
  process.exit(0);
});

process.on('SIGINT', async () => {
  console.log('SIGINT received, shutting down gracefully');
  if (authService) {
    await authService.shutdown();
  }
  process.exit(0);
});

// Start the service
const authService = new AuthService();
authService.start();

module.exports = AuthService;
