const fs = require('fs');
const path = require('path');

/**
 * Security Configuration Generator
 * Auto-generates secure configuration files and code snippets
 */
class ConfigGenerator {
  constructor(options = {}) {
    this.targetPath = options.targetPath || process.cwd();
  }

  /**
   * Generate all recommended security configurations
   */
  async generateAll() {
    console.log('\n⚙️  Generating security configurations...\n');

    const configs = [];

    // Check what framework is being used
    const framework = await this.detectFramework();

    // Generate helmet config
    configs.push(this.generateHelmetConfig());

    // Generate CORS config
    configs.push(this.generateCORSConfig());

    // Generate rate limiting config
    configs.push(this.generateRateLimitConfig());

    // Generate ESLint security rules
    configs.push(this.generateESLintSecurityRules());

    // Generate .env.example
    configs.push(this.generateEnvExample());

    // Generate gitignore additions
    configs.push(this.generateGitignoreAdditions());

    // Display all configs
    this.displayConfigs(configs);

    return configs;
  }

  /**
   * Detect project framework
   */
  async detectFramework() {
    try {
      const packageJsonPath = path.join(this.targetPath, 'package.json');
      if (!fs.existsSync(packageJsonPath)) return 'unknown';

      const packageJson = JSON.parse(fs.readFileSync(packageJsonPath, 'utf-8'));
      const deps = { ...packageJson.dependencies, ...packageJson.devDependencies };

      if (deps.express) return 'express';
      if (deps.fastify) return 'fastify';
      if (deps['@nestjs/core']) return 'nestjs';
      if (deps.next) return 'nextjs';
      if (deps.koa) return 'koa';
      if (deps.hapi) return 'hapi';

      return 'unknown';
    } catch (error) {
      return 'unknown';
    }
  }

  /**
   * Generate Helmet configuration
   */
  generateHelmetConfig() {
    return {
      name: 'helmet-config.js',
      description: 'HTTP security headers middleware',
      language: 'javascript',
      content: `const helmet = require('helmet');

/**
 * Helmet security configuration
 * Provides essential HTTP security headers
 */
const helmetConfig = helmet({
  // Content-Security-Policy
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      imgSrc: ["'self'", 'data:', 'https:'],
      connectSrc: ["'self'"],
      fontSrc: ["'self'"],
      objectSrc: ["'none'"],
      mediaSrc: ["'self'"],
      frameSrc: ["'none'"],
      childSrc: ["'none'"],
      formAction: ["'self'"],
      frameAncestors: ["'none'"],
      baseUri: ["'self'"],
      manifestSrc: ["'self'"]
    }
  },

  // Cross-Origin Embedder Policy
  crossOriginEmbedderPolicy: true,

  // Cross-Origin Opener Policy
  crossOriginOpenerPolicy: {
    policy: 'same-origin'
  },

  // Cross-Origin Resource Policy
  crossOriginResourcePolicy: {
    policy: 'same-origin'
  },

  // DNS Prefetch Control
  dnsPrefetchControl: {
    allow: false
  },

  // Frameguard (X-Frame-Options)
  frameguard: {
    action: 'deny'
  },

  // HSTS (Strict-Transport-Security)
  hsts: {
    maxAge: 31536000, // 1 year
    includeSubDomains: true,
    preload: true
  },

  // IE No Open
  ieNoOpen: true,

  // No Sniff (X-Content-Type-Options)
  noSniff: true,

  // Referrer Policy
  referrerPolicy: {
    policy: 'strict-origin-when-cross-origin'
  },

  // X-XSS-Protection
  xssFilter: true
});

module.exports = helmetConfig;
`,
      installCommand: 'npm install helmet',
      usageExample: `const helmetConfig = require('./config/helmet-config');
app.use(helmetConfig);`
    };
  }

  /**
   * Generate CORS configuration
   */
  generateCORSConfig() {
    return {
      name: 'cors-config.js',
      description: 'Secure CORS configuration',
      language: 'javascript',
      content: `const cors = require('cors');

/**
 * CORS configuration
 * Restricts cross-origin requests to trusted domains
 */
const allowedOrigins = process.env.CORS_ORIGINS
  ? process.env.CORS_ORIGINS.split(',')
  : [
      'http://localhost:3000',
      'https://yourdomain.com',
      'https://www.yourdomain.com'
    ];

const corsOptions = {
  origin: function (origin, callback) {
    // Allow requests with no origin (mobile apps, curl, etc.)
    if (!origin) return callback(null, true);

    if (allowedOrigins.indexOf(origin) !== -1) {
      callback(null, true);
    } else {
      callback(new Error('Not allowed by CORS'));
    }
  },
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH'],
  allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With'],
  exposedHeaders: ['X-Total-Count', 'X-Page-Number'],
  credentials: true,
  maxAge: 86400 // 24 hours
};

const corsMiddleware = cors(corsOptions);

module.exports = corsMiddleware;
`,
      installCommand: 'npm install cors',
      usageExample: `const corsMiddleware = require('./config/cors-config');
app.use(corsMiddleware);`
    };
  }

  /**
   * Generate rate limiting configuration
   */
  generateRateLimitConfig() {
    return {
      name: 'rate-limit-config.js',
      description: 'Rate limiting middleware configuration',
      language: 'javascript',
      content: `const rateLimit = require('express-rate-limit');

/**
 * General API rate limiter
 */
const generalLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // Limit each IP to 100 requests per window
  message: {
    error: 'Too many requests',
    message: 'Please try again later',
    retryAfter: 900 // seconds
  },
  standardHeaders: true,
  legacyHeaders: false
});

/**
 * Strict rate limiter for authentication endpoints
 */
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 5, // Limit each IP to 5 login attempts per window
  message: {
    error: 'Too many login attempts',
    message: 'Please try again after 15 minutes',
    retryAfter: 900
  },
  standardHeaders: true,
  legacyHeaders: false
});

/**
 * Upload rate limiter
 */
const uploadLimiter = rateLimit({
  windowMs: 60 * 60 * 1000, // 1 hour
  max: 10, // Limit each IP to 10 uploads per hour
  message: {
    error: 'Upload limit exceeded',
    message: 'You can upload up to 10 files per hour'
  },
  standardHeaders: true,
  legacyHeaders: false
});

/**
 * API-specific rate limiter
 */
const apiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 50, // Limit each IP to 50 API requests per window
  message: {
    error: 'API rate limit exceeded',
    message: 'Please reduce your request frequency'
  },
  standardHeaders: true,
  legacyHeaders: false
});

module.exports = {
  generalLimiter,
  authLimiter,
  uploadLimiter,
  apiLimiter
};
`,
      installCommand: 'npm install express-rate-limit',
      usageExample: `const { generalLimiter, authLimiter } = require('./config/rate-limit-config');

// Apply to all routes
app.use(generalLimiter);

// Apply strict limit to auth routes
app.post('/login', authLimiter, loginHandler);
app.post('/register', authLimiter, registerHandler);`
    };
  }

  /**
   * Generate ESLint security rules
   */
  generateESLintSecurityRules() {
    return {
      name: '.eslintrc.security.json',
      description: 'ESLint configuration with security-focused rules',
      language: 'json',
      content: `{
  "plugins": [
    "security"
  ],
  "extends": [
    "plugin:security/recommended"
  ],
  "rules": {
    "security/detect-eval-with-expression": "error",
    "security/detect-no-csrftoken-middleware": "warn",
    "security/detect-object-injection": "warn",
    "security/detect-unsafe-regex": "error",
    "security/detect-buffer-noassert": "error",
    "security/detect-child-process": "warn",
    "security/detect-disable-mustache-escape": "error",
    "security/detect-non-literal-fs-filename": "warn",
    "security/detect-non-literal-regexp": "warn",
    "security/detect-non-literal-require": "warn",
    "security/detect-possible-timing-attacks": "warn",
    "security/detect-pseudoRandomBytes": "warn",
    "no-eval": "error",
    "no-implied-eval": "error",
    "no-new-func": "error",
    "no-script-url": "error",
    "no-prototype-builtins": "error"
  }
}
`,
      installCommand: 'npm install --save-dev eslint-plugin-security',
      usageExample: 'Add to your existing .eslintrc or use as standalone config'
    };
  }

  /**
   * Generate .env.example template
   */
  generateEnvExample() {
    return {
      name: '.env.example',
      description: 'Environment variables template',
      language: 'bash',
      content: `# ============================================
# Environment Variables Template
# Copy this file to .env and fill in your values
# NEVER commit .env to version control!
# ============================================

# Application
NODE_ENV=development
PORT=3000
APP_NAME=MyApp
APP_URL=http://localhost:3000

# Database
DATABASE_URL=postgresql://user:password@localhost:5432/dbname
MONGODB_URI=mongodb://localhost:27017/dbname
REDIS_URL=redis://localhost:6379

# Authentication
JWT_SECRET=change-this-to-a-long-random-string
JWT_EXPIRES_IN=1h
SESSION_SECRET=change-this-to-another-random-string
BCRYPT_ROUNDS=12

# CORS
CORS_ORIGINS=http://localhost:3000,https://yourdomain.com

# Email
SENDGRID_API_KEY=SG.xxx
SMTP_HOST=smtp.example.com
SMTP_PORT=587
SMTP_USER=your-email@example.com
SMTP_PASS=your-password

# File Upload
MAX_FILE_SIZE=5242880 # 5MB in bytes
UPLOAD_DIR=./uploads
AWS_S3_BUCKET=your-bucket
AWS_ACCESS_KEY_ID=your-access-key
AWS_SECRET_ACCESS_KEY=your-secret-key

# Payment Processing (Stripe)
STRIPE_SECRET_KEY=sk_test_xxx
STRIPE_PUBLISHABLE_KEY=pk_test_xxx
STRIPE_WEBHOOK_SECRET=whsec_xxx

# API Keys
OPENAI_API_KEY=sk-xxx
GOOGLE_API_KEY=AIzaSyxxx

# Logging
LOG_LEVEL=info
SENTRY_DSN=https://xxx@sentry.io/xxx

# Rate Limiting
RATE_LIMIT_WINDOW_MS=900000
RATE_LIMIT_MAX_REQUESTS=100
`,
      installCommand: null,
      usageExample: 'cp .env.example .env && edit .env with your actual values'
    };
  }

  /**
   * Generate .gitignore additions
   */
  generateGitignoreAdditions() {
    return {
      name: '.gitignore.security',
      description: 'Security-related entries for .gitignore',
      language: 'text',
      content: `
# ============================================
# Security-sensitive files - DO NOT COMMIT
# Add these to your .gitignore
# ============================================

# Environment variables
.env
.env.local
.env.production
.env.staging
.env.test
*.env

# Secrets and credentials
secrets.json
credentials.json
service-account.json
*-credentials.json

# Database files
*.db
*.sqlite
*.sqlite3

# Logs
logs/
*.log
npm-debug.log*

# Runtime data
pids
*.pid
*.seed
*.pid.lock

# Coverage directory
coverage/
.nyc_output/

# Optional npm cache directory
.npm

# Optional eslint cache
.eslintcache

# Optional REPL history
.node_repl_history

# Output of 'npm pack'
*.tgz

# Yarn
.yarn-integrity
.pnp.*
.yarn/cache
.yarn/unplugged
.yarn/build-state.yml
.yarn/install-state.gz

# IDE
.vscode/
.idea/
*.swp
*.swo
*~

# OS
.DS_Store
Thumbs.db

# Build outputs
dist/
build/
out/

# Temporary files
tmp/
temp/
*.tmp
`,
      installCommand: null,
      usageExample: 'Append this content to your existing .gitignore file'
    };
  }

  /**
   * Display all generated configurations
   */
  displayConfigs(configs) {
    const chalk = require('chalk');

    console.log(chalk.cyan('═'.repeat(70)));
    console.log(chalk.cyan('  📦 Generated Security Configurations'));
    console.log(chalk.cyan('═'.repeat(70)));
    console.log();

    configs.forEach((config, index) => {
      console.log(chalk.yellow(`\n${index + 1}. ${config.name}`));
      console.log(chalk.dim('─'.repeat(70)));
      console.log(chalk.gray(`Description: ${config.description}`));
      console.log();

      if (config.installCommand) {
        console.log(chalk.green('📥 Install:'));
        console.log(chalk.green(`   ${config.installCommand}`));
        console.log();
      }

      console.log(chalk.blue('📄 Code:'));
      console.log(chalk.dim('─'.repeat(70)));
      console.log(chalk.white(config.content));
      console.log(chalk.dim('─'.repeat(70)));

      if (config.usageExample) {
        console.log();
        console.log(chalk.magenta('💡 Usage:'));
        console.log(chalk.magenta(`   ${config.usageExample}`));
      }

      console.log();
    });

    console.log(chalk.cyan('\n' + '═'.repeat(70)));
    console.log(chalk.green('✅ To save any config, copy the code above to the respective file.'));
    console.log(chalk.cyan('═'.repeat(70)));
    console.log();
  }
}

module.exports = ConfigGenerator;
