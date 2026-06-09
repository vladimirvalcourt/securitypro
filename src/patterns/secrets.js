/**
 * Secret detection patterns for hardcoded credentials, API keys, and tokens
 * Covers major cloud providers, databases, payment processors, and common services
 */

const SECRET_PATTERNS = [
  // AWS Credentials
  {
    name: 'AWS Access Key ID',
    pattern: /(?:AKIA|ABIA|ACCA|ASIA)[0-9A-Z]{16}/g,
    severity: 'critical',
    category: 'cloud-provider',
    remediation: 'Remove AWS credentials from code. Use environment variables or AWS IAM roles.',
    envVar: 'AWS_ACCESS_KEY_ID'
  },
  {
    name: 'AWS Secret Access Key',
    pattern: /(?<![A-Za-z0-9/+=])[A-Za-z0-9/+=]{40}(?![A-Za-z0-9/+=])/g,
    severity: 'critical',
    category: 'cloud-provider',
    remediation: 'Remove AWS secret keys from code. Use AWS Secrets Manager or environment variables.',
    envVar: 'AWS_SECRET_ACCESS_KEY'
  },

  // Google Cloud
  {
    name: 'Google API Key',
    pattern: /AIza[0-9A-Za-z_-]{35}/g,
    severity: 'high',
    category: 'cloud-provider',
    remediation: 'Restrict API key usage in Google Cloud Console. Move to environment variables.',
    envVar: 'GOOGLE_API_KEY'
  },
  {
    name: 'Google OAuth Client Secret',
    pattern: /GOCSPX-[0-9a-zA-Z_-]{28}/g,
    severity: 'high',
    category: 'cloud-provider',
    remediation: 'Store OAuth secrets in environment variables or secret manager.',
    envVar: 'GOOGLE_CLIENT_SECRET'
  },

  // GitHub
  {
    name: 'GitHub Personal Access Token',
    pattern: /ghp_[A-Za-z0-9_]{36}/g,
    severity: 'critical',
    category: 'version-control',
    remediation: 'Revoke token immediately. Use GitHub Actions secrets or environment variables.',
    envVar: 'GITHUB_TOKEN'
  },
  {
    name: 'GitHub Fine-grained PAT',
    pattern: /github_pat_[A-Za-z0-9_]{82}/g,
    severity: 'critical',
    category: 'version-control',
    remediation: 'Revoke token immediately. Store in secure environment variables.',
    envVar: 'GITHUB_TOKEN'
  },

  // Stripe
  {
    name: 'Stripe Secret Key',
    pattern: /sk_live_[0-9a-zA-Z]{24}/g,
    severity: 'critical',
    category: 'payment',
    remediation: 'CRITICAL: Remove Stripe secret key! Use environment variables. Rotate key immediately.',
    envVar: 'STRIPE_SECRET_KEY'
  },
  {
    name: 'Stripe Test Key',
    pattern: /sk_test_[0-9a-zA-Z]{24}/g,
    severity: 'medium',
    category: 'payment',
    remediation: 'Move test keys to environment variables even for development.',
    envVar: 'STRIPE_TEST_KEY'
  },

  // OpenAI
  {
    name: 'OpenAI API Key',
    pattern: /sk-[A-Za-z0-9_-]{48}/g,
    severity: 'high',
    category: 'ai-service',
    remediation: 'Store OpenAI API keys in environment variables or secret manager.',
    envVar: 'OPENAI_API_KEY'
  },

  // Database Connection Strings
  {
    name: 'MongoDB Connection String',
    pattern: /mongodb(\+srv)?:\/\/[^:\s]+:[^@\s]+@[^\s]+/g,
    severity: 'critical',
    category: 'database',
    remediation: 'Never commit database connection strings. Use environment variables with MONGODB_URI.',
    envVar: 'MONGODB_URI'
  },
  {
    name: 'PostgreSQL Connection String',
    pattern: /postgresql:\/\/[^:\s]+:[^@\s]+@[^\s]+/g,
    severity: 'critical',
    category: 'database',
    remediation: 'Remove PostgreSQL credentials. Use DATABASE_URL environment variable.',
    envVar: 'DATABASE_URL'
  },
  {
    name: 'MySQL Connection String',
    pattern: /mysql:\/\/[^:\s]+:[^@\s]+@[^\s]+/g,
    severity: 'critical',
    category: 'database',
    remediation: 'Remove MySQL credentials. Use environment variables for connection details.',
    envVar: 'MYSQL_URL'
  },
  {
    name: 'Redis Connection String',
    pattern: /redis:\/\/:[^@]+@[^\s]+/g,
    severity: 'high',
    category: 'database',
    remediation: 'Remove Redis passwords from code. Use REDIS_URL environment variable.',
    envVar: 'REDIS_URL'
  },

  // Firebase
  {
    name: 'Firebase API Key',
    pattern: /AIzaSy[A-Za-z0-9_-]{33}/g,
    severity: 'medium',
    category: 'cloud-provider',
    remediation: 'Restrict Firebase API key in console. Consider using environment variables.',
    envVar: 'FIREBASE_API_KEY'
  },

  // JWT & Tokens
  {
    name: 'JWT Secret',
    pattern: /(?:jwt[_-]?secret|token[_-]?secret)\s*[=:]\s*['"][^'"]{16,}['"]/gi,
    severity: 'high',
    category: 'authentication',
    remediation: 'Use strong random JWT secrets stored in environment variables (JWT_SECRET).',
    envVar: 'JWT_SECRET'
  },

  // Generic Patterns
  {
    name: 'Generic API Key Assignment',
    pattern: /(?:api[_-]?key|apikey)\s*[=:]\s*['"][A-Za-z0-9_-]{20,}['"]/gi,
    severity: 'high',
    category: 'generic',
    remediation: 'Move API keys to environment variables (.env file, not committed).',
    envVar: 'API_KEY'
  },
  {
    name: 'Generic Password Assignment',
    pattern: /(?:password|passwd|pwd)\s*[=:]\s*['"][^'"]{8,}['"]/gi,
    severity: 'critical',
    category: 'generic',
    remediation: 'NEVER hardcode passwords. Use environment variables or secret manager.',
    envVar: 'PASSWORD'
  },
  {
    name: 'Generic Secret Assignment',
    pattern: /(?:secret|private[_-]?key)\s*[=:]\s*['"][A-Za-z0-9_-]{16,}['"]/gi,
    severity: 'high',
    category: 'generic',
    remediation: 'Move secrets to environment variables. Never commit sensitive data.',
    envVar: 'SECRET'
  },

  // Slack
  {
    name: 'Slack Bot Token',
    pattern: /xoxb-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24}/g,
    severity: 'high',
    category: 'communication',
    remediation: 'Rotate Slack token. Store in environment variables (SLACK_BOT_TOKEN).',
    envVar: 'SLACK_BOT_TOKEN'
  },
  {
    name: 'Slack Webhook URL',
    pattern: /https:\/\/hooks\.slack\.com\/services\/[A-Za-z0-9/]+/g,
    severity: 'medium',
    category: 'communication',
    remediation: 'Move Slack webhook URLs to environment variables.',
    envVar: 'SLACK_WEBHOOK_URL'
  },

  // Twilio
  {
    name: 'Twilio Auth Token',
    pattern: /[0-9a-f]{32}/g,
    severity: 'high',
    category: 'communication',
    remediation: 'Store Twilio credentials in environment variables (TWILIO_AUTH_TOKEN).',
    envVar: 'TWILIO_AUTH_TOKEN'
  },

  // SendGrid
  {
    name: 'SendGrid API Key',
    pattern: /SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}/g,
    severity: 'high',
    category: 'email',
    remediation: 'Move SendGrid API key to environment variables (SENDGRID_API_KEY).',
    envVar: 'SENDGRID_API_KEY'
  },

  // Mailchimp
  {
    name: 'Mailchimp API Key',
    pattern: /[0-9a-f]{32}-us[0-9]{1,2}/g,
    severity: 'medium',
    category: 'email',
    remediation: 'Store Mailchimp API key in environment variables.',
    envVar: 'MAILCHIMP_API_KEY'
  },

  // Heroku
  {
    name: 'Heroku API Key',
    pattern: /[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/g,
    severity: 'high',
    category: 'cloud-provider',
    remediation: 'Use Heroku config vars instead of hardcoded API keys.',
    envVar: 'HEROKU_API_KEY'
  },

  // DigitalOcean
  {
    name: 'DigitalOcean API Token',
    pattern: /dop_v1_[a-f0-9]{64}/g,
    severity: 'high',
    category: 'cloud-provider',
    remediation: 'Store DigitalOcean tokens in environment variables.',
    envVar: 'DIGITALOCEAN_TOKEN'
  },

  // NPM
  {
    name: 'NPM Access Token',
    pattern: /npm_[A-Za-z0-9]{36}/g,
    severity: 'high',
    category: 'package-manager',
    remediation: 'Use .npmrc file (not committed) or CI/CD secrets for NPM tokens.',
    envVar: 'NPM_TOKEN'
  },

  // Private Keys
  {
    name: 'RSA Private Key',
    pattern: /-----BEGIN RSA PRIVATE KEY-----/g,
    severity: 'critical',
    category: 'encryption',
    remediation: 'NEVER commit private keys. Use key management service or vault.',
    envVar: null
  },
  {
    name: 'EC Private Key',
    pattern: /-----BEGIN EC PRIVATE KEY-----/g,
    severity: 'critical',
    category: 'encryption',
    remediation: 'NEVER commit private keys. Use secure key storage.',
    envVar: null
  },
  {
    name: 'Generic Private Key',
    pattern: /-----BEGIN PRIVATE KEY-----/g,
    severity: 'critical',
    category: 'encryption',
    remediation: 'NEVER commit private keys. Use environment variables or vault.',
    envVar: null
  }
];

// Files to always skip (build artifacts, dependencies, etc.)
const IGNORED_FILES = [
  'node_modules',
  '.git',
  'dist',
  'build',
  '*.min.js',
  '*.bundle.js',
  'package-lock.json',
  'yarn.lock',
  'pnpm-lock.yaml',
  '*.log',
  '.DS_Store',
  'coverage',
  '.nyc_output'
];

module.exports = {
  SECRET_PATTERNS,
  IGNORED_FILES
};
