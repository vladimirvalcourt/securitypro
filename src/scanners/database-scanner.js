const fs = require('fs');
const path = require('path');
const { glob } = require('glob');

/**
 * Database & Storage security scanner
 * Checks for database misconfigurations, injection risks, and data exposure
 */
class DatabaseScanner {
  constructor(options = {}) {
    this.targetPath = options.targetPath || process.cwd();
    this.results = [];
  }

  /**
   * Run database security scans
   */
  async scan() {
    console.log('\n🗄️  Scanning database and storage configurations...\n');

    const files = await this.getRelevantFiles();

    for (const file of files) {
      try {
        const content = fs.readFileSync(file, 'utf-8');
        const findings = this.scanFile(file, content);
        this.results.push(...findings);
      } catch (error) {
        continue;
      }
    }

    return {
      totalFindings: this.results.length,
      findings: this.results,
      severity: this.calculateSeverity(),
      byCategory: this.getCategorySummary()
    };
  }

  /**
   * Get relevant database-related files
   */
  async getRelevantFiles() {
    const patterns = [
      '**/*database*',
      '**/*db*',
      '**/*model*',
      '**/*schema*',
      '**/*migration*',
      '**/ormconfig*',
      '**/.env*',
      '**/config/*',
      '**/*.sql'
    ];

    const files = [];
    for (const pattern of patterns) {
      try {
        const found = await glob(pattern, {
          cwd: this.targetPath,
          nodir: true,
          ignore: ['node_modules/**', '.git/**'],
          absolute: true
        });
        files.push(...found);
      } catch (error) {
        // Continue
      }
    }

    // Also scan all JS/TS files for database operations
    try {
      const codeFiles = await glob('**/*.{js,ts,jsx,tsx}', {
        cwd: this.targetPath,
        nodir: true,
        ignore: ['node_modules/**', '.git/**', 'dist/**', 'build/**'],
        absolute: true
      });
      files.push(...codeFiles);
    } catch (error) {
      // Continue
    }

    return [...new Set(files)];
  }

  /**
   * Scan a file for database security issues
   */
  scanFile(filePath, content) {
    const findings = [];

    findings.push(...this.checkConnectionStrings(filePath, content));
    findings.push(...this.checkQuerySafety(filePath, content));
    findings.push(...this.checkDataValidation(filePath, content));
    findings.push(...this.checkErrorHandling(filePath, content));
    findings.push(...this.checkAccessControl(filePath, content));
    findings.push(...this.checkEncryption(filePath, content));

    return findings;
  }

  /**
   * Check database connection string security
   */
  checkConnectionStrings(filePath, content) {
    const findings = [];
    const relativePath = path.relative(this.targetPath, filePath);

    // Hardcoded database credentials in connection strings
    const connStringPatterns = [
      {
        pattern: /mongodb(\+srv)?:\/\/[^:\s]+:[^@\s]+@[^\s]+/g,
        title: 'Hardcoded MongoDB connection string',
        remediation: 'Use environment variable MONGODB_URI. Never commit database credentials to version control.',
        category: 'hardcoded-credentials'
      },
      {
        pattern: /postgresql:\/\/[^:\s]+:[^@\s]+@[^\s]+/g,
        title: 'Hardcoded PostgreSQL connection string',
        remediation: 'Use environment variable DATABASE_URL. Store credentials securely.',
        category: 'hardcoded-credentials'
      },
      {
        pattern: /mysql:\/\/[^:\s]+:[^@\s]+@[^\s]+/g,
        title: 'Hardcoded MySQL connection string',
        remediation: 'Use environment variables for MySQL credentials.',
        category: 'hardcoded-credentials'
      }
    ];

    connStringPatterns.forEach(({ pattern, title, remediation, category }) => {
      pattern.lastIndex = 0;
      if (pattern.test(content)) {
        findings.push({
          id: `DB-CRED-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`,
          type: 'database-security',
          category,
          severity: 'critical',
          title,
          file: relativePath,
          line: this.findLineNumber(content, pattern),
          remediation,
          owaspReference: 'A07:2021 – Identification and Authentication Failures'
        });
      }
    });

    // Database config without SSL/TLS
    if (/mongoose\.connect|sequelize|knex/.test(content) && !/ssl|tls|useSSL/i.test(content)) {
      findings.push({
        id: `DB-SSL-${Date.now()}`,
        type: 'database-security',
        category: 'missing-encryption',
        severity: 'high',
        title: 'Database connection without SSL/TLS',
        file: relativePath,
        line: this.findLineNumber(content, /mongoose\.connect|sequelize|knex/),
        remediation: 'Enable SSL/TLS for database connections in production. Add ssl: true or useSSL: true to connection config.',
        owaspReference: 'A02:2021 – Cryptographic Failures'
      });
    }

    return findings;
  }

  /**
   * Check query safety and injection prevention
   */
  checkQuerySafety(filePath, content) {
    const findings = [];
    const relativePath = path.relative(this.targetPath, filePath);

    // Raw SQL queries with string interpolation
    if (/\.query\s*\(`.*\$\{/.test(content)) {
      findings.push({
        id: `DB-SQL-INJ-${Date.now()}`,
        type: 'database-security',
        category: 'sql-injection-risk',
        severity: 'critical',
        title: 'Raw SQL query with template literal interpolation',
        file: relativePath,
        line: this.findLineNumber(content, /\.query\s*\(`/),
        remediation: 'Use parameterized queries instead of string interpolation. Example: db.query("SELECT * FROM users WHERE id = $1", [userId])',
        owaspReference: 'A03:2021 – Injection'
      });
    }

    // NoSQL injection via user input
    if (/\.find\s*\(|\.findOne\s*\(/.test(content) && /req\.(body|params|query)/.test(content)) {
      findings.push({
        id: `DB-NOSQL-INJ-${Date.now()}`,
        type: 'database-security',
        category: 'nosql-injection-risk',
        severity: 'high',
        title: 'Potential NoSQL injection via user input',
        file: relativePath,
        line: this.findLineNumber(content, /\.find\s*\(|\.findOne\s*\(/),
        remediation: 'Validate and sanitize user input before using in database queries. Use schema validation (Zod, Yup).',
        owaspReference: 'A03:2021 – Injection'
      });
    }

    // Missing input sanitization
    if (/User\.create|Model\.create/.test(content) && /req\.body/.test(content) && !/sanitize|validate|pick/.test(content)) {
      findings.push({
        id: `DB-INPUT-${Date.now()}`,
        type: 'database-security',
        category: 'missing-input-validation',
        severity: 'medium',
        title: 'Direct user input to database without validation',
        file: relativePath,
        line: this.findLineNumber(content, /User\.create|Model\.create/),
        remediation: 'Validate and sanitize user input before database operations. Use schema validation libraries.',
        owaspReference: 'A03:2021 – Injection'
      });
    }

    return findings;
  }

  /**
   * Check data validation and schema enforcement
   */
  checkDataValidation(filePath, content) {
    const findings = [];
    const relativePath = path.relative(this.targetPath, filePath);

    // Models without validation schemas
    if (/(?:new Schema|defineModel|createTable)/i.test(content) && !/required|validate|min|max/.test(content)) {
      findings.push({
        id: `DB-SCHEMA-${Date.now()}`,
        type: 'database-security',
        category: 'missing-schema-validation',
        severity: 'medium',
        title: 'Database model without field validation',
        file: relativePath,
        line: this.findLineNumber(content, /new Schema|defineModel|createTable/i),
        remediation: 'Add validation rules to database models (required fields, min/max lengths, type checks).',
        owaspReference: 'A08:2021 – Software and Data Integrity Failures'
      });
    }

    // Missing unique constraints on sensitive fields
    if (/email|username|phone/.test(content) && /Schema|model/.test(content) && !/unique:\s*true|uniqueIndex/.test(content)) {
      findings.push({
        id: `DB-UNIQUE-${Date.now()}`,
        type: 'database-security',
        category: 'missing-unique-constraint',
        severity: 'low',
        title: 'Sensitive field may lack unique constraint',
        file: relativePath,
        line: this.findLineNumber(content, /email|username|phone/),
        remediation: 'Add unique constraints to email, username, and other identifier fields to prevent duplicates.',
        owaspReference: 'A08:2021 – Software and Data Integrity Failures'
      });
    }

    return findings;
  }

  /**
   * Check database error handling
   */
  checkErrorHandling(filePath, content) {
    const findings = [];
    const relativePath = path.relative(this.targetPath, filePath);

    // Database errors sent to client
    if (/catch.*err/.test(content) && /res\.(send|json).*err/.test(content)) {
      findings.push({
        id: `DB-ERR-DISC-${Date.now()}`,
        type: 'database-security',
        category: 'error-disclosure',
        severity: 'medium',
        title: 'Database error details sent to client',
        file: relativePath,
        line: this.findLineNumber(content, /res\.(send|json).*err/),
        remediation: 'Send generic error messages to clients. Log detailed errors server-side only.',
        owaspReference: 'A05:2021 – Security Misconfiguration'
      });
    }

    // Unhandled promise rejections in database operations
    if (/(?:\.save\(\)|\.insert\(\)|\.update\(\))/.test(content) && !/await|\.then|\.catch/.test(content)) {
      findings.push({
        id: `DB-ERR-UNHANDLED-${Date.now()}`,
        type: 'database-security',
        category: 'unhandled-promise',
        severity: 'medium',
        title: 'Database operation without error handling',
        file: relativePath,
        line: this.findLineNumber(content, /\.save\(\)|\.insert\(\)/),
        remediation: 'Always handle errors from database operations with try/catch or .catch() blocks.',
        owaspReference: 'A09:2021 – Security Logging and Monitoring Failures'
      });
    }

    return findings;
  }

  /**
   * Check database access control
   */
  checkAccessControl(filePath, content) {
    const findings = [];
    const relativePath = path.relative(this.targetPath, filePath);

    // Direct ID-based queries without ownership check
    if (/findById\(req\.params\.id\)/.test(content) && !/userId|ownerId|belongsTo|authorize/.test(content)) {
      findings.push({
        id: `DB-ACCESS-${Date.now()}`,
        type: 'database-security',
        category: 'missing-access-control',
        severity: 'high',
        title: 'Database query without ownership verification',
        file: relativePath,
        line: this.findLineNumber(content, /findById\(req\.params\.id\)/),
        remediation: 'Verify that the authenticated user owns or has permission to access the requested resource.',
        owaspReference: 'A01:2021 – Broken Access Control'
      });
    }

    // Mass assignment vulnerability
    if (/User\.create\(req\.body\)|\.update\(req\.body\)/.test(content)) {
      findings.push({
        id: `DB-MASS-ASSIGN-${Date.now()}`,
        type: 'database-security',
        category: 'mass-assignment',
        severity: 'high',
        title: 'Potential mass assignment vulnerability',
        file: relativePath,
        line: this.findLineNumber(content, /User\.create\(req\.body\)/),
        remediation: 'Whitelist allowed fields instead of passing entire req.body. Prevent users from setting admin roles, etc.',
        owaspReference: 'A01:2021 – Broken Access Control'
      });
    }

    return findings;
  }

  /**
   * Check data encryption at rest
   */
  checkEncryption(filePath, content) {
    const findings = [];
    const relativePath = path.relative(this.targetPath, filePath);

    // Sensitive fields stored unencrypted
    const sensitiveFields = ['ssn', 'social.security', 'credit.card', 'bank.account'];
    sensitiveFields.forEach(field => {
      if (new RegExp(field, 'i').test(content) && /Schema|model|column/i.test(content) && !/encrypt|hash|cipher/.test(content)) {
        findings.push({
          id: `DB-ENCRYPT-${Date.now()}`,
          type: 'database-security',
          category: 'missing-encryption-at-rest',
          severity: 'critical',
          title: `Sensitive field "${field}" may be stored unencrypted`,
          file: relativePath,
          line: this.findLineNumber(content, new RegExp(field, 'i')),
          remediation: 'Encrypt sensitive data (SSN, credit cards, bank accounts) before storing in database. Use field-level encryption.',
          owaspReference: 'A02:2021 – Cryptographic Failures'
        });
      }
    });

    return findings;
  }

  /**
   * Helper: Find line number for a pattern
   */
  findLineNumber(content, pattern) {
    const lines = content.split('\n');
    for (let i = 0; i < lines.length; i++) {
      if (pattern.test(lines[i])) {
        return i + 1;
      }
    }
    return null;
  }

  /**
   * Calculate overall severity
   */
  calculateSeverity() {
    if (this.results.length === 0) return 'none';

    const hasCritical = this.results.some(f => f.severity === 'critical');
    const hasHigh = this.results.some(f => f.severity === 'high');

    if (hasCritical) return 'critical';
    if (hasHigh) return 'high';
    return 'medium';
  }

  /**
   * Get summary by category
   */
  getCategorySummary() {
    const summary = {};
    this.results.forEach(finding => {
      summary[finding.category] = (summary[finding.category] || 0) + 1;
    });
    return summary;
  }
}

module.exports = DatabaseScanner;
