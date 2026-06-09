const fs = require('fs');
const path = require('path');
const { glob } = require('glob');

/**
 * OWASP Top 10 vulnerability scanner for web applications
 * Detects common security issues in code
 */
class OwaspScanner {
  constructor(options = {}) {
    this.targetPath = options.targetPath || process.cwd();
    this.results = [];
  }

  /**
   * Run OWASP Top 10 scans
   */
  async scan() {
    console.log('\n🛡️  Scanning for OWASP Top 10 vulnerabilities...\n');

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
   * Get relevant source files to scan
   */
  async getRelevantFiles() {
    const extensions = ['*.js', '*.ts', '*.jsx', '*.tsx', '*.py', '*.rb', '*.php', '*.java', '*.go'];
    const files = [];

    for (const ext of extensions) {
      try {
        const found = await glob(`**/${ext}`, {
          cwd: this.targetPath,
          nodir: true,
          ignore: ['node_modules/**', '.git/**', 'dist/**', 'build/**', 'test/**', 'tests/**'],
          absolute: true
        });
        files.push(...found);
      } catch (error) {
        // Continue with other extensions
      }
    }

    return [...new Set(files)]; // Remove duplicates
  }

  /**
   * Scan a file for OWASP vulnerabilities
   */
  scanFile(filePath, content) {
    const findings = [];

    findings.push(...this.checkSQLInjection(filePath, content));
    findings.push(...this.checkXSS(filePath, content));
    findings.push(...this.checkBrokenAuth(filePath, content));
    findings.push(...this.checkSensitiveDataExposure(filePath, content));
    findings.push(...this.checkXXE(filePath, content));
    findings.push(...this.checkBrokenAccessControl(filePath, content));
    findings.push(...this.checkSecurityMisconfiguration(filePath, content));
    findings.push(...this.checkInsecureDeserialization(filePath, content));
    findings.push(...this.checkInsufficientLogging(filePath, content));
    findings.push(...this.checkServerSideRequestForgery(filePath, content));

    return findings;
  }

  /**
   * A03:2021 - Injection (SQL, NoSQL, Command, etc.)
   */
  checkSQLInjection(filePath, content) {
    const findings = [];
    const relativePath = path.relative(this.targetPath, filePath);

    // SQL injection patterns
    const sqlPatterns = [
      {
        pattern: /(?:query|execute)\s*\(\s*['"`].*\$\{.*\}.*['"`]/g,
        title: 'Potential SQL Injection via string interpolation',
        remediation: 'Use parameterized queries or prepared statements. Never concatenate user input into SQL.',
        owasp: 'A03:2021 – Injection'
      },
      {
        pattern: /(?:query|execute)\s*\(\s*['"`].*\+.*\+.*['"`]/g,
        title: 'Potential SQL Injection via string concatenation',
        remediation: 'Use parameterized queries. Example: db.query("SELECT * FROM users WHERE id = $1", [userId])',
        owasp: 'A03:2021 – Injection'
      },
      {
        pattern: /mysql\.query\s*\([^)]*\+/g,
        title: 'MySQL query with string concatenation',
        remediation: 'Use parameterized queries with mysql2 library.',
        owasp: 'A03:2021 – Injection'
      },
      {
        pattern: /sequelize\.query\s*\([^)]*\$\{/g,
        title: 'Sequelize raw query with template literals',
        remediation: 'Use Sequelize ORM methods or parameterized replacements.',
        owasp: 'A03:2021 – Injection'
      }
    ];

    sqlPatterns.forEach(({ pattern, title, remediation, owasp }) => {
      pattern.lastIndex = 0;
      if (pattern.test(content)) {
        const lineNum = this.findLineNumber(content, pattern);
        findings.push({
          id: `OWASP-A03-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`,
          type: 'injection',
          category: 'sql-injection',
          severity: 'critical',
          title,
          file: relativePath,
          line: lineNum,
          remediation,
          owaspReference: owasp
        });
      }
    });

    // Command injection
    if (/exec\s*\(|execSync\s*\(|spawn\s*\(/.test(content) && /\$\{|concat|\+/.test(content)) {
      findings.push({
        id: `OWASP-A03-CMD-${Date.now()}`,
        type: 'injection',
        category: 'command-injection',
        severity: 'critical',
        title: 'Potential Command Injection',
        file: relativePath,
        line: this.findLineNumber(content, /exec\s*\(/),
        remediation: 'Avoid executing system commands with user input. Use safe alternatives or sanitize inputs thoroughly.',
        owaspReference: 'A03:2021 – Injection'
      });
    }

    return findings;
  }

  /**
   * A03:2021 - Cross-Site Scripting (XSS)
   */
  checkXSS(filePath, content) {
    const findings = [];
    const relativePath = path.relative(this.targetPath, filePath);

    // Dangerous innerHTML usage
    if (/\.innerHTML\s*=/.test(content)) {
      findings.push({
        id: `OWASP-XSS-${Date.now()}`,
        type: 'xss',
        category: 'dom-based-xss',
        severity: 'high',
        title: 'Dangerous innerHTML assignment',
        file: relativePath,
        line: this.findLineNumber(content, /\.innerHTML\s*=/),
        remediation: 'Use textContent instead of innerHTML, or sanitize HTML with DOMPurify before setting innerHTML.',
        owaspReference: 'A03:2021 – Injection'
      });
    }

    // React dangerouslySetInnerHTML
    if (/dangerouslySetInnerHTML/.test(content)) {
      findings.push({
        id: `OWASP-XSS-REACT-${Date.now()}`,
        type: 'xss',
        category: 'react-xss',
        severity: 'high',
        title: 'React dangerouslySetInnerHTML usage',
        file: relativePath,
        line: this.findLineNumber(content, /dangerouslySetInnerHTML/),
        remediation: 'Sanitize HTML with DOMPurify before using dangerouslySetInnerHTML. Consider safer alternatives.',
        owaspReference: 'A03:2021 – Injection'
      });
    }

    // document.write usage
    if (/document\.write\s*\(/.test(content)) {
      findings.push({
        id: `OWASP-XSS-DW-${Date.now()}`,
        type: 'xss',
        category: 'document-write',
        severity: 'medium',
        title: 'document.write() usage detected',
        file: relativePath,
        line: this.findLineNumber(content, /document\.write/),
        remediation: 'Avoid document.write(). Use DOM manipulation methods like createElement and appendChild.',
        owaspReference: 'A03:2021 – Injection'
      });
    }

    // eval() usage
    if (/\beval\s*\(/.test(content) && !/\/\/.*eval/.test(content)) {
      findings.push({
        id: `OWASP-XSS-EVAL-${Date.now()}`,
        type: 'xss',
        category: 'code-evaluation',
        severity: 'critical',
        title: 'eval() usage detected',
        file: relativePath,
        line: this.findLineNumber(content, /\beval\s*\(/),
        remediation: 'NEVER use eval() with user input. Use JSON.parse() for JSON, or find safer alternatives.',
        owaspReference: 'A03:2021 – Injection'
      });
    }

    return findings;
  }

  /**
   * A07:2021 - Broken Authentication
   */
  checkBrokenAuth(filePath, content) {
    const findings = [];
    const relativePath = path.relative(this.targetPath, filePath);

    // Weak password hashing
    if (/md5\s*\(|sha1\s*\(/.test(content) && /password/i.test(content)) {
      findings.push({
        id: `OWASP-AUTH-${Date.now()}`,
        type: 'broken-auth',
        category: 'weak-hashing',
        severity: 'critical',
        title: 'Weak password hashing algorithm',
        file: relativePath,
        line: this.findLineNumber(content, /md5|sha1/),
        remediation: 'Use bcrypt, scrypt, or argon2 for password hashing. MD5 and SHA1 are cryptographically broken.',
        owaspReference: 'A07:2021 – Identification and Authentication Failures'
      });
    }

    // Hardcoded credentials
    if (/password\s*[=:]\s*['"](admin|password|123456)['"]/i.test(content)) {
      findings.push({
        id: `OWASP-AUTH-CRED-${Date.now()}`,
        type: 'broken-auth',
        category: 'default-credentials',
        severity: 'critical',
        title: 'Default or weak credentials detected',
        file: relativePath,
        line: this.findLineNumber(content, /password\s*[=:]/),
        remediation: 'Never use default credentials. Enforce strong password policies and use environment variables.',
        owaspReference: 'A07:2021 – Identification and Authentication Failures'
      });
    }

    // Missing rate limiting on auth endpoints
    if (/(?:login|signin|auth)/i.test(content) && !/rate[-_]?limit/i.test(content)) {
      // This is a soft check - just informational
      // We'll add it only if we detect auth routes
    }

    return findings;
  }

  /**
   * A02:2021 - Cryptographic Failures (Sensitive Data Exposure)
   */
  checkSensitiveDataExposure(filePath, content) {
    const findings = [];
    const relativePath = path.relative(this.targetPath, filePath);

    // HTTP instead of HTTPS
    if (/http:\/\/(?!localhost|127\.0\.0\.1)/.test(content)) {
      findings.push({
        id: `OWASP-CRYPTO-${Date.now()}`,
        type: 'sensitive-data-exposure',
        category: 'insecure-transport',
        severity: 'high',
        title: 'HTTP URL detected (should use HTTPS)',
        file: relativePath,
        line: this.findLineNumber(content, /http:\/\//),
        remediation: 'Use HTTPS for all external API calls and services. Never send sensitive data over HTTP.',
        owaspReference: 'A02:2021 – Cryptographic Failures'
      });
    }

    // Logging sensitive data
    if (/console\.(log|info|debug)\s*\(.*(?:password|token|secret|key|credit[-_]?card|ssn)/i.test(content)) {
      findings.push({
        id: `OWASP-CRYPTO-LOG-${Date.now()}`,
        type: 'sensitive-data-exposure',
        category: 'sensitive-data-logging',
        severity: 'high',
        title: 'Sensitive data being logged',
        file: relativePath,
        line: this.findLineNumber(content, /console\.(log|info|debug)/),
        remediation: 'Never log passwords, tokens, secrets, or PII. Use structured logging with sensitive fields filtered.',
        owaspReference: 'A02:2021 – Cryptographic Failures'
      });
    }

    // Storing credit card numbers
    if (/credit[-_]?card|card[_-]?number|cc[_-]?num/i.test(content) && /(?:save|store|insert|create)/i.test(content)) {
      findings.push({
        id: `OWASP-CRYPTO-CC-${Date.now()}`,
        type: 'sensitive-data-exposure',
        category: 'pci-compliance',
        severity: 'critical',
        title: 'Potential credit card storage',
        file: relativePath,
        line: this.findLineNumber(content, /credit[-_]?card|card[_-]?number/),
        remediation: 'NEVER store credit card numbers. Use payment processors (Stripe, PayPal) with tokenization.',
        owaspReference: 'A02:2021 – Cryptographic Failures'
      });
    }

    return findings;
  }

  /**
   * A05:2021 - Security Misconfiguration
   */
  checkSecurityMisconfiguration(filePath, content) {
    const findings = [];
    const relativePath = path.relative(this.targetPath, filePath);

    // CORS wildcard
    if (/Access-Control-Allow-Origin.*\*/.test(content)) {
      findings.push({
        id: `OWASP-MISCORF-${Date.now()}`,
        type: 'security-misconfiguration',
        category: 'cors-wildcard',
        severity: 'medium',
        title: 'CORS wildcard (*) configuration',
        file: relativePath,
        line: this.findLineNumber(content, /Access-Control-Allow-Origin/),
        remediation: 'Specify allowed origins explicitly instead of using wildcard. Restrict to trusted domains.',
        owaspReference: 'A05:2021 – Security Misconfiguration'
      });
    }

    // Debug mode enabled in production
    if (/debug\s*[=:]\s*(true|1)/i.test(content) && !/test|spec/i.test(filePath)) {
      findings.push({
        id: `OWASP-MISCORF-DBG-${Date.now()}`,
        type: 'security-misconfiguration',
        category: 'debug-enabled',
        severity: 'medium',
        title: 'Debug mode may be enabled',
        file: relativePath,
        line: this.findLineNumber(content, /debug\s*[=:]/),
        remediation: 'Disable debug mode in production. Use environment variables to control debug settings.',
        owaspReference: 'A05:2021 – Security Misconfiguration'
      });
    }

    // Verbose error messages
    if (/error\.message|error\.stack|err\.stack/.test(content) && /res\.send|res\.json/.test(content)) {
      findings.push({
        id: `OWASP-MISCORF-ERR-${Date.now()}`,
        type: 'security-misconfiguration',
        category: 'verbose-errors',
        severity: 'medium',
        title: 'Detailed error messages sent to client',
        file: relativePath,
        line: this.findLineNumber(content, /error\.stack|err\.stack/),
        remediation: 'Send generic error messages to clients. Log detailed errors server-side only.',
        owaspReference: 'A05:2021 – Security Misconfiguration'
      });
    }

    return findings;
  }

  /**
   * A01:2021 - Broken Access Control
   */
  checkBrokenAccessControl(filePath, content) {
    const findings = [];
    const relativePath = path.relative(this.targetPath, filePath);

    // Missing authorization checks on admin routes
    if (/admin|manage|delete|update/i.test(filePath) && !/auth|middleware|guard|protect/i.test(content)) {
      // Soft check - only flag if it looks like a route handler without auth
      if (/(app\.get|app\.post|router\.get|router\.post)/.test(content)) {
        findings.push({
          id: `OWASP-ACCESS-${Date.now()}`,
          type: 'broken-access-control',
          category: 'missing-authz',
          severity: 'high',
          title: 'Route may lack authorization checks',
          file: relativePath,
          line: this.findLineNumber(content, /app\.(get|post)|router\.(get|post)/),
          remediation: 'Add authentication middleware and authorization checks to sensitive routes.',
          owaspReference: 'A01:2021 – Broken Access Control'
        });
      }
    }

    // Direct object reference without validation
    if (/req\.params\.id|req\.query\.id/.test(content) && /findById|findOne/.test(content) && !/userId|ownerId|belongs/i.test(content)) {
      findings.push({
        id: `OWASP-ACCESS-IDOR-${Date.now()}`,
        type: 'broken-access-control',
        category: 'idor',
        severity: 'high',
        title: 'Potential Insecure Direct Object Reference (IDOR)',
        file: relativePath,
        line: this.findLineNumber(content, /req\.params\.id|req\.query\.id/),
        remediation: 'Verify that the authenticated user has permission to access the requested resource.',
        owaspReference: 'A01:2021 – Broken Access Control'
      });
    }

    return findings;
  }

  /**
   * A08:2021 - Software and Data Integrity Failures
   */
  checkInsecureDeserialization(filePath, content) {
    const findings = [];
    const relativePath = path.relative(this.targetPath, filePath);

    // Unsafe deserialization
    if (/JSON\.parse\s*\(.*req\.(body|params|query)/.test(content)) {
      findings.push({
        id: `OWASP-DESER-${Date.now()}`,
        type: 'integrity-failure',
        category: 'unsafe-deserialization',
        severity: 'medium',
        title: 'Untrusted data deserialization',
        file: relativePath,
        line: this.findLineNumber(content, /JSON\.parse/),
        remediation: 'Validate and sanitize data before parsing. Use schema validation (Zod, Yup) for incoming data.',
        owaspReference: 'A08:2021 – Software and Data Integrity Failures'
      });
    }

    return findings;
  }

  /**
   * A09:2021 - Security Logging and Monitoring Failures
   */
  checkInsufficientLogging(filePath, content) {
    const findings = [];
    const relativePath = path.relative(this.targetPath, filePath);

    // Auth events without logging
    if (/(?:login|logout|register|password[_-]?reset)/i.test(content) && !/log|audit|track|monitor/i.test(content)) {
      // Only flag if it's clearly an auth handler
      if (/(async|function).*?(login|auth|register)/i.test(content)) {
        findings.push({
          id: `OWASP-LOG-${Date.now()}`,
          type: 'insufficient-logging',
          category: 'auth-events-not-logged',
          severity: 'low',
          title: 'Authentication event may not be logged',
          file: relativePath,
          line: this.findLineNumber(content, /login|register|auth/),
          remediation: 'Log authentication events (success/failure) for security monitoring and incident response.',
          owaspReference: 'A09:2021 – Security Logging and Monitoring Failures'
        });
      }
    }

    return findings;
  }

  /**
   * A10:2021 - Server-Side Request Forgery (SSRF)
   */
  checkServerSideRequestForgery(filePath, content) {
    const findings = [];
    const relativePath = path.relative(this.targetPath, filePath);

    // Fetch/axios with user-controlled URL
    if (/(?:fetch|axios\.get|http\.get)\s*\(.*req\.(body|params|query)/.test(content)) {
      findings.push({
        id: `OWASP-SSRF-${Date.now()}`,
        type: 'ssrf',
        category: 'user-controlled-url',
        severity: 'high',
        title: 'Potential SSRF - User-controlled URL in request',
        file: relativePath,
        line: this.findLineNumber(content, /fetch|axios\.get/),
        remediation: 'Validate and whitelist URLs before making server-side requests. Block internal IP ranges.',
        owaspReference: 'A10:2021 – Server-Side Request Forgery'
      });
    }

    return findings;
  }

  /**
   * Placeholder checks for XXE (more relevant in XML-processing apps)
   */
  checkXXE(filePath, content) {
    // XXE is primarily relevant for XML parsers
    // Basic check for XML parsing without security features
    return [];
  }

  /**
   * Helper: Find line number for a pattern match
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
   * Get summary by vulnerability category
   */
  getCategorySummary() {
    const summary = {};
    this.results.forEach(finding => {
      summary[finding.category] = (summary[finding.category] || 0) + 1;
    });
    return summary;
  }
}

module.exports = OwaspScanner;
