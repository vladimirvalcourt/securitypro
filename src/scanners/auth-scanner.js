const fs = require('fs');
const path = require('path');
const { glob } = require('glob');

/**
 * Authentication & Authorization security scanner
 * Checks for common auth implementation flaws
 */
class AuthScanner {
  constructor(options = {}) {
    this.targetPath = options.targetPath || process.cwd();
    this.results = [];
  }

  /**
   * Run authentication and authorization security checks
   */
  async scan() {
    console.log('\n🔐 Scanning authentication and authorization implementations...\n');

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
   * Get relevant files for auth scanning
   */
  async getRelevantFiles() {
    const patterns = [
      '**/*auth*',
      '**/*login*',
      '**/*register*',
      '**/*session*',
      '**/*token*',
      '**/*middleware*',
      '**/*route*',
      '**/app.js',
      '**/server.js',
      '**/index.js'
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

    return [...new Set(files)];
  }

  /**
   * Scan a single file for auth issues
   */
  scanFile(filePath, content) {
    const findings = [];

    findings.push(...this.checkJWTImplementation(filePath, content));
    findings.push(...this.checkSessionSecurity(filePath, content));
    findings.push(...this.checkPasswordPolicy(filePath, content));
    findings.push(...this.checkRateLimiting(filePath, content));
    findings.push(...this.checkCSRFProtection(filePath, content));
    findings.push(...this.checkOAuthImplementation(filePath, content));

    return findings;
  }

  /**
   * Check JWT implementation issues
   */
  checkJWTImplementation(filePath, content) {
    const findings = [];
    const relativePath = path.relative(this.targetPath, filePath);

    // JWT with weak algorithm
    if (/jwt\.sign/.test(content) && /algorithm.*none/i.test(content)) {
      findings.push({
        id: `AUTH-JWT-ALG-${Date.now()}`,
        type: 'authentication',
        category: 'jwt-algorithm',
        severity: 'critical',
        title: 'JWT using "none" algorithm',
        file: relativePath,
        line: this.findLineNumber(content, /algorithm.*none/i),
        remediation: 'NEVER use "none" algorithm for JWT. Use RS256 or HS256 with strong secret keys.',
        owaspReference: 'A07:2021 – Identification and Authentication Failures'
      });
    }

    // JWT without expiration
    if (/jwt\.sign/.test(content) && !/expiresIn|exp:/.test(content)) {
      findings.push({
        id: `AUTH-JWT-EXP-${Date.now()}`,
        type: 'authentication',
        category: 'jwt-no-expiry',
        severity: 'high',
        title: 'JWT token without expiration',
        file: relativePath,
        line: this.findLineNumber(content, /jwt\.sign/),
        remediation: 'Always set expiration on JWT tokens (e.g., expiresIn: "1h"). Never create perpetual tokens.',
        owaspReference: 'A07:2021 – Identification and Authentication Failures'
      });
    }

    // Storing sensitive data in JWT payload
    if (/jwt\.sign.*password|jwt\.sign.*secret/i.test(content)) {
      findings.push({
        id: `AUTH-JWT-DATA-${Date.now()}`,
        type: 'authentication',
        category: 'jwt-sensitive-data',
        severity: 'high',
        title: 'Sensitive data in JWT payload',
        file: relativePath,
        line: this.findLineNumber(content, /jwt\.sign/),
        remediation: 'Only store non-sensitive user identifiers in JWT. Never include passwords or secrets.',
        owaspReference: 'A07:2021 – Identification and Authentication Failures'
      });
    }

    // Missing JWT verification
    if (/jwt\.verify/.test(content) === false && /jwt\.sign/.test(content)) {
      findings.push({
        id: `AUTH-JWT-VERIFY-${Date.now()}`,
        type: 'authentication',
        category: 'missing-jwt-verification',
        severity: 'critical',
        title: 'JWT signing without verification',
        file: relativePath,
        line: this.findLineNumber(content, /jwt\.sign/),
        remediation: 'Implement JWT verification middleware for protected routes. Always verify tokens before trusting them.',
        owaspReference: 'A07:2021 – Identification and Authentication Failures'
      });
    }

    return findings;
  }

  /**
   * Check session security
   */
  checkSessionSecurity(filePath, content) {
    const findings = [];
    const relativePath = path.relative(this.targetPath, filePath);

    // Session without secure cookie flags
    if (/express-session|cookie-session/.test(content)) {
      if (!/secure:\s*true/.test(content)) {
        findings.push({
          id: `AUTH-SESSION-SEC-${Date.now()}`,
          type: 'authentication',
          category: 'insecure-cookie',
          severity: 'high',
          title: 'Session cookie without secure flag',
          file: relativePath,
          line: this.findLineNumber(content, /express-session|cookie-session/),
          remediation: 'Set secure: true, httpOnly: true, and sameSite: "strict" for session cookies.',
          owaspReference: 'A07:2021 – Identification and Authentication Failures'
        });
      }

      if (!/httpOnly:\s*true/.test(content)) {
        findings.push({
          id: `AUTH-SESSION-HTTP-${Date.now()}`,
          type: 'authentication',
          category: 'cookie-not-httponly',
          severity: 'high',
          title: 'Session cookie without httpOnly flag',
          file: relativePath,
          line: this.findLineNumber(content, /express-session|cookie-session/),
          remediation: 'Set httpOnly: true to prevent XSS attacks from stealing session cookies.',
          owaspReference: 'A07:2021 – Identification and Authentication Failures'
        });
      }
    }

    // Session fixation vulnerability
    if (/req\.session\.regenerate/.test(content) === false && /login|authenticate/i.test(content)) {
      findings.push({
        id: `AUTH-SESSION-FIX-${Date.now()}`,
        type: 'authentication',
        category: 'session-fixation',
        severity: 'medium',
        title: 'Session not regenerated after login',
        file: relativePath,
        line: this.findLineNumber(content, /login|authenticate/i),
        remediation: 'Regenerate session ID after successful authentication to prevent session fixation attacks.',
        owaspReference: 'A07:2021 – Identification and Authentication Failures'
      });
    }

    return findings;
  }

  /**
   * Check password policy implementation
   */
  checkPasswordPolicy(filePath, content) {
    const findings = [];
    const relativePath = path.relative(this.targetPath, filePath);

    // No password validation
    if (/(?:register|signup|createUser)/i.test(content) && !/password.*length|minLength|maxLength/.test(content)) {
      findings.push({
        id: `AUTH-PWD-POLICY-${Date.now()}`,
        type: 'authentication',
        category: 'weak-password-policy',
        severity: 'medium',
        title: 'No password strength validation',
        file: relativePath,
        line: this.findLineNumber(content, /register|signup|createUser/i),
        remediation: 'Enforce password requirements: minimum 8 characters, uppercase, lowercase, numbers, special chars.',
        owaspReference: 'A07:2021 – Identification and Authentication Failures'
      });
    }

    // Plain text password storage
    if (/(?:password|pwd)\s*[=:]\s*req\.body/.test(content) && !/hash|bcrypt|argon|scrypt/.test(content)) {
      findings.push({
        id: `AUTH-PWD-PLAIN-${Date.now()}`,
        type: 'authentication',
        category: 'plaintext-password',
        severity: 'critical',
        title: 'Password may be stored in plain text',
        file: relativePath,
        line: this.findLineNumber(content, /password|pwd/),
        remediation: 'ALWAYS hash passwords with bcrypt, argon2, or scrypt before storing. Never store plain text passwords.',
        owaspReference: 'A07:2021 – Identification and Authentication Failures'
      });
    }

    return findings;
  }

  /**
   * Check rate limiting implementation
   */
  checkRateLimiting(filePath, content) {
    const findings = [];
    const relativePath = path.relative(this.targetPath, filePath);

    // Auth endpoints without rate limiting
    if (/(?:login|signin|auth|register)/i.test(content) && !/rate[-_]?limit|express-rate-limit/.test(content)) {
      if (/app\.(post|get)|router\.(post|get)/.test(content)) {
        findings.push({
          id: `AUTH-RATE-${Date.now()}`,
          type: 'authentication',
          category: 'missing-rate-limiting',
          severity: 'medium',
          title: 'Authentication endpoint without rate limiting',
          file: relativePath,
          line: this.findLineNumber(content, /login|auth|register/i),
          remediation: 'Add rate limiting to auth endpoints using express-rate-limit to prevent brute force attacks.',
          owaspReference: 'A07:2021 – Identification and Authentication Failures'
        });
      }
    }

    return findings;
  }

  /**
   * Check CSRF protection
   */
  checkCSRFProtection(filePath, content) {
    const findings = [];
    const relativePath = path.relative(this.targetPath, filePath);

    // Form submissions without CSRF token
    if (/(?:app\.post|router\.post)/.test(content) && !/csrf|csurf|anti-forgery|x-csrf-token/i.test(content)) {
      // Only flag if it's not an API route
      if (!/api\/|\/api/.test(filePath)) {
        findings.push({
          id: `AUTH-CSRF-${Date.now()}`,
          type: 'authentication',
          category: 'missing-csrf-protection',
          severity: 'medium',
          title: 'Form submission may lack CSRF protection',
          file: relativePath,
          line: this.findLineNumber(content, /app\.post|router\.post/),
          remediation: 'Implement CSRF protection using csurf middleware or anti-forgery tokens for form submissions.',
          owaspReference: 'A01:2021 – Broken Access Control'
        });
      }
    }

    return findings;
  }

  /**
   * Check OAuth implementation
   */
  checkOAuthImplementation(filePath, content) {
    const findings = [];
    const relativePath = path.relative(this.targetPath, filePath);

    // OAuth state parameter missing
    if (/(?:passport|oauth|google-auth|github-auth)/i.test(content) && !/state:/.test(content)) {
      findings.push({
        id: `AUTH-OAUTH-STATE-${Date.now()}`,
        type: 'authentication',
        category: 'oauth-missing-state',
        severity: 'high',
        title: 'OAuth flow without state parameter',
        file: relativePath,
        line: this.findLineNumber(content, /passport|oauth/i),
        remediation: 'Always use state parameter in OAuth flows to prevent CSRF attacks on authentication.',
        owaspReference: 'A07:2021 – Identification and Authentication Failures'
      });
    }

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

module.exports = AuthScanner;
