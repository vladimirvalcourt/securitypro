const fs = require('fs');
const path = require('path');

/**
 * Rate Limiting & DDoS Protection Checker
 * Validates rate limiting implementation across API endpoints
 */
class RateLimitScanner {
  constructor(options = {}) {
    this.targetPath = options.targetPath || process.cwd();
    this.results = [];
  }

  async scan() {
    console.log('\n⏱️  Checking rate limiting and DDoS protection...\n');

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

  async getRelevantFiles() {
    const { glob } = require('glob');
    const patterns = ['**/*.{js,ts,jsx,tsx}', '**/*route*', '**/*api*', '**/*controller*'];
    const files = [];

    for (const pattern of patterns) {
      try {
        const found = await glob(pattern, {
          cwd: this.targetPath,
          nodir: true,
          ignore: ['node_modules/**', '.git/**', 'dist/**', 'build/**'],
          absolute: true
        });
        files.push(...found);
      } catch (error) {
        continue;
      }
    }

    return [...new Set(files)];
  }

  scanFile(filePath, content) {
    const findings = [];
    findings.push(...this.checkRateLimitMiddleware(filePath, content));
    findings.push(...this.checkEndpointRateLimits(filePath, content));
    findings.push(...this.checkUnboundedQueries(filePath, content));
    findings.push(...this.checkAuthEndpointProtection(filePath, content));
    findings.push(...this.checkResourceExhaustion(filePath, content));
    return findings;
  }

  checkRateLimitMiddleware(filePath, content) {
    const findings = [];
    const relativePath = path.relative(this.targetPath, filePath);

    // Express app without any rate limiting
    if (/express|app\.listen|server/.test(content) && !/rate[-_]?limit|express-rate-limit|throttle|redis/i.test(content)) {
      findings.push({
        id: `RATELIMIT-MISSING-${Date.now()}`,
        type: 'rate-limiting',
        category: 'no-rate-limiting',
        severity: 'high',
        title: 'Application without rate limiting middleware',
        file: relativePath,
        line: this.findLineNumber(content, /express|app\.listen/),
        remediation: 'Install and configure express-rate-limit to protect against abuse and DDoS.',
        bestPractice: `const rateLimit = require('express-rate-limit');\nconst limiter = rateLimit({\n  windowMs: 15 * 60 * 1000, // 15 minutes\n  max: 100 // limit each IP to 100 requests per windowMs\n});\napp.use(limiter);`,
        owaspReference: 'A04:2021 – Insecure Design'
      });
    }

    return findings;
  }

  checkEndpointRateLimits(filePath, content) {
    const findings = [];
    const relativePath = path.relative(this.targetPath, filePath);

    // Sensitive endpoints without specific rate limits
    const sensitiveEndpoints = [
      { pattern: /\/login|\/signin|\/auth/, name: 'Authentication endpoint' },
      { pattern: /\/register|\/signup/, name: 'Registration endpoint' },
      { pattern: /\/password.*reset|\/forgot.*password/, name: 'Password reset endpoint' },
      { pattern: /\/api\/.*verify|\/verify.*code/, name: 'Verification endpoint' }
    ];

    for (const { pattern, name } of sensitiveEndpoints) {
      if (pattern.test(content) && !/rate[-_]?limit|throttle/.test(content)) {
        findings.push({
          id: `RATELIMIT-ENDPOINT-${Date.now()}`,
          type: 'rate-limiting',
          category: 'unprotected-sensitive-endpoint',
          severity: 'high',
          title: `${name} without rate limiting`,
          file: relativePath,
          line: this.findLineNumber(content, pattern),
          remediation: 'Add strict rate limiting to prevent brute force attacks.',
          bestPractice: `const authLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 5 });\napp.post('/login', authLimiter, handler);`,
          owaspReference: 'A07:2021 – Identification and Authentication Failures'
        });
      }
    }

    return findings;
  }

  checkUnboundedQueries(filePath, content) {
    const findings = [];
    const relativePath = path.relative(this.targetPath, filePath);

    // User-controlled limit without maximum
    if (/limit.*req\.query|limit.*req\.params/.test(content) && !/Math\.min|max.*limit|clamp/i.test(content)) {
      findings.push({
        id: `RATELIMIT-QUERY-${Date.now()}`,
        type: 'rate-limiting',
        category: 'unbounded-query-parameter',
        severity: 'medium',
        title: 'User-controlled query parameter without maximum bound',
        file: relativePath,
        line: this.findLineNumber(content, /limit.*req\./),
        remediation: 'Cap user-controlled parameters to prevent resource exhaustion.',
        bestPractice: 'const limit = Math.min(parseInt(req.query.limit) || 10, 100);',
        owaspReference: 'A04:2021 – Insecure Design'
      });
    }

    // Pagination without limits
    if (/\.find\(\)|\.findAll\(\)/.test(content) && !/limit|skip|page|paginate/.test(content)) {
      findings.push({
        id: `RATELIMIT-PAGINATION-${Date.now()}`,
        type: 'rate-limiting',
        category: 'missing-pagination-limits',
        severity: 'medium',
        title: 'Database query without pagination limits',
        file: relativePath,
        line: this.findLineNumber(content, /\.find\(\)|\.findAll\(\)/),
        remediation: 'Always implement pagination with maximum page size limits.',
        bestPractice: 'const page = Math.min(parseInt(req.query.page) || 1, 100);\nconst limit = Math.min(parseInt(req.query.limit) || 10, 50);',
        owaspReference: 'A04:2021 – Insecure Design'
      });
    }

    return findings;
  }

  checkAuthEndpointProtection(filePath, content) {
    const findings = [];
    const relativePath = path.relative(this.targetPath, filePath);

    // Auth endpoints should have stricter limits
    if (/(?:login|auth|token)/i.test(content) && /rate/.test(content)) {
      // Check if rate limit is appropriate (< 20 requests per window)
      if (/max:\s*(100|200|500|1000)/.test(content)) {
        findings.push({
          id: `RATELIMIT-AUTH-WEAK-${Date.now()}`,
          type: 'rate-limiting',
          category: 'weak-auth-rate-limit',
          severity: 'medium',
          title: 'Authentication endpoint with weak rate limiting',
          file: relativePath,
          line: this.findLineNumber(content, /max:/),
          remediation: 'Use stricter rate limits for auth endpoints (5-10 requests per 15 minutes).',
          bestPractice: 'max: 5 requests per 15 minutes for login attempts',
          owaspReference: 'A07:2021 – Identification and Authentication Failures'
        });
      }
    }

    return findings;
  }

  checkResourceExhaustion(filePath, content) {
    const findings = [];
    const relativePath = path.relative(this.targetPath, filePath);

    // Expensive operations without limits
    const expensiveOps = [
      { pattern: /bcrypt\.hash|argon2\.hash/, name: 'Password hashing' },
      { pattern: /sharp\(|gm\(|imagemagick/, name: 'Image processing' },
      { pattern: /pdf|excel|report.*generate/, name: 'Document generation' }
    ];

    for (const { pattern, name } of expensiveOps) {
      if (pattern.test(content) && !/rate[-_]?limit|queue|throttle|job/.test(content)) {
        findings.push({
          id: `RATELIMIT-RESOURCE-${Date.now()}`,
          type: 'rate-limiting',
          category: 'unprotected-expensive-operation',
          severity: 'medium',
          title: `${name} without rate limiting or queuing`,
          file: relativePath,
          line: this.findLineNumber(content, pattern),
          remediation: 'Rate limit or queue expensive operations to prevent DoS.',
          bestPractice: 'Use job queues (Bull, Agenda) for expensive operations with rate limits',
          owaspReference: 'A04:2021 – Insecure Design'
        });
      }
    }

    return findings;
  }

  findLineNumber(content, pattern) {
    const lines = content.split('\n');
    for (let i = 0; i < lines.length; i++) {
      if (pattern.test(lines[i])) {
        return i + 1;
      }
    }
    return null;
  }

  calculateSeverity() {
    if (this.results.length === 0) return 'none';
    const hasCritical = this.results.some(f => f.severity === 'critical');
    const hasHigh = this.results.some(f => f.severity === 'high');
    if (hasCritical) return 'critical';
    if (hasHigh) return 'high';
    return 'medium';
  }

  getCategorySummary() {
    const summary = {};
    this.results.forEach(finding => {
      summary[finding.category] = (summary[finding.category] || 0) + 1;
    });
    return summary;
  }
}

module.exports = RateLimitScanner;
