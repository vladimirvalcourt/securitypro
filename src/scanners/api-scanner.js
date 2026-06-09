const fs = require('fs');
const path = require('path');
const { glob } = require('glob');

/**
 * API Endpoint Security Scanner
 * Checks REST/GraphQL APIs for common security issues
 */
class ApiScanner {
  constructor(options = {}) {
    this.targetPath = options.targetPath || process.cwd();
    this.results = [];
  }

  /**
   * Run API security scans
   */
  async scan() {
    console.log('\n🌐 Scanning API endpoints for security issues...\n');

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
   * Get API-related files
   */
  async getRelevantFiles() {
    const patterns = [
      '**/*api*',
      '**/*route*',
      '**/*controller*',
      '**/*endpoint*',
      '**/routes/**',
      '**/controllers/**'
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
   * Scan a file for API security issues
   */
  scanFile(filePath, content) {
    const findings = [];

    findings.push(...this.checkInputValidation(filePath, content));
    findings.push(...this.checkOutputValidation(filePath, content));
    findings.push(...this.checkRateLimiting(filePath, content));
    findings.push(...this.checkHttpSecurity(filePath, content));
    findings.push(...this.checkPagination(filePath, content));
    findings.push(...this.checkVersioning(filePath, content));

    return findings;
  }

  /**
   * Check input validation on API endpoints
   */
  checkInputValidation(filePath, content) {
    const findings = [];
    const relativePath = path.relative(this.targetPath, filePath);

    // POST/PUT without body validation
    if (/(app\.post|router\.post|app\.put|router\.put)/.test(content) && /req\.body/.test(content)) {
      if (!/validate|schema|joi|yup|zod|express-validator/.test(content)) {
        findings.push({
          id: `API-INPUT-${Date.now()}`,
          type: 'api-security',
          category: 'missing-input-validation',
          severity: 'high',
          title: 'API endpoint without request body validation',
          file: relativePath,
          line: this.findLineNumber(content, /app\.(post|put)|router\.(post|put)/),
          remediation: 'Add input validation using Zod, Yup, Joi, or express-validator. Never trust user input.',
          owaspReference: 'A03:2021 – Injection'
        });
      }
    }

    // Missing content-type checking
    if (/(app\.post|router\.post)/.test(content) && !/content-type|application\/json/.test(content)) {
      findings.push({
        id: `API-CONTENT-${Date.now()}`,
        type: 'api-security',
        category: 'missing-content-type-check',
        severity: 'low',
        title: 'Endpoint may not validate Content-Type header',
        file: relativePath,
        line: this.findLineNumber(content, /app\.post|router\.post/),
        remediation: 'Validate Content-Type header to ensure JSON requests. Add middleware to reject non-JSON payloads.',
        owaspReference: 'A05:2021 – Security Misconfiguration'
      });
    }

    return findings;
  }

  /**
   * Check output validation and data exposure
   */
  checkOutputValidation(filePath, content) {
    const findings = [];
    const relativePath = path.relative(this.targetPath, filePath);

    // Sending entire user objects
    if (/res\.json.*user|res\.send.*user/i.test(content) && !/pick|omit|select|exclude/.test(content)) {
      findings.push({
        id: `API-OUTPUT-${Date.now()}`,
        type: 'api-security',
        category: 'sensitive-data-exposure',
        severity: 'high',
        title: 'API may expose entire user object',
        file: relativePath,
        line: this.findLineNumber(content, /res\.json.*user|res\.send.*user/i),
        remediation: 'Return only necessary fields. Exclude passwords, tokens, internal IDs. Use DTOs or pick/omit utilities.',
        owaspReference: 'A02:2021 – Cryptographic Failures'
      });
    }

    // Verbose error responses
    if (/catch.*err/.test(content) && /res\.status\(500\).*err/.test(content)) {
      findings.push({
        id: `API-ERROR-${Date.now()}`,
        type: 'api-security',
        category: 'verbose-error-messages',
        severity: 'medium',
        title: 'Detailed error messages in API response',
        file: relativePath,
        line: this.findLineNumber(content, /res\.status\(500\)/),
        remediation: 'Send generic error messages to clients. Log detailed errors server-side for debugging.',
        owaspReference: 'A05:2021 – Security Misconfiguration'
      });
    }

    return findings;
  }

  /**
   * Check rate limiting on API endpoints
   */
  checkRateLimiting(filePath, content) {
    const findings = [];
    const relativePath = path.relative(this.targetPath, filePath);

    // API routes without rate limiting
    if (/\/api\//.test(filePath) && !/rate[-_]?limit|express-rate-limit|throttle/.test(content)) {
      findings.push({
        id: `API-RATE-${Date.now()}`,
        type: 'api-security',
        category: 'missing-rate-limiting',
        severity: 'medium',
        title: 'API endpoint without rate limiting',
        file: relativePath,
        line: this.findLineNumber(content, /app\.(get|post|put|delete)|router\./),
        remediation: 'Add rate limiting to all API endpoints using express-rate-limit to prevent abuse and DDoS.',
        owaspReference: 'A04:2021 – Insecure Design'
      });
    }

    return findings;
  }

  /**
   * Check HTTP security headers
   */
  checkHttpSecurity(filePath, content) {
    const findings = [];
    const relativePath = path.relative(this.targetPath, filePath);

    // Missing security headers
    if (/express/.test(content) && !/helmet|X-Frame-Options|Content-Security-Policy/.test(content)) {
      findings.push({
        id: `API-HEADERS-${Date.now()}`,
        type: 'api-security',
        category: 'missing-security-headers',
        severity: 'medium',
        title: 'Missing HTTP security headers',
        file: relativePath,
        line: this.findLineNumber(content, /express/),
        remediation: 'Use helmet middleware to set security headers (CSP, X-Frame-Options, HSTS, etc.).',
        owaspReference: 'A05:2021 – Security Misconfiguration'
      });
    }

    // CORS misconfiguration
    if (/cors\s*\(/.test(content) && /origin:\s*['"]\*['"]/.test(content)) {
      findings.push({
        id: `API-CORS-${Date.now()}`,
        type: 'api-security',
        category: 'cors-misconfiguration',
        severity: 'medium',
        title: 'CORS configured with wildcard origin',
        file: relativePath,
        line: this.findLineNumber(content, /cors\s*\(/),
        remediation: 'Specify allowed origins explicitly instead of using "*". Restrict to trusted domains.',
        owaspReference: 'A05:2021 – Security Misconfiguration'
      });
    }

    return findings;
  }

  /**
   * Check pagination implementation
   */
  checkPagination(filePath, content) {
    const findings = [];
    const relativePath = path.relative(this.targetPath, filePath);

    // List endpoints without pagination
    if (/\.find\s*\(\)\.exec\(\)|\.findAll\(\)/.test(content) && !/limit|skip|page|paginate/.test(content)) {
      findings.push({
        id: `API-PAGINATION-${Date.now()}`,
        type: 'api-security',
        category: 'missing-pagination',
        severity: 'low',
        title: 'List endpoint without pagination',
        file: relativePath,
        line: this.findLineNumber(content, /\.find\s*\(\)/),
        remediation: 'Implement pagination for list endpoints to prevent resource exhaustion and data scraping.',
        owaspReference: 'A04:2021 – Insecure Design'
      });
    }

    // Unbounded query results
    if (/limit.*req\.query/.test(content) && !/Math\.min|maxLimit/.test(content)) {
      findings.push({
        id: `API-LIMIT-${Date.now()}`,
        type: 'api-security',
        category: 'unbounded-results',
        severity: 'medium',
        title: 'User-controlled limit without maximum bound',
        file: relativePath,
        line: this.findLineNumber(content, /limit.*req\.query/),
        remediation: 'Set maximum limit (e.g., Math.min(req.query.limit, 100)) to prevent excessive data retrieval.',
        owaspReference: 'A04:2021 – Insecure Design'
      });
    }

    return findings;
  }

  /**
   * Check API versioning
   */
  checkVersioning(filePath, content) {
    const findings = [];
    const relativePath = path.relative(this.targetPath, filePath);

    // API without versioning
    if (/\/api\//.test(filePath) && !/\/v\d+|\/api\/v/.test(content)) {
      findings.push({
        id: `API-VERSION-${Date.now()}`,
        type: 'api-security',
        category: 'missing-versioning',
        severity: 'low',
        title: 'API endpoint without versioning',
        file: relativePath,
        line: this.findLineNumber(content, /\/api\//),
        remediation: 'Implement API versioning (e.g., /api/v1/) to allow backward-compatible changes.',
        owaspReference: 'A04:2021 – Insecure Design'
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

module.exports = ApiScanner;
