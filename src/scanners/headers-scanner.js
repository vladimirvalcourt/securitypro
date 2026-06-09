const fs = require('fs');
const path = require('path');

/**
 * CORS & HTTP Headers Auditor
 * Checks for missing security headers and CORS misconfigurations
 */
class HeadersScanner {
  constructor(options = {}) {
    this.targetPath = options.targetPath || process.cwd();
    this.results = [];
  }

  async scan() {
    console.log('\n🛡️  Auditing HTTP security headers and CORS...\n');

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
    const patterns = ['**/*.{js,ts,jsx,tsx}', '**/app.*', '**/server.*', '**/index.*'];
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
    findings.push(...this.checkHelmetUsage(filePath, content));
    findings.push(...this.checkCORSConfiguration(filePath, content));
    findings.push(...this.checkSecurityHeaders(filePath, content));
    findings.push(...this.checkHSTS(filePath, content));
    findings.push(...this.checkCSP(filePath, content));
    return findings;
  }

  checkHelmetUsage(filePath, content) {
    const findings = [];
    const relativePath = path.relative(this.targetPath, filePath);

    if (/express/.test(content) && !/helmet/.test(content)) {
      findings.push({
        id: `HEADERS-HELMET-${Date.now()}`,
        type: 'http-headers',
        category: 'missing-helmet',
        severity: 'high',
        title: 'Express app without helmet middleware',
        file: relativePath,
        line: this.findLineNumber(content, /express/),
        remediation: 'Install and use helmet: npm install helmet, then add app.use(helmet())',
        bestPractice: 'const helmet = require("helment");\napp.use(helmet());',
        owaspReference: 'A05:2021 – Security Misconfiguration'
      });
    }

    return findings;
  }

  checkCORSConfiguration(filePath, content) {
    const findings = [];
    const relativePath = path.relative(this.targetPath, filePath);

    // Wildcard CORS
    if (/Access-Control-Allow-Origin.*\*/.test(content)) {
      findings.push({
        id: `HEADERS-CORS-WILD-${Date.now()}`,
        type: 'http-headers',
        category: 'cors-wildcard',
        severity: 'medium',
        title: 'CORS configured with wildcard (*) origin',
        file: relativePath,
        line: this.findLineNumber(content, /Access-Control-Allow-Origin/),
        remediation: 'Specify allowed origins explicitly instead of using "*".',
        bestPractice: 'app.use(cors({ origin: ["https://yourdomain.com"] }))',
        owaspReference: 'A05:2021 – Security Misconfiguration'
      });
    }

    // CORS without credentials restriction
    if (/cors\s*\(/.test(content) && /origin.*\*/.test(content) && /credentials.*true/.test(content)) {
      findings.push({
        id: `HEADERS-CORS-CRED-${Date.now()}`,
        type: 'http-headers',
        category: 'cors-credentials-wildcard',
        severity: 'critical',
        title: 'CORS wildcard with credentials enabled',
        file: relativePath,
        line: this.findLineNumber(content, /cors\s*\(/),
        remediation: 'NEVER use wildcard CORS origin with credentials: true. This is a critical security risk.',
        bestPractice: 'Specify exact origins when using credentials',
        owaspReference: 'A05:2021 – Security Misconfiguration'
      });
    }

    return findings;
  }

  checkSecurityHeaders(filePath, content) {
    const findings = [];
    const relativePath = path.relative(this.targetPath, filePath);

    const requiredHeaders = [
      { header: 'X-Frame-Options', pattern: /X-Frame-Options|frameguard/i, fix: 'helmet.frameguard()' },
      { header: 'X-Content-Type-Options', pattern: /X-Content-Type-Options|noSniff/i, fix: 'helmet.noSniff()' },
      { header: 'X-XSS-Protection', pattern: /X-XSS-Protection|xssFilter/i, fix: 'Not needed with CSP' },
      { header: 'Strict-Transport-Security', pattern: /Strict-Transport-Security|hsts/i, fix: 'helmet.hsts()' },
      { header: 'Content-Security-Policy', pattern: /Content-Security-Policy|contentSecurityPolicy/i, fix: 'helmet.contentSecurityPolicy()' }
    ];

    if (/express|server|app\.listen/.test(content)) {
      for (const { header, pattern, fix } of requiredHeaders) {
        if (!pattern.test(content) && !/helmet/.test(content)) {
          findings.push({
            id: `HEADERS-MISSING-${header}-${Date.now()}`,
            type: 'http-headers',
            category: 'missing-security-header',
            severity: 'medium',
            title: `Missing security header: ${header}`,
            file: relativePath,
            line: null,
            remediation: `Add ${header} header. Use helmet or set manually: res.setHeader("${header}", "...")`,
            bestPractice: `Use helmet which sets all security headers automatically`,
            owaspReference: 'A05:2021 – Security Misconfiguration'
          });
        }
      }
    }

    return findings;
  }

  checkHSTS(filePath, content) {
    const findings = [];
    const relativePath = path.relative(this.targetPath, filePath);

    if (/https|production/.test(content) && !/Strict-Transport-Security|hsts|max-age/.test(content)) {
      findings.push({
        id: `HEADERS-HSTS-${Date.now()}`,
        type: 'http-headers',
        category: 'missing-hsts',
        severity: 'medium',
        title: 'HTTPS without HSTS header',
        file: relativePath,
        line: null,
        remediation: 'Add HSTS header to enforce HTTPS: Strict-Transport-Security: max-age=31536000; includeSubDomains',
        bestPractice: 'app.use(helmet.hsts({ maxAge: 31536000, includeSubDomains: true }))',
        owaspReference: 'A05:2021 – Security Misconfiguration'
      });
    }

    return findings;
  }

  checkCSP(filePath, content) {
    const findings = [];
    const relativePath = path.relative(this.targetPath, filePath);

    if (/express|server/.test(content) && !/Content-Security-Policy|csp|helmet/.test(content)) {
      findings.push({
        id: `HEADERS-CSP-${Date.now()}`,
        type: 'http-headers',
        category: 'missing-csp',
        severity: 'high',
        title: 'No Content-Security-Policy header',
        file: relativePath,
        line: null,
        remediation: 'Implement CSP to prevent XSS attacks. Define allowed sources for scripts, styles, etc.',
        bestPractice: `app.use(helmet.contentSecurityPolicy({\n  directives: {\n    defaultSrc: ["'self'"],\n    scriptSrc: ["'self'"],\n    styleSrc: ["'self'"]\n  }\n}))`,
        owaspReference: 'A05:2021 – Security Misconfiguration'
      });
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

module.exports = HeadersScanner;
