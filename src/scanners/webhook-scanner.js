const fs = require('fs');
const path = require('path');

/**
 * Webhook Security Validator
 * Checks webhook implementations for signature verification and security
 */
class WebhookScanner {
  constructor(options = {}) {
    this.targetPath = options.targetPath || process.cwd();
    this.results = [];
  }

  async scan() {
    console.log('\n🔗 Validating webhook security implementations...\n');

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
    const patterns = ['**/*.{js,ts,jsx,tsx}', '**/*webhook*', '**/*stripe*', '**/*payment*', '**/callback*'];
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
    findings.push(...this.checkSignatureVerification(filePath, content));
    findings.push(...this.checkReplayProtection(filePath, content));
    findings.push(...this.checkIdempotency(filePath, content));
    findings.push(...this.checkErrorHandling(filePath, content));
    findings.push(...this.checkTimeoutHandling(filePath, content));
    return findings;
  }

  checkSignatureVerification(filePath, content) {
    const findings = [];
    const relativePath = path.relative(this.targetPath, filePath);

    // Stripe webhook without signature verification
    if (/stripe|webhook/.test(content) && /endpoint|route|post/i.test(content)) {
      if (!/stripe\.webhooks\.constructEvent|verifySignature|signature|sig_header/i.test(content)) {
        findings.push({
          id: `WEBHOOK-SIG-${Date.now()}`,
          type: 'webhook-security',
          category: 'missing-signature-verification',
          severity: 'critical',
          title: 'Webhook endpoint without signature verification',
          file: relativePath,
          line: this.findLineNumber(content, /webhook|endpoint/),
          remediation: 'Verify webhook signatures to ensure requests are from legitimate providers.',
          bestPractice: `const event = stripe.webhooks.constructEvent(\n  req.body,\n  req.headers['stripe-signature'],\n  webhookSecret\n);`,
          owaspReference: 'A01:2021 – Broken Access Control'
        });
      }
    }

    // Generic webhook without any auth
    if (/webhook|callback/.test(filePath) && !/auth|verify|signature|token|secret/i.test(content)) {
      findings.push({
        id: `WEBHOOK-AUTH-${Date.now()}`,
        type: 'webhook-security',
        category: 'unprotected-webhook',
        severity: 'high',
        title: 'Webhook endpoint without authentication',
        file: relativePath,
        line: this.findLineNumber(content, /webhook|callback/),
        remediation: 'Add signature verification or token-based authentication to webhook endpoints.',
        bestPractice: 'Verify HMAC signature or shared secret for all webhook requests',
        owaspReference: 'A01:2021 – Broken Access Control'
      });
    }

    return findings;
  }

  checkReplayProtection(filePath, content) {
    const findings = [];
    const relativePath = path.relative(this.targetPath, filePath);

    if (/webhook|stripe/.test(content) && !/timestamp|nonce|replay|idempotency/i.test(content)) {
      findings.push({
        id: `WEBHOOK-REPLAY-${Date.now()}`,
        type: 'webhook-security',
        category: 'missing-replay-protection',
        severity: 'medium',
        title: 'Webhook without replay attack protection',
        file: relativePath,
        line: this.findLineNumber(content, /webhook/),
        remediation: 'Implement timestamp validation and nonce tracking to prevent replay attacks.',
        bestPractice: 'Check webhook timestamp is within 5 minutes and track processed event IDs',
        owaspReference: 'A01:2021 – Broken Access Control'
      });
    }

    return findings;
  }

  checkIdempotency(filePath, content) {
    const findings = [];
    const relativePath = path.relative(this.targetPath, filePath);

    if (/webhook.*event|stripe.*event/.test(content) && !/idempotency|processed.*before|duplicate/i.test(content)) {
      findings.push({
        id: `WEBHOOK-IDEM-${Date.now()}`,
        type: 'webhook-security',
        category: 'missing-idempotency',
        severity: 'medium',
        title: 'Webhook handler without idempotency checks',
        file: relativePath,
        line: this.findLineNumber(content, /webhook.*event/),
        remediation: 'Track processed webhook events to handle duplicate deliveries safely.',
        bestPractice: 'Store processed event IDs in database and skip if already processed',
        owaspReference: 'A04:2021 – Insecure Design'
      });
    }

    return findings;
  }

  checkErrorHandling(filePath, content) {
    const findings = [];
    const relativePath = path.relative(this.targetPath, filePath);

    if (/webhook/.test(content)) {
      // Should return 200 quickly
      if (!/200|send.*OK|json.*success/i.test(content)) {
        findings.push({
          id: `WEBHOOK-RESPONSE-${Date.now()}`,
          type: 'webhook-security',
          category: 'improper-response',
          severity: 'low',
          title: 'Webhook may not return proper acknowledgment',
          file: relativePath,
          line: this.findLineNumber(content, /webhook/),
          remediation: 'Return 200 OK immediately after receiving webhook to prevent retries.',
          bestPractice: 'Process webhooks asynchronously and return 200 immediately',
          owaspReference: 'A04:2021 – Insecure Design'
        });
      }

      // Verbose error responses
      if (/catch.*err.*res\.send.*err|res\.json.*error.*stack/i.test(content)) {
        findings.push({
          id: `WEBHOOK-ERR-DISC-${Date.now()}`,
          type: 'webhook-security',
          category: 'error-disclosure',
          severity: 'medium',
          title: 'Webhook exposing detailed error information',
          file: relativePath,
          line: this.findLineNumber(content, /catch.*err/),
          remediation: 'Return generic errors to webhook sender. Log details internally.',
          bestPractice: 'Return 200 or 400 with generic message, log full error internally',
          owaspReference: 'A05:2021 – Security Misconfiguration'
        });
      }
    }

    return findings;
  }

  checkTimeoutHandling(filePath, content) {
    const findings = [];
    const relativePath = path.relative(this.targetPath, filePath);

    if (/webhook/.test(content) && /database|api.*call|external/.test(content)) {
      if (!/timeout|async|queue|background/i.test(content)) {
        findings.push({
          id: `WEBHOOK-TIMEOUT-${Date.now()}`,
          type: 'webhook-security',
          category: 'synchronous-processing',
          severity: 'low',
          title: 'Webhook processing synchronously (may timeout)',
          file: relativePath,
          line: this.findLineNumber(content, /webhook/),
          remediation: 'Process webhooks asynchronously to avoid timeouts and improve reliability.',
          bestPractice: 'Queue webhook events and process in background worker',
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

module.exports = WebhookScanner;
