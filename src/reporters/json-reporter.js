const fs = require('fs');
const path = require('path');

/**
 * JSON reporter for machine-readable output and CI/CD integration
 */
class JsonReporter {
  constructor() {
    this.report = {
      metadata: {
        tool: 'vibe-security-auditor',
        version: '1.0.0',
        timestamp: new Date().toISOString(),
        nodeVersion: process.version
      },
      summary: {},
      findings: [],
      recommendations: []
    };
  }

  /**
   * Generate complete report from scan results
   */
  generateReport(results, targetPath, duration) {
    const allFindings = [
      ...(results.secretScan?.findings || []),
      ...(results.owaspScan?.findings || []),
      ...(results.authScan?.findings || []),
      ...(results.dbScan?.findings || []),
      ...(results.apiScan?.findings || [])
    ];

    this.report.metadata.targetPath = targetPath;
    this.report.metadata.scanDuration = duration;

    this.report.summary = this.generateSummary(results);
    this.report.findings = this.formatFindings(allFindings);
    this.report.recommendations = this.generateRecommendations(allFindings);

    return this.report;
  }

  /**
   * Generate summary statistics
   */
  generateSummary(results) {
    const allFindings = [
      ...(results.secretScan?.findings || []),
      ...(results.owaspScan?.findings || []),
      ...(results.authScan?.findings || []),
      ...(results.dbScan?.findings || []),
      ...(results.apiScan?.findings || [])
    ];

    const bySeverity = { critical: 0, high: 0, medium: 0, low: 0 };
    const byType = {};
    const byFile = {};

    allFindings.forEach(finding => {
      bySeverity[finding.severity]++;
      byType[finding.type] = (byType[finding.type] || 0) + 1;
      byFile[finding.file] = (byFile[finding.file] || 0) + 1;
    });

    const hasCritical = bySeverity.critical > 0;
    const hasHigh = bySeverity.high > 0;

    let overallStatus = 'pass';
    if (hasCritical) overallStatus = 'fail';
    else if (hasHigh) overallStatus = 'warning';

    return {
      totalFindings: allFindings.length,
      bySeverity,
      byType,
      byFile,
      overallStatus,
      scansPerformed: {
        secrets: results.secretScan?.totalFindings || 0,
        owasp: results.owaspScan?.totalFindings || 0,
        authentication: results.authScan?.totalFindings || 0,
        database: results.dbScan?.totalFindings || 0,
        api: results.apiScan?.totalFindings || 0
      }
    };
  }

  /**
   * Format findings for JSON output
   */
  formatFindings(findings) {
    return findings.map(finding => ({
      id: finding.id,
      severity: finding.severity,
      type: finding.type,
      category: finding.category,
      title: finding.title,
      file: finding.file,
      line: finding.line,
      column: finding.column,
      remediation: finding.remediation,
      suggestedEnvVar: finding.suggestedEnvVar || null,
      owaspReference: finding.owaspReference || null,
      matchedPattern: finding.matchedPattern || null
    }));
  }

  /**
   * Generate actionable recommendations
   */
  generateRecommendations(findings) {
    const recommendations = [];

    // Check for specific issue types and add recommendations
    const hasSecrets = findings.some(f => f.type === 'hardcoded-secret');
    const hasSqlInjection = findings.some(f => f.category === 'sql-injection');
    const hasXss = findings.some(f => f.type === 'xss');
    const hasAuthIssues = findings.some(f => f.type === 'authentication');
    const hasDbIssues = findings.some(f => f.type === 'database-security');

    if (hasSecrets) {
      recommendations.push({
        priority: 'critical',
        title: 'Implement Secret Management',
        description: 'Move all hardcoded secrets to environment variables or a secret manager.',
        steps: [
          'Create a .env file with all sensitive values',
          'Add .env to .gitignore',
          'Use dotenv package to load environment variables',
          'Consider using AWS Secrets Manager or HashiCorp Vault for production'
        ]
      });
    }

    if (hasSqlInjection) {
      recommendations.push({
        priority: 'critical',
        title: 'Prevent SQL Injection',
        description: 'Use parameterized queries instead of string concatenation.',
        steps: [
          'Replace string interpolation with parameterized queries',
          'Use ORM query builders when possible',
          'Validate and sanitize all user inputs',
          'Apply principle of least privilege to database users'
        ]
      });
    }

    if (hasXss) {
      recommendations.push({
        priority: 'high',
        title: 'Prevent Cross-Site Scripting (XSS)',
        description: 'Sanitize all user-generated content before rendering.',
        steps: [
          'Use textContent instead of innerHTML where possible',
          'Install and use DOMPurify for HTML sanitization',
          'Set Content-Security-Policy headers',
          'Escape user input in templates'
        ]
      });
    }

    if (hasAuthIssues) {
      recommendations.push({
        priority: 'high',
        title: 'Strengthen Authentication',
        description: 'Implement secure authentication practices.',
        steps: [
          'Use bcrypt or argon2 for password hashing',
          'Implement rate limiting on auth endpoints',
          'Add JWT expiration and refresh token rotation',
          'Enable multi-factor authentication for admin accounts'
        ]
      });
    }

    if (hasDbIssues) {
      recommendations.push({
        priority: 'high',
        title: 'Harden Database Security',
        description: 'Secure database connections and queries.',
        steps: [
          'Enable SSL/TLS for database connections',
          'Use connection pooling with proper limits',
          'Implement row-level security where applicable',
          'Regular security audits and penetration testing'
        ]
      });
    }

    // General recommendations
    recommendations.push({
      priority: 'medium',
      title: 'General Security Best Practices',
      description: 'Additional security improvements for your application.',
      steps: [
        'Install helmet middleware for security headers',
        'Enable CORS with specific allowed origins',
        'Implement comprehensive logging and monitoring',
        'Set up automated dependency vulnerability scanning',
        'Conduct regular security training for developers'
      ]
    });

    return recommendations;
  }

  /**
   * Save report to file
   */
  saveToFile(report, outputPath) {
    const fullPath = path.resolve(outputPath);
    const dir = path.dirname(fullPath);

    // Ensure directory exists
    if (!fs.existsSync(dir)) {
      fs.mkdirSync(dir, { recursive: true });
    }

    fs.writeFileSync(fullPath, JSON.stringify(report, null, 2), 'utf-8');
    return fullPath;
  }
}

module.exports = JsonReporter;
