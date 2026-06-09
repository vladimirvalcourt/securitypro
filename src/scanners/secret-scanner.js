const fs = require('fs');
const path = require('path');
const { glob } = require('glob');
const { SECRET_PATTERNS, IGNORED_FILES } = require('../patterns/secrets');

/**
 * Scans codebase for hardcoded secrets, API keys, and credentials
 */
class SecretScanner {
  constructor(options = {}) {
    this.targetPath = options.targetPath || process.cwd();
    this.ignorePatterns = options.ignorePatterns || [];
    this.results = [];
  }

  /**
   * Run the secret scan on the target directory
   */
  async scan() {
    console.log('\n🔍 Scanning for hardcoded secrets and credentials...\n');

    const files = await this.getFilesToScan();
    let filesScanned = 0;

    for (const file of files) {
      try {
        const content = fs.readFileSync(file, 'utf-8');
        const findings = this.scanFile(file, content);

        if (findings.length > 0) {
          this.results.push(...findings);
        }

        filesScanned++;
      } catch (error) {
        // Skip binary files or files that can't be read
        continue;
      }
    }

    return {
      filesScanned,
      totalFindings: this.results.length,
      findings: this.results,
      severity: this.calculateSeverity()
    };
  }

  /**
   * Get list of files to scan based on target path and ignore patterns
   */
  async getFilesToScan() {
    const allIgnorePatterns = [...IGNORED_FILES, ...this.ignorePatterns];

    const files = await glob('**/*', {
      cwd: this.targetPath,
      nodir: true,
      dot: true,
      ignore: allIgnorePatterns,
      absolute: true
    });

    // Filter out binary files and large files
    return files.filter(file => {
      try {
        const stat = fs.statSync(file);
        // Skip files larger than 1MB
        if (stat.size > 1024 * 1024) return false;

        // Skip common binary extensions
        const ext = path.extname(file).toLowerCase();
        const binaryExts = ['.png', '.jpg', '.jpeg', '.gif', '.ico', '.pdf', '.zip', '.tar', '.gz'];
        if (binaryExts.includes(ext)) return false;

        return true;
      } catch (error) {
        return false;
      }
    });
  }

  /**
   * Scan a single file for secrets
   */
  scanFile(filePath, content) {
    const findings = [];
    const relativePath = path.relative(this.targetPath, filePath);
    const lines = content.split('\n');

    for (const pattern of SECRET_PATTERNS) {
      // Reset regex state
      pattern.pattern.lastIndex = 0;

      let match;
      while ((match = pattern.pattern.exec(content)) !== null) {
        const matchedText = match[0];

        // Find line number
        const lineNumber = content.substring(0, match.index).split('\n').length;
        const lineContent = lines[lineNumber - 1]?.trim() || '';

        // Skip if it's clearly a comment explaining the pattern (not actual usage)
        if (this.isCommentedOut(lineContent, matchedText)) {
          continue;
        }

        findings.push({
          id: `SECRET-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`,
          type: 'hardcoded-secret',
          category: pattern.category,
          severity: pattern.severity,
          title: `${pattern.name} detected`,
          file: relativePath,
          line: lineNumber,
          column: match.index - content.lastIndexOf('\n', match.index - 1),
          matchedPattern: this.maskSecret(matchedText),
          originalMatch: matchedText,
          remediation: pattern.remediation,
          suggestedEnvVar: pattern.envVar,
          owaspReference: 'A07:2021 – Identification and Authentication Failures'
        });
      }
    }

    return findings;
  }

  /**
   * Check if a match is in a comment (to reduce false positives)
   */
  isCommentedOut(lineContent, matchedText) {
    // Common comment patterns
    const commentPatterns = [
      /^\/\//,           // JavaScript single-line comment
      /^\s*\*/,          // JSDoc/multi-line comment
      /^\s*#/,           // Python/shell comment
      /^\s*<!--/,        // HTML comment
      /example/i,        // Example/dummy values
      /placeholder/i,
      /your[-_]?key/i,
      /your[-_]?secret/i,
      /replace[-_]?me/i,
      /changeme/i
    ];

    return commentPatterns.some(pattern => pattern.test(lineContent));
  }

  /**
   * Mask sensitive parts of detected secrets for safe display
   */
  maskSecret(secret) {
    if (secret.length <= 8) return '****';
    return secret.substring(0, 4) + '...' + secret.substring(secret.length - 4);
  }

  /**
   * Calculate overall severity based on findings
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
   * Generate summary statistics
   */
  getSummary() {
    const byCategory = {};
    const bySeverity = { critical: 0, high: 0, medium: 0, low: 0 };

    this.results.forEach(finding => {
      byCategory[finding.category] = (byCategory[finding.category] || 0) + 1;
      bySeverity[finding.severity]++;
    });

    return {
      totalFindings: this.results.length,
      byCategory,
      bySeverity
    };
  }
}

module.exports = SecretScanner;
