const fs = require('fs');
const path = require('path');

/**
 * Environment Variable Validator
 * Validates .env files, checks for hardcoded secrets, and ensures proper env usage
 */
class EnvScanner {
  constructor(options = {}) {
    this.targetPath = options.targetPath || process.cwd();
    this.results = [];
  }

  /**
   * Run environment variable validation scan
   */
  async scan() {
    console.log('\n🔐 Validating environment variable configuration...\n');

    const envPath = path.join(this.targetPath, '.env');
    const envExamplePath = path.join(this.targetPath, '.env.example');
    const gitignorePath = path.join(this.targetPath, '.gitignore');

    // Check if .env exists
    const envExists = fs.existsSync(envPath);
    
    // Check if .env is in .gitignore
    const gitignoreContent = fs.existsSync(gitignorePath) 
      ? fs.readFileSync(gitignorePath, 'utf-8') 
      : '';
    const envInGitignore = gitignoreContent.includes('.env');

    // Check for .env.example
    const envExampleExists = fs.existsSync(envExamplePath);

    // Scan codebase for hardcoded values that should be env vars
    const hardcodedSecrets = await this.scanForHardcodedEnvVars();

    // Validate .env file format if it exists
    const envValidation = envExists ? this.validateEnvFile(envPath) : null;

    // Generate recommendations
    const recommendations = this.generateRecommendations({
      envExists,
      envInGitignore,
      envExampleExists,
      hardcodedSecrets,
      envValidation
    });

    this.results = [...hardcodedSecrets, ...recommendations];

    return {
      totalFindings: this.results.length,
      findings: this.results,
      severity: this.calculateSeverity(),
      byCategory: this.getCategorySummary(),
      config: {
        envExists,
        envInGitignore,
        envExampleExists,
        hasValidation: !!envValidation
      }
    };
  }

  /**
   * Scan codebase for hardcoded values that should be environment variables
   */
  async scanForHardcodedEnvVars() {
    const findings = [];
    const { glob } = require('glob');

    // Patterns that suggest hardcoded secrets
    const patterns = [
      {
        pattern: /(MONGODB_URI|DATABASE_URL|MONGO_URL)\s*[=:]\s*['"]mongodb/m,
        title: 'Hardcoded database connection string',
        remediation: 'Move to environment variable: MONGODB_URI=mongodb://...',
        category: 'hardcoded-db-uri',
        severity: 'critical'
      },
      {
        pattern: /(JWT_SECRET|SECRET_KEY|APP_SECRET)\s*[=:]\s*['"][^'"]{8,}['"]/m,
        title: 'Hardcoded JWT or app secret',
        remediation: 'Move to environment variable: JWT_SECRET=your-secret-key',
        category: 'hardcoded-secret',
        severity: 'critical'
      },
      {
        pattern: /(API_KEY|STRIPE_|SENDGRID_|AWS_|OPENAI_)[A-Z_]*\s*[=:]\s*['"][a-zA-Z0-9]{16,}['"]/m,
        title: 'Hardcoded API key',
        remediation: 'Move to environment variable',
        category: 'hardcoded-api-key',
        severity: 'critical'
      },
      {
        pattern: /(PASSWORD|PASSWD|PWD)\s*[=:]\s*['"][^'"]+['"]/mi,
        title: 'Hardcoded password',
        remediation: 'Move to environment variable: DB_PASSWORD=...',
        category: 'hardcoded-password',
        severity: 'critical'
      },
      {
        pattern: /(SESSION_SECRET|COOKIE_SECRET)\s*[=:]\s*['"][^'"]+['"]/m,
        title: 'Hardcoded session/cookie secret',
        remediation: 'Move to environment variable: SESSION_SECRET=...',
        category: 'hardcoded-session-secret',
        severity: 'high'
      }
    ];

    try {
      const files = await glob('**/*.{js,ts,jsx,tsx,py,rb,go}', {
        cwd: this.targetPath,
        nodir: true,
        ignore: ['node_modules/**', '.git/**', 'dist/**', 'build/**', '*.test.*', '*.spec.*'],
        absolute: true
      });

      for (const file of files) {
        try {
          const content = fs.readFileSync(file, 'utf-8');
          const relativePath = path.relative(this.targetPath, file);

          // Skip .env files themselves
          if (relativePath.startsWith('.env')) continue;

          for (const { pattern, title, remediation, category, severity } of patterns) {
            pattern.lastIndex = 0;
            if (pattern.test(content)) {
              findings.push({
                id: `ENV-HARDCODED-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`,
                type: 'environment-variable',
                category,
                severity,
                title,
                file: relativePath,
                line: this.findLineNumber(content, pattern),
                remediation,
                owaspReference: 'A07:2021 – Identification and Authentication Failures'
              });
            }
          }
        } catch (error) {
          // Skip unreadable files
        }
      }
    } catch (error) {
      // Continue if glob fails
    }

    return findings;
  }

  /**
   * Validate .env file format
   */
  validateEnvFile(envPath) {
    const issues = [];
    const content = fs.readFileSync(envPath, 'utf-8');
    const lines = content.split('\n');

    for (let i = 0; i < lines.length; i++) {
      const line = lines[i].trim();
      
      // Skip empty lines and comments
      if (!line || line.startsWith('#')) continue;

      // Check for proper KEY=VALUE format
      if (!/^[A-Z_][A-Z0-9_]*=.*/.test(line)) {
        issues.push({
          line: i + 1,
          issue: 'Invalid format. Use UPPERCASE_WITH_UNDERSCORES=value',
          suggestion: line
        });
      }

      // Check for spaces around =
      if (/\s+=\s+/.test(line)) {
        issues.push({
          line: i + 1,
          issue: 'Remove spaces around = sign',
          suggestion: line.replace(/\s*=\s*/, '=')
        });
      }

      // Check for unquoted values with special characters
      if (/=[^\s].*[\s$`]/.test(line) && !/=['"].*['"]/.test(line)) {
        issues.push({
          line: i + 1,
          issue: 'Value with special characters should be quoted',
          suggestion: line.replace(/=(.*)/, '="$1"')
        });
      }
    }

    return {
      totalLines: lines.length,
      validEntries: lines.filter(l => /^[A-Z_][A-Z0-9_]*=.*/.test(l.trim())).length,
      issues
    };
  }

  /**
   * Generate configuration recommendations
   */
  generateRecommendations(config) {
    const recommendations = [];

    if (!config.envInGitignore) {
      recommendations.push({
        id: 'ENV-GITIGNORE',
        type: 'environment-variable',
        category: 'gitignore-missing',
        severity: 'critical',
        title: '.env file not in .gitignore',
        file: '.gitignore',
        line: null,
        remediation: 'Add ".env" to .gitignore immediately to prevent committing secrets!',
        owaspReference: 'A07:2021 – Identification and Authentication Failures',
        autoFix: this.generateGitignoreFix()
      });
    }

    if (!config.envExampleExists) {
      recommendations.push({
        id: 'ENV-EXAMPLE',
        type: 'environment-variable',
        category: 'missing-env-example',
        severity: 'medium',
        title: 'No .env.example file found',
        file: '.env.example',
        line: null,
        remediation: 'Create .env.example with all required variables (without values) for documentation.',
        owaspReference: 'A07:2021 – Identification and Authentication Failures',
        autoFix: this.generateEnvExample()
      });
    }

    if (!config.envExists && config.hardcodedSecrets.length > 0) {
      recommendations.push({
        id: 'ENV-MISSING',
        type: 'environment-variable',
        category: 'missing-env-file',
        severity: 'high',
        title: 'No .env file but hardcoded secrets detected',
        file: '.env',
        line: null,
        remediation: 'Create .env file and move all hardcoded secrets to environment variables.',
        owaspReference: 'A07:2021 – Identification and Authentication Failures'
      });
    }

    if (config.envValidation?.issues?.length > 0) {
      recommendations.push({
        id: 'ENV-FORMAT',
        type: 'environment-variable',
        category: 'invalid-env-format',
        severity: 'low',
        title: `${config.envValidation.issues.length} formatting issue(s) in .env file`,
        file: '.env',
        line: null,
        remediation: 'Fix .env file formatting issues for better maintainability.',
        owaspReference: 'A07:2021 – Identification and Authentication Failures'
      });
    }

    return recommendations;
  }

  /**
   * Generate .gitignore fix
   */
  generateGitignoreFix() {
    return {
      action: 'append-to-gitignore',
      content: '\n# Environment variables\n.env\n.env.local\n.env.production\n*.env\n'
    };
  }

  /**
   * Generate .env.example template
   */
  generateEnvExample() {
    // Extract common env var patterns from codebase
    const commonVars = [
      '# Database',
      'DATABASE_URL=postgresql://user:password@localhost:5432/dbname',
      'MONGODB_URI=mongodb://localhost:27017/dbname',
      '',
      '# Authentication',
      'JWT_SECRET=your-jwt-secret-key-here',
      'SESSION_SECRET=your-session-secret-here',
      '',
      '# API Keys',
      'STRIPE_SECRET_KEY=sk_test_...',
      'STRIPE_PUBLISHABLE_KEY=pk_test_...',
      'SENDGRID_API_KEY=SG.xxx',
      '',
      '# Application',
      'NODE_ENV=development',
      'PORT=3000',
      'CORS_ORIGIN=http://localhost:3000'
    ];

    return {
      action: 'create-file',
      filename: '.env.example',
      content: commonVars.join('\n')
    };
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

module.exports = EnvScanner;
