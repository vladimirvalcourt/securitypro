const chalk = require('chalk');
const { THREAT_MATRIX, SECURITY_STACK, GOLDEN_RULES } = require('../patterns/threat-matrix');

/**
 * Threat Matrix Reporter
 * Displays comprehensive security threats specific to vibe-coded apps
 */
class ThreatMatrixReporter {
  constructor() {
    this.severityIcons = {
      critical: '🔴',
      high: '🟠',
      medium: '🟡',
      low: '🔵'
    };
  }

  /**
   * Display complete threat matrix
   */
  displayThreatMatrix() {
    console.log('\n');
    console.log(chalk.bold.red('╔═══════════════════════════════════════════════════════════╗'));
    console.log(chalk.bold.red('║     🔴 THREAT MATRIX: Vibe Coded Apps                    ║'));
    console.log(chalk.bold.red('║     Comprehensive Security Threats for AI-Generated Code ║'));
    console.log(chalk.bold.red('╚═══════════════════════════════════════════════════════════╝'));
    console.log('\n');

    THREAT_MATRIX.forEach((threat, index) => {
      const icon = this.severityIcons[threat.severity];
      const color = this.getSeverityColor(threat.severity);

      console.log(color(`\n### ${index + 1}. ${threat.name}`));
      console.log(chalk.dim('─'.repeat(60)));
      console.log(`${icon} ${color(`Severity: ${threat.severity.toUpperCase()}`)}`);
      console.log(chalk.white(`Category: ${threat.category}`));
      console.log(chalk.cyan(`ID: ${threat.id}`));
      console.log('\n');
      console.log(chalk.white('Description:'));
      console.log(chalk.gray(`  ${threat.description}`));
      console.log('\n');
      console.log(chalk.yellow('Red Team Attack Vector:'));
      console.log(chalk.gray(`  ${threat.attackVector}`));
      console.log('\n');
      console.log(chalk.green('✅ Solution:'));
      threat.remediation.forEach(step => {
        console.log(chalk.green(`  • ${step}`));
      });

      if (threat.owaspReference) {
        console.log(chalk.magenta(`\n  OWASP Reference: ${threat.owaspReference}`));
      }

      console.log('\n');
    });
  }

  /**
   * Display Red Team Security Stack
   */
  displaySecurityStack() {
    console.log('\n');
    console.log(chalk.bold.cyan('╔═══════════════════════════════════════════════════════════╗'));
    console.log(chalk.bold.cyan('║     🛡️  Red Team Security Stack for Vibe Coders         ║'));
    console.log(chalk.bold.cyan('╚═══════════════════════════════════════════════════════════╝'));
    console.log('\n');

    Object.entries(SECURITY_STACK).forEach(([layer, info]) => {
      console.log(chalk.bold.white(`**${this.formatLayerName(layer)}**`));
      console.log(chalk.cyan(`  Tools: ${info.tools.join(', ')}`));
      console.log(chalk.gray(`  Purpose: ${info.purpose}`));
      console.log('\n');
    });
  }

  /**
   * Display Golden Rules
   */
  displayGoldenRules() {
    console.log('\n');
    console.log(chalk.bold.yellow('╔═══════════════════════════════════════════════════════════╗'));
    console.log(chalk.bold.yellow('║     🚨 Golden Rules for Vibe Coders                     ║'));
    console.log(chalk.bold.yellow('╚═══════════════════════════════════════════════════════════╝'));
    console.log('\n');

    GOLDEN_RULES.forEach((rule, index) => {
      console.log(chalk.yellow(`${index + 1}. ${rule}`));
    });

    console.log('\n');
    console.log(chalk.bold.red('53% of organizations have already discovered security issues in AI-generated code that passed initial review.'));
    console.log(chalk.bold.red('The biggest risk isn\'t that AI writes bad code — it\'s that developers trust it without verification.'));
    console.log('\n');
    console.log(chalk.bold.green('Always move fast on UI, but read every line of auth, payment, and data-handling code the AI generates.'));
    console.log('\n');
  }

  /**
   * Get color function for severity
   */
  getSeverityColor(severity) {
    const colors = {
      critical: chalk.red.bold,
      high: chalk.red,
      medium: chalk.yellow,
      low: chalk.blue
    };
    return colors[severity] || chalk.white;
  }

  /**
   * Format layer name for display
   */
  formatLayerName(layer) {
    const names = {
      secretScanning: 'Secret Scanning',
      dependencyAudit: 'Dependency Audit',
      sast: 'SAST (Static Analysis)',
      auth: 'Authentication',
      rateLimiting: 'Rate Limiting',
      secretsManagement: 'Secrets Management',
      logging: 'Logging & Monitoring',
      dast: 'DAST/Pen Testing',
      cspHeaders: 'CSP/Security Headers'
    };
    return names[layer] || layer;
  }
}

module.exports = ThreatMatrixReporter;
