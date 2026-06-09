const chalk = require('chalk');

/**
 * Console reporter with colorful, user-friendly output
 */
class ConsoleReporter {
  constructor() {
    this.severityIcons = {
      critical: '🔴',
      high: '🟠',
      medium: '🟡',
      low: '🔵',
      none: '✅'
    };

    this.severityColors = {
      critical: chalk.red.bold,
      high: chalk.red,
      medium: chalk.yellow,
      low: chalk.blue,
      none: chalk.green
    };
  }

  /**
   * Display scan header
   */
  displayHeader(targetPath) {
    console.log('\n');
    console.log(chalk.bold.cyan('╔═══════════════════════════════════════════════════════════╗'));
    console.log(chalk.bold.cyan('║         🔒 Vibe Security Auditor v1.0                    ║'));
    console.log(chalk.bold.cyan('║         Comprehensive Code Security Scanner              ║'));
    console.log(chalk.bold.cyan('╚═══════════════════════════════════════════════════════════╝'));
    console.log('\n');
    console.log(chalk.dim(`Target: ${targetPath}`));
    console.log(chalk.dim(`Scan started: ${new Date().toLocaleString()}`));
    console.log(chalk.dim('─'.repeat(60)));
  }

  /**
   * Display scan results summary
   */
  displaySummary(results) {
    const { secretScan, owaspScan, authScan, dbScan, apiScan } = results;

    console.log('\n');
    console.log(chalk.bold.white('📊 SCAN SUMMARY'));
    console.log(chalk.dim('─'.repeat(60)));

    // Secret scan results
    if (secretScan.totalFindings > 0) {
      console.log(chalk.red.bold(`\n🔑 Hardcoded Secrets: ${secretScan.totalFindings} issues found`));
      this.displaySeverityBreakdown(secretScan.findings);
    } else {
      console.log(chalk.green('\n✅ No hardcoded secrets detected'));
    }

    // OWASP results
    if (owaspScan.totalFindings > 0) {
      console.log(chalk.red.bold(`\n🛡️  OWASP Vulnerabilities: ${owaspScan.totalFindings} issues found`));
      this.displayCategoryBreakdown(owaspScan.findings);
    } else {
      console.log(chalk.green('\n✅ No OWASP vulnerabilities detected'));
    }

    // Auth results
    if (authScan.totalFindings > 0) {
      console.log(chalk.red.bold(`\n🔐 Authentication Issues: ${authScan.totalFindings} issues found`));
      this.displayCategoryBreakdown(authScan.findings);
    } else {
      console.log(chalk.green('\n✅ No authentication issues detected'));
    }

    // Database results
    if (dbScan.totalFindings > 0) {
      console.log(chalk.red.bold(`\n🗄️  Database Security: ${dbScan.totalFindings} issues found`));
      this.displayCategoryBreakdown(dbScan.findings);
    } else {
      console.log(chalk.green('\n✅ No database security issues detected'));
    }

    // API results
    if (apiScan.totalFindings > 0) {
      console.log(chalk.red.bold(`\n🌐 API Security: ${apiScan.totalFindings} issues found`));
      this.displayCategoryBreakdown(apiScan.findings);
    } else {
      console.log(chalk.green('\n✅ No API security issues detected'));
    }

    // Overall assessment
    this.displayOverallAssessment(results);
  }

  /**
   * Display severity breakdown
   */
  displaySeverityBreakdown(findings) {
    const bySeverity = { critical: 0, high: 0, medium: 0, low: 0 };
    findings.forEach(f => bySeverity[f.severity]++);

    Object.entries(bySeverity).forEach(([severity, count]) => {
      if (count > 0) {
        const icon = this.severityIcons[severity];
        const color = this.severityColors[severity];
        console.log(`   ${icon} ${color(severity.toUpperCase())}: ${count}`);
      }
    });
  }

  /**
   * Display category breakdown
   */
  displayCategoryBreakdown(findings) {
    const byCategory = {};
    findings.forEach(f => {
      byCategory[f.category] = (byCategory[f.category] || 0) + 1;
    });

    Object.entries(byCategory).slice(0, 5).forEach(([category, count]) => {
      console.log(`   • ${category}: ${count}`);
    });

    if (Object.keys(byCategory).length > 5) {
      console.log(`   ... and ${Object.keys(byCategory).length - 5} more categories`);
    }
  }

  /**
   * Display overall security assessment
   */
  displayOverallAssessment(results) {
    const totalIssues =
      (results.secretScan?.totalFindings || 0) +
      (results.owaspScan?.totalFindings || 0) +
      (results.authScan?.totalFindings || 0) +
      (results.dbScan?.totalFindings || 0) +
      (results.apiScan?.totalFindings || 0);

    const hasCritical = [
      results.secretScan,
      results.owaspScan,
      results.authScan,
      results.dbScan,
      results.apiScan
    ].some(scan => scan?.findings?.some(f => f.severity === 'critical'));

    console.log('\n');
    console.log(chalk.bold.white('🎯 OVERALL SECURITY ASSESSMENT'));
    console.log(chalk.dim('─'.repeat(60)));

    if (totalIssues === 0) {
      console.log(chalk.green.bold('\n✅ EXCELLENT! No security issues detected.'));
      console.log(chalk.green('Your codebase follows security best practices.'));
    } else if (hasCritical) {
      console.log(chalk.red.bold('\n🚨 CRITICAL: Immediate action required!'));
      console.log(chalk.red(`${totalIssues} security issues found, including critical vulnerabilities.`));
      console.log(chalk.red('Fix critical issues before deploying to production.'));
    } else {
      console.log(chalk.yellow.bold(`\n⚠️  WARNING: ${totalIssues} security issues detected.`));
      console.log(chalk.yellow('Review and fix issues to improve security posture.'));
    }

    console.log('\n');
  }

  /**
   * Display detailed findings
   */
  displayDetailedFindings(results) {
    console.log('\n');
    console.log(chalk.bold.white('📋 DETAILED FINDINGS'));
    console.log(chalk.dim('─'.repeat(60)));

    const allFindings = [
      ...(results.secretScan?.findings || []),
      ...(results.owaspScan?.findings || []),
      ...(results.authScan?.findings || []),
      ...(results.dbScan?.findings || []),
      ...(results.apiScan?.findings || [])
    ];

    // Sort by severity
    const severityOrder = { critical: 0, high: 1, medium: 2, low: 3 };
    allFindings.sort((a, b) => severityOrder[a.severity] - severityOrder[b.severity]);

    allFindings.forEach((finding, index) => {
      console.log('\n');
      const icon = this.severityIcons[finding.severity];
      const color = this.severityColors[finding.severity];

      console.log(`${icon} ${color(`[${finding.severity.toUpperCase()}]`)} ${chalk.bold(finding.title)}`);
      console.log(chalk.dim(`   ID: ${finding.id}`));
      console.log(chalk.dim(`   Type: ${finding.type}`));
      console.log(chalk.cyan(`   File: ${finding.file}:${finding.line || '?'}`));

      if (finding.matchedPattern) {
        console.log(chalk.yellow(`   Pattern: ${finding.matchedPattern}`));
      }

      if (finding.suggestedEnvVar) {
        console.log(chalk.green(`   Use env var: ${finding.suggestedEnvVar}`));
      }

      console.log(chalk.white(`   Issue: ${finding.remediation}`));

      if (finding.owaspReference) {
        console.log(chalk.magenta(`   OWASP: ${finding.owaspReference}`));
      }

      if (finding.explanation) {
        console.log(chalk.cyan(`\n   🤖 AI Explanation: ${finding.explanation}`));
      }

      // Add separator except for last item
      if (index < allFindings.length - 1) {
        console.log(chalk.dim('   ' + '─'.repeat(50)));
      }
    });

    console.log('\n');
  }

  /**
   * Display remediation guide
   */
  displayRemediationGuide(results) {
    console.log('\n');
    console.log(chalk.bold.white('🔧 REMEDIATION GUIDE'));
    console.log(chalk.dim('─'.repeat(60)));

    const allFindings = [
      ...(results.secretScan?.findings || []),
      ...(results.owaspScan?.findings || []),
      ...(results.authScan?.findings || []),
      ...(results.dbScan?.findings || []),
      ...(results.apiScan?.findings || [])
    ];

    // Group by priority
    const critical = allFindings.filter(f => f.severity === 'critical');
    const high = allFindings.filter(f => f.severity === 'high');
    const medium = allFindings.filter(f => f.severity === 'medium');

    if (critical.length > 0) {
      console.log(chalk.red.bold('\n🔴 CRITICAL PRIORITY (Fix Immediately):'));
      critical.forEach(f => {
        console.log(chalk.red(`   • ${f.file}:${f.line || '?'} - ${f.remediation}`));
      });
    }

    if (high.length > 0) {
      console.log(chalk.yellow.bold('\n🟠 HIGH PRIORITY (Fix Before Production):'));
      high.slice(0, 10).forEach(f => {
        console.log(chalk.yellow(`   • ${f.file}:${f.line || '?'} - ${f.remediation}`));
      });
      if (high.length > 10) {
        console.log(chalk.yellow(`   ... and ${high.length - 10} more high priority issues`));
      }
    }

    if (medium.length > 0) {
      console.log(chalk.blue.bold('\n🟡 MEDIUM PRIORITY (Fix When Possible):'));
      medium.slice(0, 5).forEach(f => {
        console.log(chalk.blue(`   • ${f.file}:${f.line || '?'} - ${f.remediation}`));
      });
      if (medium.length > 5) {
        console.log(chalk.blue(`   ... and ${medium.length - 5} more medium priority issues`));
      }
    }

    console.log('\n');
    console.log(chalk.bold.white('💡 QUICK FIXES:'));
    console.log(chalk.dim('─'.repeat(60)));
    console.log(chalk.green('1. Move all secrets to .env file (add to .gitignore)'));
    console.log(chalk.green('2. Install and configure helmet for security headers'));
    console.log(chalk.green('3. Add input validation with Zod or Yup'));
    console.log(chalk.green('4. Enable rate limiting on all endpoints'));
    console.log(chalk.green('5. Use parameterized queries for database operations'));
    console.log('\n');
  }

  /**
   * Display scan completion
   */
  displayCompletion(duration) {
    console.log(chalk.dim('─'.repeat(60)));
    console.log(chalk.dim(`Scan completed in ${(duration / 1000).toFixed(2)}s`));
    console.log(chalk.dim('─'.repeat(60)));
    console.log('\n');
    console.log(chalk.cyan('Stay secure! 🔒'));
    console.log('\n');
  }
}

module.exports = ConsoleReporter;
