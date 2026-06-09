#!/usr/bin/env node

const { Command } = require('commander');
const path = require('path');
const chalk = require('chalk');
const fs = require('fs');

// Import scanners
const SecretScanner = require('./scanners/secret-scanner');
const OwaspScanner = require('./scanners/owasp-scanner');
const AuthScanner = require('./scanners/auth-scanner');
const DatabaseScanner = require('./scanners/database-scanner');
const ApiScanner = require('./scanners/api-scanner');

// Import reporters
const ConsoleReporter = require('./reporters/console-reporter');
const JsonReporter = require('./reporters/json-reporter');
const ThreatMatrixReporter = require('./reporters/threat-matrix-reporter');

const program = new Command();

program
  .name('securitypro')
  .description('🔒 Professional security audit tool for developers')
  .version('1.0.0');

program
  .command('scan')
  .description('Run comprehensive security scan on a codebase')
  .option('-p, --path <path>', 'Path to scan (default: current directory)', '.')
  .option('-o, --output <file>', 'Output report to JSON file')
  .option('--no-secrets', 'Skip secret detection scan')
  .option('--no-owasp', 'Skip OWASP vulnerability scan')
  .option('--no-auth', 'Skip authentication scan')
  .option('--no-db', 'Skip database scan')
  .option('--no-api', 'Skip API scan')
  .option('--ignore <patterns>', 'Comma-separated patterns to ignore', '')
  .option('--verbose', 'Show detailed findings', false)
  .action(async (options) => {
    const startTime = Date.now();
    const targetPath = path.resolve(options.path);

    // Validate target path
    if (!fs.existsSync(targetPath)) {
      console.error(chalk.red(`Error: Path "${targetPath}" does not exist.`));
      process.exit(1);
    }

    const reporter = new ConsoleReporter();
    reporter.displayHeader(targetPath);

    const results = {};

    try {
      // Run Secret Scanner
      if (options.secrets) {
        const secretScanner = new SecretScanner({
          targetPath,
          ignorePatterns: options.ignore ? options.ignore.split(',') : []
        });
        results.secretScan = await secretScanner.scan();
      }

      // Run OWASP Scanner
      if (options.owasp) {
        const owaspScanner = new OwaspScanner({ targetPath });
        results.owaspScan = await owaspScanner.scan();
      }

      // Run Auth Scanner
      if (options.auth) {
        const authScanner = new AuthScanner({ targetPath });
        results.authScan = await authScanner.scan();
      }

      // Run Database Scanner
      if (options.db) {
        const dbScanner = new DatabaseScanner({ targetPath });
        results.dbScan = await dbScanner.scan();
      }

      // Run API Scanner
      if (options.api) {
        const apiScanner = new ApiScanner({ targetPath });
        results.apiScan = await apiScanner.scan();
      }

      const duration = Date.now() - startTime;

      // Display results
      reporter.displaySummary(results);

      if (options.verbose) {
        reporter.displayDetailedFindings(results);
      }

      reporter.displayRemediationGuide(results);
      reporter.displayCompletion(duration);

      // Generate JSON report if requested
      if (options.output) {
        const jsonReporter = new JsonReporter();
        const report = jsonReporter.generateReport(results, targetPath, duration);
        const outputPath = jsonReporter.saveToFile(report, options.output);
        console.log(chalk.green(`✓ JSON report saved to: ${outputPath}`));
      }

      // Exit with error code if critical issues found
      const hasCritical = [
        results.secretScan,
        results.owaspScan,
        results.authScan,
        results.dbScan,
        results.apiScan
      ].some(scan => scan?.findings?.some(f => f.severity === 'critical'));

      if (hasCritical) {
        process.exit(2);
      }

    } catch (error) {
      console.error(chalk.red('\n❌ Scan failed:'), error.message);
      console.error(error.stack);
      process.exit(1);
    }
  });

program
  .command('quick')
  .description('Quick scan for hardcoded secrets only')
  .option('-p, --path <path>', 'Path to scan (default: current directory)', '.')
  .action(async (options) => {
    const targetPath = path.resolve(options.path);

    if (!fs.existsSync(targetPath)) {
      console.error(chalk.red(`Error: Path "${targetPath}" does not exist.`));
      process.exit(1);
    }

    console.log(chalk.cyan('\n⚡ Running quick secret scan...\n'));

    const scanner = new SecretScanner({ targetPath });
    const results = await scanner.scan();

    if (results.totalFindings === 0) {
      console.log(chalk.green('✅ No hardcoded secrets detected!'));
    } else {
      console.log(chalk.red(`\n🚨 Found ${results.totalFindings} potential secrets!\n`));

      results.findings.forEach(finding => {
        const icon = finding.severity === 'critical' ? '🔴' : '🟠';
        console.log(`${icon} ${finding.title}`);
        console.log(chalk.dim(`   ${finding.file}:${finding.line}`));
        console.log(chalk.yellow(`   → ${finding.remediation}`));
        console.log('');
      });
    }
  });

program
  .command('check-config')
  .description('Check security configuration files')
  .option('-p, --path <path>', 'Path to check (default: current directory)', '.')
  .action(async (options) => {
    const targetPath = path.resolve(options.path);

    console.log(chalk.cyan('\n🔍 Checking security configuration...\n'));

    const checks = [
      { file: '.env', required: false, description: 'Environment variables file' },
      { file: '.gitignore', required: true, description: 'Git ignore file' },
      { file: 'package.json', required: true, description: 'Package manifest' },
      { file: '.eslintrc.json', required: false, description: 'ESLint config' },
      { file: 'Dockerfile', required: false, description: 'Docker configuration' }
    ];

    checks.forEach(check => {
      const filePath = path.join(targetPath, check.file);
      const exists = fs.existsSync(filePath);
      const status = exists ? chalk.green('✓') : (check.required ? chalk.red('✗') : chalk.yellow('○'));
      console.log(`${status} ${check.file.padEnd(20)} - ${check.description}`);

      if (check.file === '.gitignore' && exists) {
        const content = fs.readFileSync(filePath, 'utf-8');
        if (!content.includes('.env')) {
          console.log(chalk.yellow('   ⚠️  Warning: .env not in .gitignore!'));
        }
      }
    });

    console.log('\n');
  });

program
  .command('threats')
  .description('Display comprehensive threat matrix for vibe-coded apps')
  .action(() => {
    const reporter = new ThreatMatrixReporter();
    reporter.displayThreatMatrix();
    reporter.displaySecurityStack();
    reporter.displayGoldenRules();
  });

program
  .command('watch')
  .description('Watch files and scan automatically when they change')
  .option('-p, --path <path>', 'Path to watch (default: current directory)', '.')
  .option('-i, --interval <seconds>', 'Scan interval in seconds', '5')
  .option('-q, --quiet', 'Only show critical issues', false)
  .action(async (options) => {
    const chokidar = require('chokidar');
    const targetPath = path.resolve(options.path);
    const interval = parseInt(options.interval) * 1000;
    const quiet = options.quiet;

    if (!fs.existsSync(targetPath)) {
      console.error(chalk.red(`Error: Path "${targetPath}" does not exist.`));
      process.exit(1);
    }

    console.log(chalk.cyan('\n👁️  SecurityPro Watch Mode Activated'));
    console.log(chalk.dim('─'.repeat(60)));
    console.log(chalk.cyan(`Watching: ${targetPath}`));
    console.log(chalk.cyan(`Scan interval: ${options.interval}s`));
    console.log(chalk.cyan('Press Ctrl+C to stop\n'));

    let lastScanTime = 0;
    let changedFiles = new Set();

    // Initialize watcher
    const watcher = chokidar.watch(targetPath, {
      ignored: [
        /node_modules/,
        /\.git/,
        /dist/,
        /build/,
        /\.securitypro-cache/,
        /\.(log|png|jpg|jpeg|gif|ico|pdf|zip)$/
      ],
      persistent: true,
      ignoreInitial: true
    });

    // Track file changes
    watcher.on('change', (filePath) => {
      changedFiles.add(filePath);
    });

    watcher.on('add', (filePath) => {
      changedFiles.add(filePath);
    });

    // Periodic scanning
    setInterval(async () => {
      if (changedFiles.size === 0) return;

      const now = Date.now();
      if (now - lastScanTime < interval) return;

      lastScanTime = now;
      const filesToScan = Array.from(changedFiles);
      changedFiles.clear();

      console.log(chalk.yellow(`\n[${new Date().toLocaleTimeString()}] Scanning ${filesToScan.length} changed file(s)...`));

      try {
        const results = {};
        let totalIssues = 0;

        // Quick secret scan on changed files
        const SecretScanner = require('./scanners/secret-scanner');
        const secretScanner = new SecretScanner({ targetPath });
        
        for (const file of filesToScan) {
          try {
            const content = fs.readFileSync(file, 'utf-8');
            const findings = secretScanner.scanFile(file, content);
            if (findings.length > 0) {
              results.secretFindings = findings;
              totalIssues += findings.length;
            }
          } catch (error) {
            // Skip binary files
          }
        }

        if (totalIssues === 0) {
          console.log(chalk.green('✓ No issues found\n'));
        } else {
          console.log(chalk.red(`\n🚨 Found ${totalIssues} security issue(s):\n`));
          
          results.secretFindings.forEach(finding => {
            if (quiet && finding.severity !== 'critical') return;
            
            const icon = finding.severity === 'critical' ? '🔴' : 
                        finding.severity === 'high' ? '🟠' : '🟡';
            console.log(`${icon} ${chalk.bold(finding.title)}`);
            console.log(chalk.dim(`   File: ${finding.file}:${finding.line}`));
            console.log(chalk.green(`   Fix: ${finding.remediation}`));
            console.log('');
          });

          console.log(chalk.yellow('💡 Tip: Fix these issues before committing!\n'));
        }
      } catch (error) {
        console.error(chalk.red('Scan error:', error.message));
      }
    }, 1000); // Check every second, but only scan at interval

    console.log(chalk.green('✓ Watching for changes...\n'));

    // Handle graceful shutdown
    process.on('SIGINT', () => {
      console.log(chalk.cyan('\n\n👋 Watch mode stopped. Stay secure!\n'));
      watcher.close();
      process.exit(0);
    });
  });

program.parse(process.argv);

// Show help if no command provided
if (!process.argv.slice(2).length) {
  program.outputHelp();
}
