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
const DependencyScanner = require('./scanners/dependency-scanner');
const EnvScanner = require('./scanners/env-scanner');
const PreCommitScanner = require('./scanners/precommit-scanner');
const PromptScanner = require('./scanners/prompt-scanner');
const HeadersScanner = require('./scanners/headers-scanner');
const UploadScanner = require('./scanners/upload-scanner');
const WebhookScanner = require('./scanners/webhook-scanner');
const RateLimitScanner = require('./scanners/rate-limit-scanner');

// Import generators
const ConfigGenerator = require('./generators/config-generator');

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
  .option('--no-deps', 'Skip dependency vulnerability scan')
  .option('--no-env', 'Skip environment variable validation')
  .option('--no-headers', 'Skip HTTP headers audit')
  .option('--no-uploads', 'Skip file upload security scan')
  .option('--no-webhooks', 'Skip webhook security validation')
  .option('--no-ratelimit', 'Skip rate limiting check')
  .option('--no-prompts', 'Skip AI prompt security analysis')
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

      // Run Dependency Scanner
      if (options.deps) {
        const depScanner = new DependencyScanner({ targetPath });
        results.dependencyScan = await depScanner.scan();
      }

      // Run Environment Variable Scanner
      if (options.env) {
        const envScanner = new EnvScanner({ targetPath });
        results.envScan = await envScanner.scan();
      }

      // Run Headers Scanner
      if (options.headers) {
        const headersScanner = new HeadersScanner({ targetPath });
        results.headersScan = await headersScanner.scan();
      }

      // Run Upload Scanner
      if (options.uploads) {
        const uploadScanner = new UploadScanner({ targetPath });
        results.uploadScan = await uploadScanner.scan();
      }

      // Run Webhook Scanner
      if (options.webhooks) {
        const webhookScanner = new WebhookScanner({ targetPath });
        results.webhookScan = await webhookScanner.scan();
      }

      // Run Rate Limit Scanner
      if (options.ratelimit) {
        const rateLimitScanner = new RateLimitScanner({ targetPath });
        results.rateLimitScan = await rateLimitScanner.scan();
      }

      // Run Prompt Scanner
      if (options.prompts) {
        const promptScanner = new PromptScanner({ targetPath });
        results.promptScan = await promptScanner.scan();
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
        results.apiScan,
        results.dependencyScan,
        results.envScan,
        results.headersScan,
        results.uploadScan,
        results.webhookScan,
        results.rateLimitScan,
        results.promptScan
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

program
  .command('precommit')
  .description('Manage pre-commit hook installation')
  .option('-p, --path <path>', 'Project path (default: current directory)', '.')
  .option('--install', 'Install pre-commit hook')
  .option('--uninstall', 'Remove pre-commit hook')
  .option('--husky', 'Setup Husky integration')
  .option('--check', 'Check if hook is installed')
  .action(async (options) => {
    const targetPath = path.resolve(options.path);
    const scanner = new PreCommitScanner({ targetPath });

    if (options.install) {
      const result = await scanner.installHook();
      process.exit(result.success ? 0 : 1);
    } else if (options.uninstall) {
      const result = scanner.uninstallHook();
      process.exit(result.success ? 0 : 1);
    } else if (options.husky) {
      const result = await scanner.setupHusky();
      process.exit(result.success ? 0 : 1);
    } else if (options.check) {
      const installed = scanner.isHookInstalled();
      console.log(installed ? chalk.green('✅ Pre-commit hook is installed') : chalk.yellow('⚠️  No pre-commit hook found'));
      process.exit(installed ? 0 : 1);
    } else {
      // Default: run scan on staged files
      const result = await scanner.scan();
      process.exit(result.success ? 0 : 1);
    }
  });

program
  .command('deps')
  .description('Scan dependencies for known vulnerabilities')
  .option('-p, --path <path>', 'Path to scan (default: current directory)', '.')
  .action(async (options) => {
    const targetPath = path.resolve(options.path);
    
    if (!fs.existsSync(targetPath)) {
      console.error(chalk.red(`Error: Path "${targetPath}" does not exist.`));
      process.exit(1);
    }

    const scanner = new DependencyScanner({ targetPath });
    const results = await scanner.scan();

    if (results.totalFindings === 0) {
      console.log(chalk.green('\n✅ No dependency vulnerabilities found!'));
    } else {
      console.log(chalk.red(`\n🚨 Found ${results.totalFindings} vulnerability(ies)!\n`));
      
      results.findings.forEach(finding => {
        const icon = finding.severity === 'critical' ? '🔴' : 
                    finding.severity === 'high' ? '🟠' : '🟡';
        console.log(`${icon} [${finding.severity.toUpperCase()}] ${finding.title}`);
        console.log(chalk.dim(`   Package: ${finding.packageName}`));
        console.log(chalk.green(`   Fix: ${finding.remediation}`));
        console.log('');
      });
    }
  });

program
  .command('env-check')
  .description('Validate environment variable configuration')
  .option('-p, --path <path>', 'Path to check (default: current directory)', '.')
  .action(async (options) => {
    const targetPath = path.resolve(options.path);
    
    if (!fs.existsSync(targetPath)) {
      console.error(chalk.red(`Error: Path "${targetPath}" does not exist.`));
      process.exit(1);
    }

    const scanner = new EnvScanner({ targetPath });
    const results = await scanner.scan();

    if (results.totalFindings === 0) {
      console.log(chalk.green('\n✅ Environment configuration looks good!'));
    } else {
      console.log(chalk.red(`\n🚨 Found ${results.totalFindings} issue(s)!\n`));
      
      results.findings.forEach(finding => {
        const icon = finding.severity === 'critical' ? '🔴' : 
                    finding.severity === 'high' ? '🟠' : '🟡';
        console.log(`${icon} [${finding.severity.toUpperCase()}] ${finding.title}`);
        console.log(chalk.dim(`   File: ${finding.file}`));
        console.log(chalk.green(`   Fix: ${finding.remediation}`));
        if (finding.bestPractice) {
          console.log(chalk.blue(`   Best Practice: ${finding.bestPractice}`));
        }
        console.log('');
      });
    }
  });

program
  .command('prompts')
  .description('Analyze AI prompts for security issues')
  .option('-p, --path <path>', 'Path to scan (default: current directory)', '.')
  .action(async (options) => {
    const targetPath = path.resolve(options.path);
    
    if (!fs.existsSync(targetPath)) {
      console.error(chalk.red(`Error: Path "${targetPath}" does not exist.`));
      process.exit(1);
    }

    const scanner = new PromptScanner({ targetPath });
    const results = await scanner.scan();

    if (results.totalFindings === 0) {
      console.log(chalk.green('\n✅ No insecure prompting patterns detected!'));
    } else {
      console.log(chalk.red(`\n🚨 Found ${results.totalFindings} insecure prompt(s)!\n`));
      
      results.findings.forEach(finding => {
        const icon = finding.severity === 'critical' ? '🔴' : 
                    finding.severity === 'high' ? '🟠' : '🟡';
        console.log(`${icon} [${finding.severity.toUpperCase()}] ${finding.title}`);
        console.log(chalk.dim(`   File: ${finding.file}:${finding.line}`));
        console.log(chalk.green(`   Fix: ${finding.remediation}`));
        if (finding.bestPractice) {
          console.log(chalk.blue(`   Better: ${finding.bestPractice}`));
        }
        console.log('');
      });
    }
  });

program
  .command('generate-configs')
  .description('Generate secure configuration templates')
  .option('-p, --path <path>', 'Target directory (default: current directory)', '.')
  .action(async (options) => {
    const targetPath = path.resolve(options.path);
    const generator = new ConfigGenerator({ targetPath });
    await generator.generateAll();
  });

program.parse(process.argv);

// Show help if no command provided
if (!process.argv.slice(2).length) {
  program.outputHelp();
}
