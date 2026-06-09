/**
 * Vibe Security Auditor - Main Module
 * Programmatic API for security scanning
 */

const SecretScanner = require('./scanners/secret-scanner');
const OwaspScanner = require('./scanners/owasp-scanner');
const AuthScanner = require('./scanners/auth-scanner');
const DatabaseScanner = require('./scanners/database-scanner');
const ApiScanner = require('./scanners/api-scanner');
const ConsoleReporter = require('./reporters/console-reporter');
const JsonReporter = require('./reporters/json-reporter');

/**
 * Run comprehensive security audit
 * @param {Object} options - Scan configuration
 * @param {string} options.targetPath - Path to scan
 * @param {boolean} options.scanSecrets - Enable secret detection (default: true)
 * @param {boolean} options.scanOwasp - Enable OWASP scan (default: true)
 * @param {boolean} options.scanAuth - Enable auth scan (default: true)
 * @param {boolean} options.scanDb - Enable database scan (default: true)
 * @param {boolean} options.scanApi - Enable API scan (default: true)
 * @returns {Promise<Object>} Complete scan results
 */
async function audit(options = {}) {
  const {
    targetPath = process.cwd(),
    scanSecrets = true,
    scanOwasp = true,
    scanAuth = true,
    scanDb = true,
    scanApi = true
  } = options;

  const results = {};

  if (scanSecrets) {
    const scanner = new SecretScanner({ targetPath });
    results.secretScan = await scanner.scan();
  }

  if (scanOwasp) {
    const scanner = new OwaspScanner({ targetPath });
    results.owaspScan = await scanner.scan();
  }

  if (scanAuth) {
    const scanner = new AuthScanner({ targetPath });
    results.authScan = await scanner.scan();
  }

  if (scanDb) {
    const scanner = new DatabaseScanner({ targetPath });
    results.dbScan = await scanner.scan();
  }

  if (scanApi) {
    const scanner = new ApiScanner({ targetPath });
    results.apiScan = await scanner.scan();
  }

  return results;
}

module.exports = {
  audit,
  SecretScanner,
  OwaspScanner,
  AuthScanner,
  DatabaseScanner,
  ApiScanner,
  ConsoleReporter,
  JsonReporter
};
