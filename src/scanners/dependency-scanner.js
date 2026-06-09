const fs = require('fs');
const path = require('path');
const { execSync } = require('child_process');

/**
 * Dependency Vulnerability Scanner
 * Scans package.json dependencies for known CVEs and security issues
 */
class DependencyScanner {
  constructor(options = {}) {
    this.targetPath = options.targetPath || process.cwd();
    this.results = [];
  }

  /**
   * Run dependency vulnerability scan
   */
  async scan() {
    console.log('\n📦 Scanning dependencies for known vulnerabilities...\n');

    const packageJsonPath = path.join(this.targetPath, 'package.json');
    
    if (!fs.existsSync(packageJsonPath)) {
      return {
        totalFindings: 0,
        findings: [],
        severity: 'none',
        message: 'No package.json found'
      };
    }

    try {
      const packageJson = JSON.parse(fs.readFileSync(packageJsonPath, 'utf-8'));
      const allDeps = {
        ...packageJson.dependencies,
        ...packageJson.devDependencies
      };

      // Use npm audit for comprehensive scanning
      const auditResults = await this.runNpmAudit();
      
      // Check for outdated packages
      const outdatedResults = await this.checkOutdatedPackages(Object.keys(allDeps));
      
      // Check for unmaintained packages
      const maintenanceResults = await this.checkPackageMaintenance(Object.keys(allDeps));

      this.results = [...auditResults, ...outdatedResults, ...maintenanceResults];

      return {
        totalFindings: this.results.length,
        findings: this.results,
        severity: this.calculateSeverity(),
        byCategory: this.getCategorySummary(),
        dependenciesScanned: Object.keys(allDeps).length
      };
    } catch (error) {
      console.error('Error scanning dependencies:', error.message);
      return {
        totalFindings: 0,
        findings: [],
        severity: 'none',
        error: error.message
      };
    }
  }

  /**
   * Run npm audit to check for known vulnerabilities
   */
  async runNpmAudit() {
    const findings = [];
    
    try {
      const auditOutput = execSync('npm audit --json', {
        cwd: this.targetPath,
        stdio: ['pipe', 'pipe', 'ignore'],
        timeout: 30000
      }).toString();

      const auditData = JSON.parse(auditOutput);
      
      if (auditData.auditReportVersion === 2) {
        // New audit format
        for (const vuln of auditData.vulnerabilities || []) {
          findings.push({
            id: `DEP-VULN-${vuln.name}-${Date.now()}`,
            type: 'dependency-vulnerability',
            category: 'known-cve',
            severity: this.mapNpmSeverity(vuln.severity),
            title: `Vulnerable package: ${vuln.name}@${vuln.installed}`,
            file: 'package.json',
            line: null,
            packageName: vuln.name,
            installedVersion: vuln.installed,
            vulnerableVersions: vuln.vulnerable_versions,
            patchedVersions: vuln.patched_versions,
            remediation: `Update ${vuln.name} to version ${vuln.patched_versions || 'latest'}. Run: npm install ${vuln.name}@latest`,
            owaspReference: 'A06:2021 – Vulnerable and Outdated Components',
            cve: vuln.via?.[0]?.cve || 'N/A',
            advisory: vuln.via?.[0]?.url || 'N/A'
          });
        }
      } else {
        // Old audit format
        for (const [id, vuln] of Object.entries(auditData.advisories || {})) {
          if (vuln.module_name) {
            findings.push({
              id: `DEP-VULN-${vuln.module_name}-${Date.now()}`,
              type: 'dependency-vulnerability',
              category: 'known-cve',
              severity: this.mapNpmSeverity(vuln.severity),
              title: `Vulnerable package: ${vuln.module_name}@${vuln.findings?.[0]?.version || 'unknown'}`,
              file: 'package.json',
              line: null,
              packageName: vuln.module_name,
              installedVersion: vuln.findings?.[0]?.version || 'unknown',
              vulnerableVersions: vuln.vulnerable_versions,
              patchedVersions: vuln.patched_versions,
              remediation: `Update ${vuln.module_name} to version ${vuln.patched_versions || 'latest'}. Run: npm install ${vuln.module_name}@latest`,
              owaspReference: 'A06:2021 – Vulnerable and Outdated Components',
              cve: vuln.cves?.[0] || 'N/A',
              advisory: vuln.url || 'N/A'
            });
          }
        }
      }
    } catch (error) {
      // npm audit might fail if not in a proper npm project
      // Continue with other checks
    }

    return findings;
  }

  /**
   * Check for outdated packages
   */
  async checkOutdatedPackages(packages) {
    const findings = [];
    
    try {
      const outdatedOutput = execSync('npm outdated --json', {
        cwd: this.targetPath,
        stdio: ['pipe', 'pipe', 'ignore'],
        timeout: 30000
      }).toString();

      const outdatedData = JSON.parse(outdatedOutput);
      
      for (const [pkg, info] of Object.entries(outdatedData)) {
        const majorDiff = this.getMajorVersionDiff(info.current, info.latest);
        
        if (majorDiff > 0) {
          findings.push({
            id: `DEP-OUTDATED-${pkg}-${Date.now()}`,
            type: 'dependency-outdated',
            category: 'outdated-major-version',
            severity: majorDiff > 1 ? 'medium' : 'low',
            title: `Package ${pkg} is ${majorDiff} major versions behind`,
            file: 'package.json',
            line: null,
            packageName: pkg,
            currentVersion: info.current,
            latestVersion: info.latest,
            wantedVersion: info.wanted,
            remediation: `Update ${pkg} from ${info.current} to ${info.latest}. Run: npm install ${pkg}@latest`,
            owaspReference: 'A06:2021 – Vulnerable and Outdated Components',
            breakingChanges: majorDiff > 0
          });
        }
      }
    } catch (error) {
      // npm outdated might fail, continue
    }

    return findings;
  }

  /**
   * Check package maintenance status
   */
  async checkPackageMaintenance(packages) {
    const findings = [];
    
    // Check for commonly known unmaintained packages
    const unmaintainedPackages = {
      'request': 'Deprecated since 2020. Use node-fetch, axios, or got instead.',
      'left-pad': 'Unmaintained. Use String.prototype.padStart() instead.',
      'moment': 'In maintenance mode. Use date-fns, day.js, or Luxon instead.',
      'bower': 'Deprecated. Use npm, yarn, or pnpm instead.',
      'gulp-util': 'Deprecated. Use individual replacement packages.',
      'nodemon': 'Consider using tsx or ts-node-dev for TypeScript projects.'
    };

    for (const pkg of packages) {
      if (unmaintainedPackages[pkg]) {
        findings.push({
          id: `DEP-MAINT-${pkg}-${Date.now()}`,
          type: 'dependency-maintenance',
          category: 'unmaintained-package',
          severity: 'medium',
          title: `Package ${pkg} is no longer maintained`,
          file: 'package.json',
          line: null,
          packageName: pkg,
          remediation: unmaintainedPackages[pkg],
          owaspReference: 'A06:2021 – Vulnerable and Outdated Components'
        });
      }
    }

    return findings;
  }

  /**
   * Map npm audit severity to our severity levels
   */
  mapNpmSeverity(severity) {
    const severityMap = {
      'critical': 'critical',
      'high': 'high',
      'moderate': 'medium',
      'low': 'low',
      'info': 'low'
    };
    return severityMap[severity] || 'medium';
  }

  /**
   * Get major version difference
   */
  getMajorVersionDiff(current, latest) {
    const currentMajor = parseInt(current.split('.')[0]);
    const latestMajor = parseInt(latest.split('.')[0]);
    return latestMajor - currentMajor;
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

module.exports = DependencyScanner;
