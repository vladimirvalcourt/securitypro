const fs = require('fs');
const path = require('path');
const https = require('https');

/**
 * Typosquatting & Hallucination Scanner
 * Checks package.json dependencies against the npm registry
 * to detect malicious typosquatting or AI-hallucinated packages.
 */
class TyposquatScanner {
  constructor(options = {}) {
    this.targetPath = options.targetPath || process.cwd();
    this.results = [];
  }

  async scan() {
    const packageJsonPath = path.join(this.targetPath, 'package.json');
    if (!fs.existsSync(packageJsonPath)) {
      return { totalFindings: 0, findings: [] };
    }

    try {
      const pkg = JSON.parse(fs.readFileSync(packageJsonPath, 'utf-8'));
      const dependencies = {
        ...(pkg.dependencies || {}),
        ...(pkg.devDependencies || {})
      };

      const packagesToCheck = Object.keys(dependencies);
      
      // Check each package sequentially to avoid rate-limiting from npm registry
      for (const packageName of packagesToCheck) {
        await this.checkPackage(packageName);
      }

      return {
        totalFindings: this.results.length,
        findings: this.results,
        severity: this.calculateSeverity()
      };
    } catch (error) {
      console.error('Error scanning for typosquatting:', error.message);
      return { totalFindings: 0, findings: [] };
    }
  }

  checkPackage(packageName) {
    return new Promise((resolve) => {
      // Don't check local or git dependencies
      if (packageName.startsWith('file:') || packageName.startsWith('git+') || packageName.startsWith('github:')) {
        return resolve();
      }

      const encodedPackageName = packageName.replace('/', '%2f');
      const url = `https://registry.npmjs.org/${encodedPackageName}`;

      https.get(url, (res) => {
        if (res.statusCode === 404) {
          // Package doesn't exist -> Likely AI hallucination
          this.results.push({
            id: `HALLUCINATION-${Date.now()}`,
            type: 'dependency-hallucination',
            category: 'supply-chain',
            severity: 'high',
            title: `Dependency does not exist in npm registry: ${packageName}`,
            file: 'package.json',
            packageName,
            remediation: `Remove "${packageName}" or find the correct package name. AI often hallucinates package names.`,
            bestPractice: 'Always verify a package exists on npmjs.com before installing it.'
          });
          return resolve();
        }

        if (res.statusCode !== 200) {
          // Other error, just skip
          return resolve();
        }

        let data = '';
        res.on('data', (chunk) => data += chunk);
        res.on('end', () => {
          try {
            const pkgData = JSON.parse(data);
            const createdDate = new Date(pkgData.time?.created);
            const now = new Date();
            const ageInDays = (now - createdDate) / (1000 * 60 * 60 * 24);

            // Flag packages created within the last 7 days
            if (ageInDays < 7) {
              this.results.push({
                id: `NEW-PACKAGE-${Date.now()}`,
                type: 'dependency-typosquat',
                category: 'supply-chain',
                severity: 'critical',
                title: `Extremely new dependency detected: ${packageName} (Created ${Math.round(ageInDays)} days ago)`,
                file: 'package.json',
                packageName,
                remediation: `Verify this is exactly the package you intended to install. Malicious typosquatted packages are often brand new.`,
                bestPractice: 'Avoid using extremely new packages in production unless strictly necessary and verified.'
              });
            }
          } catch (e) {}
          resolve();
        });
      }).on('error', () => resolve());
    });
  }

  calculateSeverity() {
    if (this.results.length === 0) return 'none';
    const hasCritical = this.results.some(f => f.severity === 'critical');
    const hasHigh = this.results.some(f => f.severity === 'high');
    if (hasCritical) return 'critical';
    if (hasHigh) return 'high';
    return 'medium';
  }
}

module.exports = TyposquatScanner;
