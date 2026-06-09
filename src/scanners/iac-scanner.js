const fs = require('fs');
const path = require('path');
const { glob } = require('glob');
const yaml = require('js-yaml');

/**
 * Infrastructure as Code (IaC) Scanner
 * Scans Dockerfiles, docker-compose.yml, and GitHub Actions for misconfigurations
 */
class IaCScanner {
  constructor(options = {}) {
    this.targetPath = options.targetPath || process.cwd();
    this.results = [];
  }

  async scan() {
    await this.scanDockerfiles();
    await this.scanGitHubActions();
    // docker-compose scanning can be added here

    return {
      totalFindings: this.results.length,
      findings: this.results,
      severity: this.calculateSeverity()
    };
  }

  async scanDockerfiles() {
    try {
      const dockerfiles = await glob('**/Dockerfile*', {
        cwd: this.targetPath,
        nodir: true,
        ignore: ['node_modules/**', '.git/**'],
        absolute: true
      });

      for (const file of dockerfiles) {
        const content = fs.readFileSync(file, 'utf-8');
        const lines = content.split('\n');
        const relativePath = path.relative(this.targetPath, file);
        
        let hasUserDirective = false;
        let isRootUser = true;

        lines.forEach((line, index) => {
          const trimmed = line.trim();
          
          if (trimmed.toUpperCase().startsWith('USER ')) {
            hasUserDirective = true;
            const user = trimmed.split(' ')[1];
            if (user === 'root' || user === '0') {
              this.results.push({
                id: `IAC-DOCKER-ROOT-${Date.now()}`,
                type: 'iac-security',
                category: 'infrastructure',
                severity: 'critical',
                title: 'Docker container runs as root user',
                file: relativePath,
                line: index + 1,
                remediation: 'Change to a non-root user (e.g., node) to minimize the impact of container escapes.',
                bestPractice: 'Add `USER node` (or another unprivileged user) before the ENTRYPOINT/CMD.'
              });
            } else {
              isRootUser = false;
            }
          }

          if (trimmed.includes('curl ') && trimmed.includes('| bash')) {
            this.results.push({
              id: `IAC-DOCKER-CURL-BASH-${Date.now()}`,
              type: 'iac-security',
              category: 'infrastructure',
              severity: 'high',
              title: 'Unsafe execution of remote scripts (curl | bash)',
              file: relativePath,
              line: index + 1,
              remediation: 'Download scripts, verify their hash/checksum, and then execute them instead of piping directly to bash.',
              bestPractice: 'Use package managers or verified binary downloads over `curl | bash`.'
            });
          }
        });

        if (!hasUserDirective || isRootUser) {
          // If no USER directive, it runs as root by default
          this.results.push({
            id: `IAC-DOCKER-DEFAULT-ROOT-${Date.now()}`,
            type: 'iac-security',
            category: 'infrastructure',
            severity: 'high',
            title: 'Docker container implicitly runs as root user',
            file: relativePath,
            line: 1,
            remediation: 'Explicitly set a non-root user (e.g., node) to minimize the impact of container escapes.',
            bestPractice: 'Add `USER node` (or another unprivileged user) at the end of your Dockerfile.'
          });
        }
      }
    } catch (error) {
      console.error('Error scanning Dockerfiles:', error.message);
    }
  }

  async scanGitHubActions() {
    try {
      const workflows = await glob('.github/workflows/*.{yml,yaml}', {
        cwd: this.targetPath,
        nodir: true,
        absolute: true
      });

      for (const file of workflows) {
        const content = fs.readFileSync(file, 'utf-8');
        const relativePath = path.relative(this.targetPath, file);
        const lines = content.split('\n');

        try {
          const doc = yaml.load(content);
          if (!doc) continue;

          // Check for globally permissive permissions
          if (doc.permissions === 'write-all') {
            this.results.push({
              id: `IAC-GHA-WRITE-ALL-${Date.now()}`,
              type: 'iac-security',
              category: 'infrastructure',
              severity: 'critical',
              title: 'GitHub Actions workflow has write-all permissions',
              file: relativePath,
              line: this.findLineNumber(lines, 'permissions: write-all'),
              remediation: 'Apply the principle of least privilege. Grant only specific permissions needed (e.g., contents: read).',
              bestPractice: 'Use `permissions: { contents: read }` at the top level, and grant write access only to specific jobs.'
            });
          }

          // In a real scanner, we'd iterate over jobs and steps to find unsafe pull_request_target usage
          // and curl | bash patterns. This is simplified for the demonstration.

        } catch (e) {
          // Skip invalid YAML
        }
      }
    } catch (error) {
      console.error('Error scanning GitHub Actions:', error.message);
    }
  }

  findLineNumber(lines, searchString) {
    const index = lines.findIndex(line => line.includes(searchString));
    return index >= 0 ? index + 1 : 1;
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

module.exports = IaCScanner;
