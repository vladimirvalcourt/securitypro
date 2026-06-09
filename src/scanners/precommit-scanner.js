const fs = require('fs');
const path = require('path');
const { execSync } = require('child_process');
const SecretScanner = require('./secret-scanner');

/**
 * Pre-commit Hook Integration
 * Installs and manages git hooks for automatic security scanning before commits
 */
class PreCommitScanner {
  constructor(options = {}) {
    this.targetPath = options.targetPath || process.cwd();
    this.results = [];
  }

  /**
   * Install pre-commit hook
   */
  async installHook() {
    console.log('\n🔧 Installing SecurityPro pre-commit hook...\n');

    const gitDir = this.findGitDir();
    
    if (!gitDir) {
      return {
        success: false,
        message: 'No .git directory found. Initialize git first with: git init'
      };
    }

    const hooksDir = path.join(gitDir, 'hooks');
    const preCommitHook = path.join(hooksDir, 'pre-commit');

    // Create hooks directory if it doesn't exist
    if (!fs.existsSync(hooksDir)) {
      fs.mkdirSync(hooksDir, { recursive: true });
    }

    // Generate hook script
    const hookScript = this.generateHookScript();

    // Write hook file
    fs.writeFileSync(preCommitHook, hookScript, { mode: 0o755 });

    console.log('✅ Pre-commit hook installed successfully!');
    console.log('📍 Location:', preCommitHook);
    console.log('\nThe hook will now run automatically before each commit.');
    console.log('To bypass the hook in emergencies, use: git commit --no-verify\n');

    return {
      success: true,
      hookPath: preCommitHook,
      message: 'Pre-commit hook installed successfully'
    };
  }

  /**
   * Uninstall pre-commit hook
   */
  uninstallHook() {
    console.log('\n🔧 Removing SecurityPro pre-commit hook...\n');

    const gitDir = this.findGitDir();
    
    if (!gitDir) {
      return {
        success: false,
        message: 'No .git directory found'
      };
    }

    const preCommitHook = path.join(gitDir, 'hooks', 'pre-commit');

    if (fs.existsSync(preCommitHook)) {
      fs.unlinkSync(preCommitHook);
      console.log('✅ Pre-commit hook removed successfully!\n');
      return {
        success: true,
        message: 'Pre-commit hook removed'
      };
    } else {
      console.log('⚠️  No pre-commit hook found\n');
      return {
        success: false,
        message: 'No pre-commit hook found'
      };
    }
  }

  /**
   * Check if hook is installed
   */
  isHookInstalled() {
    const gitDir = this.findGitDir();
    if (!gitDir) return false;

    const preCommitHook = path.join(gitDir, 'hooks', 'pre-commit');
    if (!fs.existsSync(preCommitHook)) return false;

    const content = fs.readFileSync(preCommitHook, 'utf-8');
    return content.includes('securitypro') || content.includes('SecurityPro');
  }

  /**
   * Run scan on staged files only (for pre-commit hook)
   */
  async scanStagedFiles() {
    console.log('\n🔍 SecurityPro: Scanning staged files...\n');

    try {
      // Get list of staged files
      const stagedFiles = this.getStagedFiles();
      
      if (stagedFiles.length === 0) {
        console.log('✅ No staged files to scan\n');
        return { success: true, findings: [] };
      }

      console.log(`Scanning ${stagedFiles.length} staged file(s)...\n`);

      // Scan only staged files for secrets
      const secretScanner = new SecretScanner({ targetPath: this.targetPath });
      const allFindings = [];

      for (const file of stagedFiles) {
        const fullPath = path.join(this.targetPath, file);
        
        if (!fs.existsSync(fullPath)) continue;

        try {
          const content = fs.readFileSync(fullPath, 'utf-8');
          const findings = secretScanner.scanFile(fullPath, content);
          allFindings.push(...findings);
        } catch (error) {
          // Skip binary files
        }
      }

      if (allFindings.length === 0) {
        console.log('✅ No security issues found in staged files!\n');
        return { success: true, findings: [] };
      }

      // Display findings
      console.log('🚨 SECURITY ISSUES FOUND:\n');
      
      let criticalCount = 0;
      let highCount = 0;

      allFindings.forEach(finding => {
        const icon = finding.severity === 'critical' ? '🔴' : '🟠';
        console.log(`${icon} [${finding.severity.toUpperCase()}] ${finding.title}`);
        console.log(`   File: ${finding.file}:${finding.line}`);
        console.log(`   Fix: ${finding.remediation}\n`);
        
        if (finding.severity === 'critical') criticalCount++;
        if (finding.severity === 'high') highCount++;
      });

      console.log('─'.repeat(60));
      console.log(`Total: ${allFindings.length} issues (${criticalCount} critical, ${highCount} high)`);
      console.log('─'.repeat(60));

      if (criticalCount > 0 || highCount > 0) {
        console.log('\n❌ COMMIT BLOCKED: Fix critical/high severity issues before committing.');
        console.log('💡 To bypass (NOT RECOMMENDED): git commit --no-verify\n');
        
        return { 
          success: false, 
          findings: allFindings,
          blocked: true 
        };
      }

      console.log('\n⚠️  Warning: Issues found but commit allowed (medium/low severity).\n');
      return { success: true, findings: allFindings };

    } catch (error) {
      console.error('Error during pre-commit scan:', error.message);
      // Don't block commit if scanner fails
      return { success: true, findings: [], error: error.message };
    }
  }

  /**
   * Get list of staged files
   */
  getStagedFiles() {
    try {
      const output = execSync('git diff --cached --name-only --diff-filter=ACM', {
        cwd: this.targetPath,
        encoding: 'utf-8'
      });
      
      return output.split('\n').filter(Boolean);
    } catch (error) {
      return [];
    }
  }

  /**
   * Find .git directory
   */
  findGitDir() {
    let currentDir = this.targetPath;
    
    while (currentDir !== path.parse(currentDir).root) {
      const gitDir = path.join(currentDir, '.git');
      if (fs.existsSync(gitDir)) {
        return gitDir;
      }
      currentDir = path.dirname(currentDir);
    }
    
    return null;
  }

  /**
   * Generate pre-commit hook script
   */
  generateHookScript() {
    return `#!/bin/bash

# SecurityPro Pre-Commit Hook
# Automatically scans staged files for security issues before committing
# Generated by SecurityPro - https://github.com/vladimirvalcourt/securitypro

# Colors for output
RED='\\033[0;31m'
GREEN='\\033[0;32m'
YELLOW='\\033[1;33m'
NC='\\033[0m' # No Color

echo ""
echo -e "\${GREEN}🔒 SecurityPro Pre-Commit Scan\${NC}"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

# Get the directory where this hook is located
HOOK_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$HOOK_DIR/../.." && pwd)"

# Check if securitypro is available
if command -v securitypro &> /dev/null; then
    SECURITYPRO_CMD="securitypro"
elif [ -f "$REPO_ROOT/node_modules/.bin/securitypro" ]; then
    SECURITYPRO_CMD="$REPO_ROOT/node_modules/.bin/securitypro"
else
    echo -e "\${YELLOW}⚠️  SecurityPro not found. Installing globally...\${NC}"
    npm install -g securitypro 2>/dev/null
    SECURITYPRO_CMD="securitypro"
fi

# Run quick secret scan on staged files
echo ""
$SECURITYPRO_CMD quick --path "$REPO_ROOT"

EXIT_CODE=$?

if [ $EXIT_CODE -eq 0 ]; then
    echo -e "\${GREEN}✅ Pre-commit scan passed!\${NC}"
    echo ""
    exit 0
else
    echo -e "\${RED}❌ Pre-commit scan failed!\${NC}"
    echo -e "\${YELLOW}💡 Fix the issues above or use --no-verify to bypass (not recommended)\${NC}"
    echo ""
    exit 1
fi
`;
  }

  /**
   * Setup Husky integration (if project uses Husky)
   */
  async setupHusky() {
    console.log('\n🐕 Setting up Husky integration...\n');

    const packageJsonPath = path.join(this.targetPath, 'package.json');
    
    if (!fs.existsSync(packageJsonPath)) {
      return {
        success: false,
        message: 'No package.json found'
      };
    }

    try {
      // Check if husky is already installed
      const packageJson = JSON.parse(fs.readFileSync(packageJsonPath, 'utf-8'));
      const hasHusky = packageJson.devDependencies?.husky || packageJson.dependencies?.husky;

      if (!hasHusky) {
        console.log('Installing Husky...');
        execSync('npm install --save-dev husky', {
          cwd: this.targetPath,
          stdio: 'inherit'
        });
      }

      // Initialize husky
      execSync('npx husky init', {
        cwd: this.targetPath,
        stdio: 'inherit'
      });

      // Create pre-commit hook
      const huskyDir = path.join(this.targetPath, '.husky');
      const preCommitFile = path.join(huskyDir, 'pre-commit');
      
      const huskyHookContent = `#!/usr/bin/env sh
. "$(dirname -- "$0")/_/husky.sh"

npx securitypro quick --path .
`;

      fs.writeFileSync(preCommitFile, huskyHookContent, { mode: 0o755 });

      console.log('✅ Husky integration complete!\n');
      return {
        success: true,
        message: 'Husky integration complete'
      };
    } catch (error) {
      console.error('Error setting up Husky:', error.message);
      return {
        success: false,
        message: `Husky setup failed: ${error.message}`
      };
    }
  }

  /**
   * Run scan (main entry point)
   */
  async scan() {
    return await this.scanStagedFiles();
  }
}

module.exports = PreCommitScanner;
