const fs = require('fs');
const path = require('path');
const chalk = require('chalk');
const LLMHealer = require('../healing/llm-healer');

/**
 * Auto-Fix Engine
 * Parses findings and applies safe automatic fixes directly to code
 */
class FixEngine {
  constructor(options = {}) {
    this.targetPath = options.targetPath || process.cwd();
    this.fixedFiles = new Set();
    this.fixesApplied = 0;
    this.llmHealer = new LLMHealer();
  }

  /**
   * Process all findings and apply safe fixes
   * @param {Object} results - Scan results object
   * @returns {number} Number of fixes applied
   */
  async applyFixes(results) {
    console.log(chalk.cyan('\n🔧 Running Auto-Fix Engine...'));
    
    const allFindings = [
      ...(results.secretScan?.findings || []),
      ...(results.owaspScan?.findings || []),
      ...(results.authScan?.findings || []),
      ...(results.dbScan?.findings || []),
      ...(results.apiScan?.findings || []),
      ...(results.promptScan?.findings || [])
    ];

    // We process fixes grouped by file to avoid multiple read/writes over writing each other
    const findingsByFile = {};
    for (const finding of allFindings) {
      if (!finding.file || !finding.line) continue;
      if (!findingsByFile[finding.file]) {
        findingsByFile[finding.file] = [];
      }
      findingsByFile[finding.file].push(finding);
    }

    for (const [file, findings] of Object.entries(findingsByFile)) {
      await this.fixFile(file, findings);
    }

    if (this.fixesApplied > 0) {
      console.log(chalk.green(`\n✅ Successfully applied ${this.fixesApplied} automatic fixes to ${this.fixedFiles.size} file(s)!`));
    } else {
      console.log(chalk.dim('\nNo safe automatic fixes could be applied to the current findings.'));
    }

    return this.fixesApplied;
  }

  async fixFile(relativeFilePath, findings) {
    const fullPath = path.resolve(this.targetPath, relativeFilePath);
    if (!fs.existsSync(fullPath)) return;

    let content = fs.readFileSync(fullPath, 'utf-8');
    let contentLines = content.split('\n');
    let modified = false;

    // Process from bottom to top so line numbers remain stable for previous lines
    const sortedFindings = findings.sort((a, b) => b.line - a.line);

    for (const finding of sortedFindings) {
      const lineIndex = finding.line - 1;
      if (lineIndex < 0 || lineIndex >= contentLines.length) continue;

      const originalLine = contentLines[lineIndex];
      let fixedLine = originalLine;

      // Rule: Hardcoded secrets (Move to process.env)
      if (finding.type === 'hardcoded-secret' || finding.category === 'secrets') {
        if (finding.suggestedEnvVar && originalLine.includes('=')) {
          // Simplistic replace for const apiKey = "abc"; -> const apiKey = process.env.API_KEY;
          fixedLine = originalLine.replace(/['"`][^'"`]+['"`]/, `process.env.${finding.suggestedEnvVar}`);
        }
      }
      
      // Rule: DOMPurify (innerHTML to textContent for simple cases)
      if (finding.category === 'xss-risk' && originalLine.includes('innerHTML')) {
        fixedLine = originalLine.replace('innerHTML', 'textContent');
      }
      
      // Rule: SQL Injection (Basic concat to parameterized string) - this is just a placeholder for more advanced AST logic
      // e.g. "SELECT * FROM users WHERE id = " + id
      if (finding.category === 'sql-injection' && originalLine.includes('concat')) {
        // Simple string concat replace (demo purposes)
        // A full AST parser will be added in Phase 3
      }

      // LLM Healing fallback for complex or high/critical issues that regex can't fix
      if (fixedLine === originalLine && (finding.severity === 'critical' || finding.severity === 'high')) {
        if (this.llmHealer.isAvailable()) {
          // Provide a tiny context window for the LLM
          const contextStart = Math.max(0, lineIndex - 5);
          const contextEnd = Math.min(contentLines.length - 1, lineIndex + 5);
          const snippet = contentLines.slice(contextStart, contextEnd + 1).join('\n');
          
          const healedCode = await this.llmHealer.heal(finding, snippet);
          if (healedCode) {
            // Because LLMs might rewrite multiple lines, we just replace the exact line for safety, 
            // or if it returns multiple lines, we insert them. For now, replace single line.
            // In a robust implementation, AST replacement is safer.
            const lines = healedCode.split('\n');
            if (lines.length === 1) {
              fixedLine = healedCode;
            }
          }
        }
      }

      if (fixedLine !== originalLine) {
        contentLines[lineIndex] = fixedLine + ' // 🔒 Fixed by SecurityPro';
        modified = true;
        this.fixesApplied++;
        console.log(chalk.dim(`   Fixed ${finding.category} in ${relativeFilePath}:${finding.line}`));
      }
    }

    if (modified) {
      fs.writeFileSync(fullPath, contentLines.join('\n'));
      this.fixedFiles.add(relativeFilePath);
    }
  }
}

module.exports = FixEngine;
