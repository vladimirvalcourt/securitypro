const fs = require('fs');
const path = require('path');

/**
 * AI Prompt Security Analyzer
 * Scans AI prompt files, chat logs, and code comments for insecure prompting patterns
 * Specifically designed for vibe coders using AI coding assistants
 */
class PromptScanner {
  constructor(options = {}) {
    this.targetPath = options.targetPath || process.cwd();
    this.results = [];
  }

  /**
   * Run AI prompt security analysis
   */
  async scan() {
    console.log('\n🤖 Analyzing AI prompts for security issues...\n');

    // Scan various file types that might contain prompts
    const promptFiles = await this.findPromptFiles();

    for (const file of promptFiles) {
      try {
        const content = fs.readFileSync(file, 'utf-8');
        const findings = this.analyzePrompts(file, content);
        this.results.push(...findings);
      } catch (error) {
        // Skip unreadable files
      }
    }

    // Also scan code comments for insecure instructions
    const codeComments = await this.scanCodeCommentsForPrompts();
    this.results.push(...codeComments);

    return {
      totalFindings: this.results.length,
      findings: this.results,
      severity: this.calculateSeverity(),
      byCategory: this.getCategorySummary(),
      filesScanned: promptFiles.length
    };
  }

  /**
   * Find files that might contain AI prompts
   */
  async findPromptFiles() {
    const { glob } = require('glob');
    const files = [];

    // Common prompt file patterns
    const patterns = [
      '**/*.md',           // Markdown files often contain prompts
      '**/prompts/**/*',   // Dedicated prompt directories
      '**/.cursorrules',   // Cursor IDE rules
      '**/.clinerules',    // Cline rules
      '**/.windsurfrc',    // Windsurf config
      '**/CLAUDE.md',      // Claude Code instructions
      '**/AGENTS.md',      // Agent instructions
      '**/.github/copilot-instructions.md', // GitHub Copilot instructions
      '**/*.prompt',       // Explicit prompt files
      '**/PROMPT*',        // Prompt documentation
      '**/instructions*'   // AI instructions
    ];

    for (const pattern of patterns) {
      try {
        const found = await glob(pattern, {
          cwd: this.targetPath,
          nodir: true,
          ignore: ['node_modules/**', '.git/**', 'dist/**', 'build/**'],
          absolute: true,
          caseSensitiveMatch: false
        });
        files.push(...found);
      } catch (error) {
        // Continue with other patterns
      }
    }

    return [...new Set(files)];
  }

  /**
   * Analyze prompt content for security issues
   */
  analyzePrompts(filePath, content) {
    const findings = [];
    const relativePath = path.relative(this.targetPath, filePath);

    // Check for insecure prompting patterns
    const insecurePatterns = this.getInsecurePromptPatterns();

    for (const { pattern, title, category, severity, remediation, bestPractice } of insecurePatterns) {
      // Ensure pattern has the global flag to prevent infinite loops with exec()
      const globalPattern = new RegExp(pattern.source, pattern.flags.includes('g') ? pattern.flags : pattern.flags + 'g');
      
      let match;
      while ((match = globalPattern.exec(content)) !== null) {
        const lineNumber = content.substring(0, match.index).split('\n').length;
        
        findings.push({
          id: `PROMPT-${category.toUpperCase()}-${Date.now()}`,
          type: 'ai-prompt-security',
          category,
          severity,
          title,
          file: relativePath,
          line: lineNumber,
          matchedText: match[0].substring(0, 100),
          remediation,
          bestPractice,
          owaspReference: 'A04:2021 – Insecure Design'
        });
      }
    }

    // Check for missing security requirements in prompts
    const missingSecurityChecks = this.checkMissingSecurityGuidance(content, filePath);
    findings.push(...missingSecurityChecks);

    return findings;
  }

  /**
   * Get patterns that indicate insecure prompting
   */
  getInsecurePromptPatterns() {
    return [
      {
        pattern: /just make it work|make it work|quick and dirty|doesn't need to be perfect/i,
        title: 'Insecure "just make it work" mentality',
        category: 'insecure-mindset',
        severity: 'high',
        remediation: 'Always prioritize security over speed. Ask AI to implement secure patterns from the start.',
        bestPractice: 'Instead say: "Implement this with proper security, input validation, and error handling"'
      },
      {
        pattern: /skip.*validation|no need.*validate|don't.*check.*input|ignore.*errors/i,
        title: 'Skipping input validation or error handling',
        category: 'missing-validation',
        severity: 'critical',
        remediation: 'Never skip validation. Always validate user input on both client and server side.',
        bestPractice: 'Add: "Include Zod/Yup schema validation for all user inputs"'
      },
      {
        pattern: /hardcode.*key|hardcode.*secret|put.*key.*here|temporary.*password/i,
        title: 'Requesting hardcoded secrets or credentials',
        category: 'hardcoded-secrets',
        severity: 'critical',
        remediation: 'Never hardcode secrets. Use environment variables from the start.',
        bestPractice: 'Add: "Use environment variables for all API keys and secrets"'
      },
      {
        pattern: /no auth|skip auth|public.*endpoint|no.*authentication|anyone can access/i,
        title: 'Disabling authentication or authorization',
        category: 'missing-auth',
        severity: 'critical',
        remediation: 'All endpoints should require authentication unless explicitly public.',
        bestPractice: 'Add: "Protect this endpoint with JWT authentication middleware"'
      },
      {
        pattern: /disable.*cors|allow.*all origins|cors.*wildcard|\*.*origin/i,
        title: 'Overly permissive CORS configuration',
        category: 'cors-misconfiguration',
        severity: 'medium',
        remediation: 'Restrict CORS to specific trusted origins instead of allowing all.',
        bestPractice: 'Add: "Configure CORS with specific allowed origins, not wildcard"'
      },
      {
        pattern: /log.*password|console\.log.*token|print.*secret|expose.*credentials/i,
        title: 'Logging sensitive information',
        category: 'sensitive-data-leak',
        severity: 'high',
        remediation: 'Never log passwords, tokens, or secrets. Use structured logging with field filtering.',
        bestPractice: 'Add: "Log only non-sensitive data, filter out passwords and tokens"'
      },
      {
        pattern: /use eval|execute.*string|dynamic.*code|run.*user.*input/i,
        title: 'Using eval() or dynamic code execution',
        category: 'code-injection',
        severity: 'critical',
        remediation: 'Never use eval() or execute user-controlled strings as code.',
        bestPractice: 'Add: "Use safe alternatives to eval, such as JSON.parse() or function maps"'
      },
      {
        pattern: /sql.*\+.*concat|string.*interpolation.*query|\$\{.*\}.*sql/i,
        title: 'SQL query with string concatenation',
        category: 'sql-injection-risk',
        severity: 'critical',
        remediation: 'Always use parameterized queries or prepared statements.',
        bestPractice: 'Add: "Use parameterized queries to prevent SQL injection"'
      },
      {
        pattern: /innerHTML|dangerouslySetInnerHTML|document\.write/i,
        title: 'Unsafe DOM manipulation (XSS risk)',
        category: 'xss-risk',
        severity: 'high',
        remediation: 'Avoid innerHTML. Use textContent or sanitize HTML with DOMPurify.',
        bestPractice: 'Add: "Sanitize HTML with DOMPurify before rendering"'
      },
      {
        pattern: /no rate limit|unlimited requests|no throttling|skip.*rate.*limit/i,
        title: 'Disabling rate limiting',
        category: 'missing-rate-limit',
        severity: 'medium',
        remediation: 'Always implement rate limiting on API endpoints to prevent abuse.',
        bestPractice: 'Add: "Add rate limiting with express-rate-limit middleware"'
      },
      {
        pattern: /store.*credit.card|save.*password.*plain|keep.*ssn.*database/i,
        title: 'Storing sensitive data insecurely',
        category: 'data-storage-risk',
        severity: 'critical',
        remediation: 'Never store credit cards or passwords directly. Use payment processors and password hashing.',
        bestPractice: 'Add: "Use Stripe for payments and bcrypt for password hashing"'
      },
      {
        pattern: /catch.*err.*console|swallow.*error|ignore.*exception|empty catch/i,
        title: 'Swallowing errors without proper handling',
        category: 'error-handling',
        severity: 'medium',
        remediation: 'Always handle errors properly. Log them securely and return appropriate responses.',
        bestPractice: 'Add: "Handle errors with proper logging and user-friendly messages"'
      }
    ];
  }

  /**
   * Check for missing security guidance in prompts
   */
  checkMissingSecurityGuidance(content, filePath) {
    const findings = [];
    const relativePath = path.relative(this.targetPath, filePath);

    // If the file contains feature requests but no security mentions
    const hasFeatureRequest = /create|build|implement|add|make|develop/i.test(content);
    const hasSecurityMention = /security|auth|validation|sanitize|protect|secure/i.test(content);

    if (hasFeatureRequest && !hasSecurityMention && content.length > 100) {
      findings.push({
        id: `PROMPT-MISSING-SEC-${Date.now()}`,
        type: 'ai-prompt-security',
        category: 'missing-security-guidance',
        severity: 'medium',
        title: 'Feature request without security requirements',
        file: relativePath,
        line: 1,
        remediation: 'Add security requirements to your prompts. Specify authentication, validation, and error handling needs.',
        bestPractice: 'Example: "Build a user profile page with JWT auth, input validation, and proper error handling"',
        owaspReference: 'A04:2021 – Insecure Design'
      });
    }

    // Check for database operations without security
    const hasDatabaseOps = /database|query|insert|update|delete|find/i.test(content);
    const hasDatabaseSecurity = /parameterized|prepared|sanitize|orm|sequelize|prisma/i.test(content);

    if (hasDatabaseOps && !hasDatabaseSecurity && content.length > 50) {
      findings.push({
        id: `PROMPT-DB-SEC-${Date.now()}`,
        type: 'ai-prompt-security',
        category: 'missing-database-security',
        severity: 'high',
        title: 'Database operations without security specifications',
        file: relativePath,
        line: 1,
        remediation: 'Specify secure database patterns in your prompts.',
        bestPractice: 'Add: "Use parameterized queries and an ORM to prevent SQL injection"',
        owaspReference: 'A03:2021 – Injection'
      });
    }

    return findings;
  }

  /**
   * Scan code comments for AI prompt instructions
   */
  async scanCodeCommentsForPrompts() {
    const findings = [];
    const { glob } = require('glob');

    try {
      const files = await glob('**/*.{js,ts,jsx,tsx}', {
        cwd: this.targetPath,
        nodir: true,
        ignore: ['node_modules/**', '.git/**', 'dist/**', 'build/**'],
        absolute: true
      });

      for (const file of files) {
        try {
          const content = fs.readFileSync(file, 'utf-8');
          const relativePath = path.relative(this.targetPath, file);
          
          // Look for comments that look like AI prompts
          const commentPatterns = [
            /\/\/\s*(?:AI|GPT|Claude|Copilot|Cursor).*?:\s*(.*)/gi,
            /\/\*\s*(?:AI|GPT|Claude|Copilot|Cursor).*?:\s*([\s\S]*?)\*\//gi,
            /#\s*(?:AI|GPT|Claude|Copilot|Cursor).*?:\s*(.*)/gi
          ];

          for (const pattern of commentPatterns) {
            pattern.lastIndex = 0;
            let match;
            
            while ((match = pattern.exec(content)) !== null) {
              const promptText = match[1] || match[0];
              
              // Analyze the prompt text
              const insecurePatterns = this.getInsecurePromptPatterns();
              
              for (const { pattern: insecurePattern, title, category, severity, remediation, bestPractice } of insecurePatterns) {
                insecurePattern.lastIndex = 0;
                if (insecurePattern.test(promptText)) {
                  const lineNumber = content.substring(0, match.index).split('\n').length;
                  
                  findings.push({
                    id: `PROMPT-COMMENT-${category.toUpperCase()}-${Date.now()}`,
                    type: 'ai-prompt-security',
                    category,
                    severity,
                    title: `Comment contains insecure prompt: ${title}`,
                    file: relativePath,
                    line: lineNumber,
                    matchedText: promptText.substring(0, 100),
                    remediation,
                    bestPractice,
                    owaspReference: 'A04:2021 – Insecure Design'
                  });
                }
              }
            }
          }
        } catch (error) {
          // Skip unreadable files
        }
      }
    } catch (error) {
      // Continue if glob fails
    }

    return findings;
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

module.exports = PromptScanner;
