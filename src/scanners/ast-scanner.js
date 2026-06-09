const fs = require('fs');
const path = require('path');
const { glob } = require('glob');
const parser = require('@babel/parser');
const traverse = require('@babel/traverse').default;

/**
 * AST Scanner
 * Deep static analysis of JavaScript/TypeScript files using Abstract Syntax Trees
 * Detects complex business logic flaws like missing authorization checks
 */
class ASTScanner {
  constructor(options = {}) {
    this.targetPath = options.targetPath || process.cwd();
    this.results = [];
  }

  async scan() {
    const files = await glob('**/*.{js,ts,jsx,tsx}', {
      cwd: this.targetPath,
      nodir: true,
      ignore: ['node_modules/**', '.git/**', 'dist/**', 'build/**'],
      absolute: true
    });

    for (const file of files) {
      this.scanFile(file);
    }

    return {
      totalFindings: this.results.length,
      findings: this.results,
      severity: this.calculateSeverity()
    };
  }

  scanFile(filePath) {
    const relativePath = path.relative(this.targetPath, filePath);
    
    // We skip scanning our own scanners to avoid self-flagging, 
    // unless the target path specifically targets them.
    if (relativePath.includes('src/scanners/') || relativePath.includes('src/autofix/')) {
      return;
    }

    try {
      const code = fs.readFileSync(filePath, 'utf-8');
      
      const ast = parser.parse(code, {
        sourceType: 'module',
        plugins: ['typescript', 'jsx'],
        errorRecovery: true
      });

      traverse(ast, {
        // Detect Express/Fastify route definitions
        CallExpression: (path) => {
          const callee = path.node.callee;
          
          // Look for app.post(), router.put(), etc.
          if (callee.type === 'MemberExpression') {
            const propName = callee.property.name;
            if (['post', 'put', 'patch', 'delete'].includes(propName)) {
              
              const args = path.node.arguments;
              if (args.length >= 2) {
                // Determine if there are middleware arguments before the handler
                // Usually `router.post('/path', authMiddleware, handler)`
                // If there's only 2 args, it's just `router.post('/path', handler)`
                // which might mean no auth middleware.
                if (args.length === 2 && (args[1].type === 'ArrowFunctionExpression' || args[1].type === 'FunctionExpression' || args[1].type === 'Identifier')) {
                  
                  // Now let's check inside the handler (if it's inline) to see if it does DB writes
                  // without checking req.user or similar
                  if (args[1].type === 'ArrowFunctionExpression' || args[1].type === 'FunctionExpression') {
                    let writesToDb = false;
                    let checksAuth = false;

                    // Traverse inside the route handler
                    path.traverse({
                      CallExpression: (innerPath) => {
                        const innerCallee = innerPath.node.callee;
                        if (innerCallee.type === 'MemberExpression') {
                          const innerProp = innerCallee.property.name;
                          if (['update', 'save', 'insert', 'delete', 'destroy'].includes(innerProp)) {
                            writesToDb = true;
                          }
                        }
                      },
                      MemberExpression: (innerPath) => {
                        if (innerPath.node.object.name === 'req' && innerPath.node.property.name === 'user') {
                          checksAuth = true;
                        }
                      }
                    });

                    if (writesToDb && !checksAuth) {
                      this.results.push({
                        id: `AST-AUTH-BYPASS-${Date.now()}-${Math.random().toString(36).substr(2, 5)}`,
                        type: 'business-logic',
                        category: 'authorization',
                        severity: 'critical',
                        title: 'Database modification endpoint missing authorization checks',
                        file: relativePath,
                        line: path.node.loc?.start?.line || 1,
                        remediation: 'Ensure you add authorization middleware to the route, or explicitly check `req.user` inside the handler before modifying data.',
                        bestPractice: 'Use a robust middleware stack (e.g., `requireAuth`) for all state-changing endpoints.'
                      });
                    }
                  }
                }
              }
            }
          }
        }
      });
    } catch (error) {
      // Babel parse errors, mostly syntax issues, we ignore them
    }
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

module.exports = ASTScanner;
