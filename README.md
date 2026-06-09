# 🔒 SecurityPro v2.0

**The ultimate security audit tool built specifically for vibe coders and AI-assisted developers.**

SecurityPro automatically scans your code for 15+ types of security issues - from hardcoded secrets to insecure AI prompts. It runs in watch mode while you code, catches issues before you commit, and provides copy-paste fixes. Think of it as your personal security expert that never sleeps.

## 🎯 What Does It Do?

SecurityPro protects your projects by detecting:

### 🔑 **Hardcoded Secrets & API Keys**
- AWS credentials, Stripe keys, database passwords
- GitHub tokens, JWT secrets, OAuth credentials
- Any sensitive data accidentally left in code
- **200+ pattern detection** with minimal false positives

### 📦 **Dependency Vulnerabilities** (NEW!)
- Known CVEs in npm packages
- Outdated dependencies with security issues
- Unmaintained packages (like `moment`, `request`)
- Automatic upgrade recommendations

### 🔐 **Environment Variable Issues** (NEW!)
- Hardcoded values that should be in `.env`
- Missing `.env.example` templates
- `.env` files not in `.gitignore`
- Auto-generates secure `.env` templates

### 🤖 **AI Prompt Security** (UNIQUE!)
- Detects insecure prompting patterns ("just make it work")
- Flags prompts that skip validation or auth
- Scans `.cursorrules`, `CLAUDE.md`, and prompt files
- Teaches security-first prompting for vibe coders

### 🛡️ **OWASP Top 10 Vulnerabilities**
- SQL injection attacks (hackers stealing your data)
- XSS attacks (hackers injecting malicious scripts)
- Broken authentication (unauthorized access)
- Insecure direct object references (IDOR)

### 💾 **Database Security**
- Unencrypted sensitive data (SSN, credit cards)
- Missing access controls
- Unsafe queries that can be exploited
- Connection string exposure

### 🌐 **API & HTTP Security** (NEW!)
- Missing security headers (CSP, HSTS, X-Frame-Options)
- CORS misconfigurations
- Rate limiting gaps
- Webhook signature verification

### 📤 **File Upload Security** (NEW!)
- Unrestricted file types (uploading .exe files!)
- Missing size limits (DoS via large uploads)
- Path traversal vulnerabilities
- Public storage without access control

### 🔗 **Webhook Security** (NEW!)
- Missing signature verification (Stripe, etc.)
- Replay attack vulnerabilities
- Synchronous processing issues
- Idempotency gaps

### ⏱️ **Rate Limiting & DDoS Protection** (NEW!)
- Auth endpoints without brute force protection
- Unbounded queries (resource exhaustion)
- Missing rate limit middleware
- Expensive operations unprotected

### 🔐 **Authentication Problems**
- Weak password hashing (MD5, SHA1)
- JWT without expiration
- Missing session regeneration
- Insecure cookie flags

### 🌐 **API Security Gaps**
- Missing input validation
- Exposed internal errors
- No pagination limits
- Verbose error messages

## ✨ Why Use SecurityPro?

**For Vibe Coders:**
- Catches insecure AI-generated code patterns
- Validates prompts before you use them
- Prevents "just make it work" mentality
- Teaches security best practices automatically

**For Beginners:**
- Catches security mistakes before hackers find them
- Explains issues in plain English with simple fixes
- No security expertise needed

**For Teams:**
- Pre-commit hooks block insecure code
- Automated security checks on every save
- Prevents secrets from being committed to Git
- Ensures consistent security standards

**For Everyone:**
- Runs silently in the background
- Instant feedback when you make a mistake
- Saves hours of debugging security issues later
- **10 specialized scanners** covering all attack vectors

## 🚀 Quick Start

### Installation (30 seconds)

```bash
# Install globally (one-time)
npm install -g securitypro

# That's it! You're ready to go.
```

### Usage

#### Option 1: Manual Scan (Quick Check)
```bash
# Scan your current project
securitypro scan

# Scan a specific folder
securitypro scan --path ./my-project

# Quick check for secrets only
securitypro quick
```

#### Option 2: Auto-Watch Mode (Recommended!) ⭐
```bash
# Watch your project and scan automatically when files change
securitypro watch

# Watch with custom interval (check every 5 seconds)
securitypro watch --interval 5

# Watch specific folder
securitypro watch --path ./src
```

**What happens in watch mode:**
1. SecurityPro monitors your files
2. When you save a file, it automatically scans it
3. If it finds issues, it shows you exactly what's wrong
4. It tells you how to fix it
5. All this happens instantly while you work!

#### Option 3: See All Threats (Learn Security)
```bash
# Display comprehensive threat guide
securitypro threats
```

## 📖 Real Examples

### Example 1: Catching Hardcoded Secrets

**❌ Bad Code (SecurityPro catches this):**
```javascript
const apiKey = "sk_live_abc123def456"; // Your Stripe key
const dbPassword = "super_secret_123";
```

**✅ What SecurityPro Shows:**
```
🔴 CRITICAL: Hardcoded Secret Detected
File: config.js:5
Issue: Stripe secret key found in code
Fix: Move to .env file → process.env.STRIPE_KEY
```

**✅ Fixed Code:**
```javascript
const apiKey = process.env.STRIPE_KEY; // Safe!
const dbPassword = process.env.DB_PASSWORD;
```

### Example 2: Preventing SQL Injection

**❌ Bad Code:**
```javascript
db.query(`SELECT * FROM users WHERE id = ${userId}`);
```

**✅ What SecurityPro Shows:**
```
🔴 CRITICAL: SQL Injection Vulnerability
File: routes/users.js:12
Issue: User input directly in SQL query
Fix: Use parameterized query → db.query("SELECT...WHERE id = $1", [userId])
```

**✅ Fixed Code:**
```javascript
db.query('SELECT * FROM users WHERE id = $1', [userId]);
```

### Example 3: Fixing XSS Vulnerability

**❌ Bad Code:**
```javascript
element.innerHTML = userInput; // Dangerous!
```

**✅ What SecurityPro Shows:**
```
🟠 HIGH: XSS Vulnerability
File: components/Profile.jsx:25
Issue: Unsanitized user input rendered as HTML
Fix: Use textContent or sanitize with DOMPurify
```

**✅ Fixed Code:**
```javascript
element.textContent = userInput; // Safe!
```

## 🆕 What's New in v2.0?

SecurityPro v2.0 brings **Enterprise-Grade Automation, Reporting, and AI capabilities**, along with 10 powerful new scanners specifically designed for vibe coders!

### 🌟 1. Multi-LLM Support & Offline AI 🧠
SecurityPro is no longer locked to OpenAI! The Auto-Healing engine now supports multiple LLM providers seamlessly. Run completely offline for maximum privacy.
- **Supported:** OpenAI, Anthropic Claude, Google Gemini, and **Ollama** (Local/Offline).
- *Set your API key or start Ollama to enable!*

### 🌟 2. AI-Powered Explanations (`--explain`) 🤖
Don't just fix it—understand it. Pass the `--explain` flag, and SecurityPro will query your configured AI to explain *why* a vulnerability is dangerous and *how* the fix works conceptually in plain, simple English right in your terminal.

### 🌟 3. Rich Reporting Engine (`--format`) 📊
Generate professional reports for stakeholders or CI/CD pipelines.
- **HTML Dashboards**: Beautiful, standalone visual reports of your Vibe Score and findings (`--format html`).
- **JSON Output**: Perfect for hooking into CI pipelines and programmatic parsing (`--format json`).

### 🌟 4. Continuous Security Automation ⚙️
Set up automated protection that works exactly when you interact with GitHub using the new `integrate` command.
- **Local Pre-Push Protection**: `securitypro integrate --pre-push` blocks hardcoded secrets *before* they ever leave your laptop.
- **GitHub Actions CI/CD**: `securitypro integrate --github-actions` automatically monitors your repository, running full scans on every push and attaching HTML dashboards as artifacts.

### 5. 🔍 Dependency Vulnerability Scanner
Scans your `package.json` for known CVEs, outdated packages, and unmaintained dependencies. Catches supply chain attacks before they hit production.

```bash
securitypro deps
```

### 2. 🔐 Environment Variable Validator
Ensures secrets aren't hardcoded, validates `.env` setup, and auto-generates templates. Prevents the #1 cause of security breaches.

```bash
securitypro env-check
```

### 3. 🛡️ Pre-commit Hook Integration
Installs git hooks that block commits containing secrets or vulnerabilities. Stops security issues at the source!

```bash
securitypro precommit --install
```

### 4. 🤖 AI Prompt Security Analyzer (UNIQUE!)
The **only tool** that scans AI prompts for insecure patterns. Detects "just make it work" mentality, missing validation requests, and unsafe prompting practices.

```bash
securitypro prompts
```

### 5. 🌐 HTTP Headers & CORS Auditor
Validates security headers (CSP, HSTS, X-Frame-Options) and CORS configuration. Prevents XSS and clickjacking attacks.

```bash
securitypro scan  # Includes headers check
```

### 6. 📤 File Upload Security Scanner
Checks for unrestricted uploads, missing size limits, path traversal risks, and malware scanning gaps.

```bash
securitypro scan  # Includes upload check
```

### 7. 🔗 Webhook Security Validator
Verifies webhook signatures (Stripe, etc.), checks replay protection, and ensures idempotency. Critical for payment integrations!

```bash
securitypro scan  # Includes webhook check
```

### 8. ⏱️ Rate Limiting & DDoS Protection Checker
Validates rate limiting on all endpoints, especially auth routes. Prevents brute force attacks and resource exhaustion.

```bash
securitypro scan  # Includes rate limit check
```

### 9. ⚙️ Security Configuration Generator
Auto-generates production-ready configs for helmet, CORS, rate limiting, ESLint security rules, and `.env.example`.

```bash
securitypro generate-configs
```

### 10. 📊 Enhanced Comprehensive Scan
The `scan` command now runs all 10+ scanners in one go, providing a complete security audit in seconds.

```bash
securitypro scan  # Runs everything!
```

---

## 🎮 How Watch Mode Works

```
You Code → Save File → SecurityPro Scans → Instant Feedback
   ↑                                              ↓
   └──────────────── Fix Issues ←───────────────┘
```

**Behind the scenes:**
1. You write code normally
2. You save a file (Cmd+S / Ctrl+S)
3. SecurityPro detects the change
4. It scans only the changed files (fast!)
5. Shows issues in your terminal immediately
6. You fix them right away
7. Cycle repeats - continuous protection!

**Benefits:**
- ✅ Catch issues immediately, not days later
- ✅ Learn security best practices as you code
- ✅ Never commit vulnerable code by accident
- ✅ Build secure habits naturally

## 📋 Commands Reference

| Command | What It Does | When to Use |
|---------|--------------|-------------|
| `securitypro scan` | Full security audit (all 10+ scanners) | Before committing code |
| `securitypro quick` | Fast secret check | Quick verification |
| `securitypro watch` | Auto-scan on file changes | While coding (recommended!) |
| `securitypro deps` | Scan dependencies for CVEs | After npm install |
| `securitypro env-check` | Validate .env configuration | Project setup |
| `securitypro prompts` | Analyze AI prompts | After writing prompts |
| `securitypro precommit` | Manage git hooks | One-time setup |
| `securitypro generate-configs` | Create secure configs | Project initialization |
| `securitypro threats` | Show all security threats | Learning & education |
| `securitypro check-config` | Verify setup files | Project initialization |

### Full Scan Options

```bash
# Run all scanners (default)
securitypro scan

# Skip certain checks (faster)
securitypro scan --no-owasp --no-auth --no-deps

# Ignore specific folders
securitypro scan --ignore "test/**,node_modules/**"

# Verbose output (see everything)
securitypro scan --verbose

# Save report to file
securitypro scan --output report.json

# Scan specific path
securitypro scan --path ./my-project
```

### Watch Mode

```bash
# Start watching (scans on file save)
securitypro watch

# Custom scan interval (seconds)
securitypro watch --interval 10

# Watch specific path
securitypro watch --path ./src

# Quiet mode (only show critical issues)
securitypro watch --quiet
```

### Pre-commit Hook Management

```bash
# Install pre-commit hook (blocks insecure commits)
securitypro precommit --install

# Setup with Husky (for projects using Husky)
securitypro precommit --husky

# Check if hook is installed
securitypro precommit --check

# Remove hook
securitypro precommit --uninstall

# Manual scan of staged files
securitypro precommit
```

### Dependency Scanner

```bash
# Check for vulnerable packages
securitypro deps

# Scan specific project
securitypro deps --path ./my-app
```

### Environment Variable Validator

```bash
# Validate .env setup
securitypro env-check

# Auto-generates .env.example if missing
securitypro env-check --path ./project
```

### AI Prompt Analyzer

```bash
# Scan prompt files for insecure patterns
securitypro prompts

# Check specific directory
securitypro prompts --path ./prompts
```

### Configuration Generator

```bash
# Generate all security configs (helmet, CORS, rate limits, etc.)
securitypro generate-configs
```

## 🔧 Configuration

### .securityprorc (Optional)

Create this file in your project root to customize:

```json
{
  "watch": {
    "enabled": true,
    "interval": 5,
    "paths": ["src/", "api/"],
    "ignore": ["test/", "*.spec.js"]
  },
  "scanners": {
    "secrets": true,
    "owasp": true,
    "auth": true,
    "database": true,
    "api": true
  },
  "notifications": {
    "critical": true,
    "high": true,
    "medium": false,
    "low": false
  }
}
```

### .gitignore (Required!)

Make sure these are in your `.gitignore`:

```gitignore
# SecurityPro
.securitypro-cache/
securitypro-report.json

# Secrets (NEVER commit these!)
.env
.env.local
*.pem
*.key
```

## 🎓 Learning Security

Run `securitypro threats` to see:
- 10 most common security threats
- How attackers exploit them
- Step-by-step prevention guides
- Real-world examples
- Security tool recommendations

**Perfect for:**
- Students learning web development
- Bootcamp graduates
- Self-taught developers
- Anyone wanting to write secure code

## 🤖 CI/CD Integration

Instead of setting up CI/CD manually, SecurityPro can generate the workflow for you!

```bash
# Automatically generate a GitHub Actions workflow that runs on every push
securitypro integrate --github-actions
```

This generates a `.github/workflows/securitypro.yml` file that runs a full security scan on every push and PR, and uploads a beautiful HTML dashboard artifact to the GitHub Action run.

If you prefer to configure it manually:

```yaml
name: Security Check
on: [push, pull_request]

jobs:
  security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Install SecurityPro
        run: npm install -g securitypro
      - name: Run Security Scan
        run: securitypro scan --format html --output securitypro-report.html
      - name: Upload Report
        uses: actions/upload-artifact@v4
        with:
          name: SecurityPro-Dashboard
          path: securitypro-report.html
```

## ❓ FAQ

### Q: Will it slow down my computer?
**A:** No! Watch mode only scans when you save files, and it's very fast (usually <1 second).

### Q: Does it upload my code anywhere?
**A:** Absolutely not! Everything runs locally on your machine. Your code never leaves your computer.

### Q: Can I use it with any framework?
**A:** Yes! Works with React, Vue, Angular, Node.js, Python, Ruby, PHP, Go - any language!

### Q: Is it free?
**A:** Yes! Completely free and open-source (MIT license).

### Q: How is this different from other tools?
**A:** SecurityPro is designed for developers who want security without complexity. It explains issues in plain English and gives you exact copy-paste fixes.

### Q: Can I disable certain checks?
**A:** Yes! Use flags like `--no-owasp` or configure in `.securityprorc`.

### Q: Will it fix issues automatically?
**A:** Not yet - it tells you what's wrong and how to fix it. This helps you learn and understand security better.

## 🆘 Troubleshooting

### "Command not found" after installation
```bash
# Try adding npm global bin to PATH
export PATH=$(npm bin -g):$PATH

# Or reinstall
npm uninstall -g securitypro
npm install -g securitypro
```

### Watch mode not detecting changes
```bash
# Increase scan interval
securitypro watch --interval 10

# Check file permissions
ls -la your-project-folder
```

### Too many false positives
```bash
# Create .securityprorc to ignore patterns
echo '{"ignore": ["test/**", "*.test.js"]}' > .securityprorc
```

## 🤝 Contributing

Found a bug? Have a feature idea? We'd love your help!

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Submit a pull request

Or just [open an issue](https://github.com/YOUR_USERNAME/securitypro/issues) - we respond quickly!

## 📄 License

MIT License - Free for personal and commercial use.

## 🙏 Acknowledgments

Built with love for developers who want to write secure code without becoming security experts.

Special thanks to:
- OWASP for vulnerability classifications
- The security research community
- Developers who reported real-world issues

---

**Stay secure, code confidently! 🔒**

Made with ❤️ for developers everywhere.
