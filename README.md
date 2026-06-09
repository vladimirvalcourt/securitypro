# 🔒 SecurityPro

**Your personal security guardian that works while you code.**

SecurityPro automatically scans your code for security vulnerabilities, hardcoded secrets, and common mistakes - catching issues before they become problems. Think of it as a security expert watching over your shoulder, helping you write safer code.

## 🎯 What Does It Do?

SecurityPro protects your projects by detecting:

### 🔑 **Hardcoded Secrets & API Keys**
- AWS credentials, Stripe keys, database passwords
- GitHub tokens, JWT secrets, OAuth credentials
- Any sensitive data accidentally left in code

### 🛡️ **Security Vulnerabilities**
- SQL injection attacks (hackers stealing your data)
- XSS attacks (hackers injecting malicious scripts)
- Broken authentication (unauthorized access)
- Insecure API endpoints

### 💾 **Database Issues**
- Unencrypted sensitive data
- Missing access controls
- Unsafe queries that can be exploited

### 🔐 **Authentication Problems**
- Weak password hashing
- Missing rate limiting (brute force protection)
- Insecure session handling

### 🌐 **API Security Gaps**
- Missing input validation
- Exposed internal errors
- No rate limiting

## ✨ Why Use SecurityPro?

**For Beginners:**
- Catches security mistakes before hackers find them
- Explains issues in plain English with simple fixes
- No security expertise needed

**For Teams:**
- Automated security checks on every save
- Prevents secrets from being committed to Git
- Ensures consistent security standards

**For Everyone:**
- Runs silently in the background
- Instant feedback when you make a mistake
- Saves hours of debugging security issues later

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
| `securitypro scan` | Full security audit | Before committing code |
| `securitypro quick` | Fast secret check | Quick verification |
| `securitypro watch` | Auto-scan on file changes | While coding (recommended!) |
| `securitypro threats` | Show all security threats | Learning & education |
| `securitypro check-config` | Verify setup files | Project initialization |

### Scan Options

```bash
# Skip certain checks (faster)
securitypro scan --no-owasp --no-auth

# Ignore specific folders
securitypro scan --ignore "test/**,node_modules/**"

# Verbose output (see everything)
securitypro scan --verbose

# Save report to file
securitypro scan --output report.json
```

### Watch Options

```bash
# Custom scan interval (seconds)
securitypro watch --interval 10

# Watch specific path
securitypro watch --path ./src

# Quiet mode (only show critical issues)
securitypro watch --quiet
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

Add to your GitHub Actions workflow:

```yaml
name: Security Check
on: [push, pull_request]

jobs:
  security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - name: Install SecurityPro
        run: npm install -g securitypro
      - name: Run Security Scan
        run: securitypro scan --output report.json
      - name: Upload Report
        uses: actions/upload-artifact@v3
        with:
          name: security-report
          path: report.json
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
