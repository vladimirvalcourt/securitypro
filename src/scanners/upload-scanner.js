const fs = require('fs');
const path = require('path');

/**
 * File Upload Security Scanner
 * Checks for insecure file upload implementations
 */
class UploadScanner {
  constructor(options = {}) {
    this.targetPath = options.targetPath || process.cwd();
    this.results = [];
  }

  async scan() {
    console.log('\n📤 Scanning file upload implementations...\n');

    const files = await this.getRelevantFiles();

    for (const file of files) {
      try {
        const content = fs.readFileSync(file, 'utf-8');
        const findings = this.scanFile(file, content);
        this.results.push(...findings);
      } catch (error) {
        continue;
      }
    }

    return {
      totalFindings: this.results.length,
      findings: this.results,
      severity: this.calculateSeverity(),
      byCategory: this.getCategorySummary()
    };
  }

  async getRelevantFiles() {
    const { glob } = require('glob');
    const patterns = ['**/*.{js,ts,jsx,tsx}', '**/*upload*', '**/*file*', '**/*multipart*'];
    const files = [];

    for (const pattern of patterns) {
      try {
        const found = await glob(pattern, {
          cwd: this.targetPath,
          nodir: true,
          ignore: ['node_modules/**', '.git/**', 'dist/**', 'build/**'],
          absolute: true
        });
        files.push(...found);
      } catch (error) {
        continue;
      }
    }

    return [...new Set(files)];
  }

  scanFile(filePath, content) {
    const findings = [];
    findings.push(...this.checkUnrestrictedUpload(filePath, content));
    findings.push(...this.checkMimeTypeValidation(filePath, content));
    findings.push(...this.checkFileSizeLimit(filePath, content));
    findings.push(...this.checkPathTraversal(filePath, content));
    findings.push(...this.checkStorageLocation(filePath, content));
    findings.push(...this.checkMalwareScanning(filePath, content));
    return findings;
  }

  checkUnrestrictedUpload(filePath, content) {
    const findings = [];
    const relativePath = path.relative(this.targetPath, filePath);

    if (/multer|express-fileupload|busboy|formidable/.test(content)) {
      if (!/fileFilter|filter|allowedTypes|mimeTypes/i.test(content)) {
        findings.push({
          id: `UPLOAD-UNRESTRICTED-${Date.now()}`,
          type: 'file-upload',
          category: 'unrestricted-file-type',
          severity: 'critical',
          title: 'File upload without type restrictions',
          file: relativePath,
          line: this.findLineNumber(content, /multer|express-fileupload/),
          remediation: 'Add file type validation. Only allow specific MIME types and extensions.',
          bestPractice: `const upload = multer({\n  fileFilter: (req, file, cb) => {\n    if (file.mimetype.startsWith('image/')) {\n      cb(null, true);\n    } else {\n      cb(new Error('Only images allowed'), false);\n    }\n  }\n})`,
          owaspReference: 'A03:2021 – Injection'
        });
      }
    }

    return findings;
  }

  checkMimeTypeValidation(filePath, content) {
    const findings = [];
    const relativePath = path.relative(this.targetPath, filePath);

    if (/req\.files|fileUpload|upload/.test(content) && !/mimetype|content-type|magic-number/i.test(content)) {
      findings.push({
        id: `UPLOAD-MIME-${Date.now()}`,
        type: 'file-upload',
        category: 'missing-mime-validation',
        severity: 'high',
        title: 'Upload without MIME type validation',
        file: relativePath,
        line: this.findLineNumber(content, /req\.files|fileUpload/),
        remediation: 'Validate MIME type server-side. Don\'t trust client-provided content-type.',
        bestPractice: 'Use file-type library to detect actual file type from buffer',
        owaspReference: 'A03:2021 – Injection'
      });
    }

    return findings;
  }

  checkFileSizeLimit(filePath, content) {
    const findings = [];
    const relativePath = path.relative(this.targetPath, filePath);

    if (/multer|upload/.test(content) && !/limits.*fileSize|maxFileSize|size.*limit/i.test(content)) {
      findings.push({
        id: `UPLOAD-SIZE-${Date.now()}`,
        type: 'file-upload',
        category: 'missing-size-limit',
        severity: 'medium',
        title: 'File upload without size limit',
        file: relativePath,
        line: this.findLineNumber(content, /multer|upload/),
        remediation: 'Set maximum file size to prevent DoS attacks.',
        bestPractice: 'const upload = multer({ limits: { fileSize: 5 * 1024 * 1024 } }) // 5MB',
        owaspReference: 'A04:2021 – Insecure Design'
      });
    }

    return findings;
  }

  checkPathTraversal(filePath, content) {
    const findings = [];
    const relativePath = path.relative(this.targetPath, filePath);

    if (/req\.files|upload/.test(content) && /originalname|filename/.test(content)) {
      if (!/sanitize|path\.basename|replace.*[\/\\]/i.test(content)) {
        findings.push({
          id: `UPLOAD-PATH-${Date.now()}`,
          type: 'file-upload',
          category: 'path-traversal-risk',
          severity: 'high',
          title: 'File upload vulnerable to path traversal',
          file: relativePath,
          line: this.findLineNumber(content, /originalname|filename/),
          remediation: 'Sanitize filenames. Remove path separators and use random names.',
          bestPractice: 'const safeName = `${Date.now()}-${crypto.randomUUID()}${path.extname(file.originalname)}`;',
          owaspReference: 'A01:2021 – Broken Access Control'
        });
      }
    }

    return findings;
  }

  checkStorageLocation(filePath, content) {
    const findings = [];
    const relativePath = path.relative(this.targetPath, filePath);

    if (/destination|dest|storage/.test(content) && /public|static|www/i.test(content)) {
      if (!/signed-url|private|authenticated/i.test(content)) {
        findings.push({
          id: `UPLOAD-STORAGE-${Date.now()}`,
          type: 'file-upload',
          category: 'public-storage',
          severity: 'medium',
          title: 'Uploaded files stored in publicly accessible directory',
          file: relativePath,
          line: this.findLineNumber(content, /destination|dest/),
          remediation: 'Store uploads outside public directories or use signed URLs.',
          bestPractice: 'Use S3 with signed URLs or store in private directory with access control',
          owaspReference: 'A01:2021 – Broken Access Control'
        });
      }
    }

    return findings;
  }

  checkMalwareScanning(filePath, content) {
    const findings = [];
    const relativePath = path.relative(this.targetPath, filePath);

    if (/upload|file/.test(content) && !/clamav|malware|virus|scan/i.test(content)) {
      // Only flag if it's clearly an upload endpoint
      if (/multer|express-fileupload|req\.files/.test(content)) {
        findings.push({
          id: `UPLOAD-MALWARE-${Date.now()}`,
          type: 'file-upload',
          category: 'missing-malware-scan',
          severity: 'low',
          title: 'File upload without malware scanning',
          file: relativePath,
          line: this.findLineNumber(content, /multer|upload/),
          remediation: 'Consider scanning uploaded files for malware, especially for user-generated content.',
          bestPractice: 'Use clamav or cloud-based malware scanning services',
          owaspReference: 'A04:2021 – Insecure Design'
        });
      }
    }

    return findings;
  }

  findLineNumber(content, pattern) {
    const lines = content.split('\n');
    for (let i = 0; i < lines.length; i++) {
      if (pattern.test(lines[i])) {
        return i + 1;
      }
    }
    return null;
  }

  calculateSeverity() {
    if (this.results.length === 0) return 'none';
    const hasCritical = this.results.some(f => f.severity === 'critical');
    const hasHigh = this.results.some(f => f.severity === 'high');
    if (hasCritical) return 'critical';
    if (hasHigh) return 'high';
    return 'medium';
  }

  getCategorySummary() {
    const summary = {};
    this.results.forEach(finding => {
      summary[finding.category] = (summary[finding.category] || 0) + 1;
    });
    return summary;
  }
}

module.exports = UploadScanner;
