const fs = require('fs');
const path = require('path');

/**
 * HTML reporter for creating visual dashboards of scan results
 */
class HtmlReporter {
  constructor() {
    this.template = `
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SecurityPro Vibe Report</title>
    <style>
        body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; background-color: #f4f4f9; color: #333; margin: 0; padding: 20px; }
        .container { max-width: 1000px; margin: 0 auto; background: white; padding: 30px; border-radius: 8px; box-shadow: 0 4px 6px rgba(0,0,0,0.1); }
        h1 { color: #2c3e50; border-bottom: 2px solid #3498db; padding-bottom: 10px; }
        .score-card { background: #34495e; color: white; padding: 20px; border-radius: 8px; text-align: center; margin: 20px 0; }
        .score-card h2 { margin: 0; font-size: 3rem; }
        .summary-stats { display: flex; justify-content: space-between; margin-bottom: 30px; }
        .stat-box { background: #ecf0f1; padding: 15px; border-radius: 5px; flex: 1; margin: 0 10px; text-align: center; }
        .stat-box.critical { border-top: 4px solid #e74c3c; }
        .stat-box.high { border-top: 4px solid #e67e22; }
        .stat-box.medium { border-top: 4px solid #f1c40f; }
        .finding { background: #fff; border: 1px solid #ddd; padding: 15px; margin-bottom: 15px; border-left: 4px solid #ccc; border-radius: 4px; }
        .finding.critical { border-left-color: #e74c3c; }
        .finding.high { border-left-color: #e67e22; }
        .finding.medium { border-left-color: #f1c40f; }
        .finding h3 { margin-top: 0; }
        .meta { font-size: 0.9rem; color: #7f8c8d; }
        .remediation { background: #e8f8f5; padding: 10px; border-radius: 4px; margin-top: 10px; }
    </style>
</head>
<body>
    <div class="container">
        <h1>🔒 SecurityPro Report</h1>
        
        <div class="score-card">
            <p>Overall Vibe Score</p>
            <h2>{{VIBE_SCORE}}</h2>
        </div>

        <div class="summary-stats">
            <div class="stat-box critical">
                <h3>Critical</h3>
                <p>{{CRITICAL_COUNT}}</p>
            </div>
            <div class="stat-box high">
                <h3>High</h3>
                <p>{{HIGH_COUNT}}</p>
            </div>
            <div class="stat-box medium">
                <h3>Medium/Low</h3>
                <p>{{MEDIUM_COUNT}}</p>
            </div>
        </div>

        <h2>Findings Details</h2>
        {{FINDINGS_HTML}}
    </div>
</body>
</html>`;
  }

  generateReport(results, targetPath, duration, vibeScore) {
    const allFindings = [
      ...(results.secretScan?.findings || []),
      ...(results.owaspScan?.findings || []),
      ...(results.authScan?.findings || []),
      ...(results.dbScan?.findings || []),
      ...(results.apiScan?.findings || []),
      ...(results.dependencyScan?.findings || []),
      ...(results.promptScan?.findings || []),
      ...(results.iacScan?.findings || []),
      ...(results.astScan?.findings || [])
    ];

    const criticalCount = allFindings.filter(f => f.severity === 'critical').length;
    const highCount = allFindings.filter(f => f.severity === 'high').length;
    const mediumCount = allFindings.length - criticalCount - highCount;

    let findingsHtml = '';
    if (allFindings.length === 0) {
      findingsHtml = '<p>No vulnerabilities found! Great job!</p>';
    } else {
      findingsHtml = allFindings.map(f => {
        const mitreHtml = f.mitreReference ? ` | <strong>MITRE:</strong> ${f.mitreReference}` : '';
        const nistHtml = f.nistReference ? ` | <strong>NIST CSF:</strong> ${f.nistReference}` : '';
        const owaspHtml = f.owaspReference ? ` | <strong>OWASP:</strong> ${f.owaspReference}` : '';
        
        return `
          <div class="finding ${f.severity}">
              <h3>[${f.severity.toUpperCase()}] ${f.title}</h3>
              <p class="meta"><strong>File:</strong> ${f.file}:${f.line || '?'} | <strong>Category:</strong> ${f.category}${owaspHtml}${mitreHtml}${nistHtml}</p>
              <div class="remediation">
                  <strong>Remediation:</strong> ${f.remediation}
              </div>
          </div>
        `;
      }).join('\\n');
    }

    let html = this.template
      .replace('{{VIBE_SCORE}}', vibeScore || 'N/A')
      .replace('{{CRITICAL_COUNT}}', criticalCount)
      .replace('{{HIGH_COUNT}}', highCount)
      .replace('{{MEDIUM_COUNT}}', mediumCount)
      .replace('{{FINDINGS_HTML}}', findingsHtml);

    return html;
  }

  saveToFile(htmlContent, outputPath) {
    const fullPath = path.resolve(outputPath);
    const dir = path.dirname(fullPath);

    if (!fs.existsSync(dir)) {
      fs.mkdirSync(dir, { recursive: true });
    }

    fs.writeFileSync(fullPath, htmlContent, 'utf-8');
    return fullPath;
  }
}

module.exports = HtmlReporter;
