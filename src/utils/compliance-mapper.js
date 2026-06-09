/**
 * Maps OWASP Top 10 vulnerabilities to MITRE ATT&CK and NIST CSF 2.0 frameworks.
 */
class ComplianceMapper {
  static mappings = {
    'A01:2021 – Broken Access Control': {
      mitre: 'TA0004 Privilege Escalation / T1068',
      nist: 'PR.AC-1 Access is Managed'
    },
    'A02:2021 – Cryptographic Failures': {
      mitre: 'TA0009 Collection / T1560',
      nist: 'PR.DS-1 Data-at-rest is Protected'
    },
    'A03:2021 – Injection': {
      mitre: 'TA0001 Initial Access / T1190',
      nist: 'DE.CM-8 Vulnerability Scans'
    },
    'A04:2021 – Insecure Design': {
      mitre: 'TA0001 Initial Access',
      nist: 'GV.RM-1 Risk Management Strategy'
    },
    'A05:2021 – Security Misconfiguration': {
      mitre: 'TA0005 Defense Evasion / T1562',
      nist: 'PR.IP-1 Baseline Configuration'
    },
    'A06:2021 – Vulnerable and Outdated Components': {
      mitre: 'TA0001 Initial Access / T1190',
      nist: 'ID.AM-2 Software Asset Management'
    },
    'A07:2021 – Identification and Authentication Failures': {
      mitre: 'TA0006 Credential Access / T1110',
      nist: 'PR.AA-1 Identity Management'
    },
    'A08:2021 – Software and Data Integrity Failures': {
      mitre: 'TA0001 Initial Access / T1195',
      nist: 'PR.DS-6 Software Integrity'
    },
    'A09:2021 – Security Logging and Monitoring Failures': {
      mitre: 'TA0005 Defense Evasion / T1562.001',
      nist: 'DE.AE-2 Log Aggregation'
    },
    'A10:2021 – Server-Side Request Forgery (SSRF)': {
      mitre: 'TA0008 Lateral Movement / T1210',
      nist: 'DE.CM-8 Vulnerability Scans'
    }
  };

  /**
   * Get compliance mapping for an OWASP reference
   * @param {string} owaspReference - e.g., "A01:2021 – Broken Access Control"
   * @returns {Object|null} - { mitre: string, nist: string }
   */
  static getMapping(owaspReference) {
    if (!owaspReference) return null;
    
    // Exact match
    if (this.mappings[owaspReference]) {
      return this.mappings[owaspReference];
    }
    
    // Partial match (e.g., if it just says "A01:2021")
    const match = Object.keys(this.mappings).find(key => 
      key.includes(owaspReference) || owaspReference.includes(key.split(' ')[0])
    );
    
    return match ? this.mappings[match] : null;
  }
}

module.exports = ComplianceMapper;
