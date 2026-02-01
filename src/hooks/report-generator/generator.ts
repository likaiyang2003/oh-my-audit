import type { ScanResult } from '../../agents/sentry/types'
import type { Vulnerability } from '../../types'
import { Severity } from '../../types'
import type { ReportOptions, HTMLReportTemplate, MarkdownReportTemplate } from './types'

export class ReportGenerator {
  private options: ReportOptions
  
  constructor(options: ReportOptions = {}) {
    this.options = {
      includeEvidence: true,
      includeRemediation: true,
      includeCodeExamples: true,
      severityFilter: ['critical', 'high', 'medium', 'low'],
      ...options
    }
  }
  
  async generateConsoleReport(scanResult: ScanResult): Promise<string> {
    const { vulnerabilities, summary, metadata } = scanResult
    
    let report = ''
    report += '📊 SECURITY AUDIT REPORT\n'
    report += '═'.repeat(50) + '\n\n'
    
    // 基本信息
    report += `📁 JAR File: ${metadata.jarPath}\n`
    report += `🔍 Framework: ${metadata.framework}\n`
    report += `📍 Entry Points: ${metadata.entryPointsCount}\n`
    report += `⏱️  Duration: ${summary.scanDuration}ms\n`
    report += `📅 Scan Time: ${metadata.scanStartTime.toISOString()}\n\n`
    
    // 漏洞统计
    report += 'VULNERABILITY SUMMARY\n'
    report += '─'.repeat(50) + '\n'
    report += `🔴 Critical: ${summary.criticalCount}\n`
    report += `🟠 High: ${summary.highCount}\n`
    report += `🟡 Medium: ${summary.mediumCount}\n`
    report += `🔵 Low: ${summary.lowCount}\n`
    report += `📊 Total: ${summary.totalVulnerabilities}\n\n`
    
    // 漏洞详情
    if (vulnerabilities.length === 0) {
      report += '✅ No vulnerabilities found\n'
    } else {
      report += 'VULNERABILITY DETAILS\n'
      report += '─'.repeat(50) + '\n\n'
      
      for (let i = 0; i < vulnerabilities.length; i++) {
        const vuln = vulnerabilities[i]
        report += this.formatVulnerabilityConsole(vuln, i + 1)
        report += '\n'
      }
    }
    
    return report
  }
  
  async generateJSONReport(scanResult: ScanResult): Promise<string> {
    const filteredResult = this.filterVulnerabilities(scanResult)
    return JSON.stringify(filteredResult, null, 2)
  }
  
  async generateHTMLReport(scanResult: ScanResult): Promise<string> {
    const { vulnerabilities, summary, metadata } = scanResult
    const filteredVulns = this.filterVulnerabilitiesList(vulnerabilities)
    
    let html = `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Security Audit Report - ${metadata.jarPath.split('/').pop()}</title>
    <style>
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            line-height: 1.6;
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
            background: #f5f5f5;
        }
        .header {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 30px;
            border-radius: 10px;
            margin-bottom: 30px;
        }
        .summary-box {
            display: grid;
            grid-template-columns: repeat(4, 1fr);
            gap: 20px;
            margin-bottom: 30px;
        }
        .stat-card {
            background: white;
            padding: 20px;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
            text-align: center;
        }
        .stat-number {
            font-size: 2em;
            font-weight: bold;
        }
        .critical { color: #dc3545; }
        .high { color: #fd7e14; }
        .medium { color: #ffc107; }
        .low { color: #17a2b8; }
        .vulnerability {
            background: white;
            margin-bottom: 20px;
            padding: 20px;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
            border-left: 4px solid #dc3545;
        }
        .vulnerability.critical { border-left-color: #dc3545; }
        .vulnerability.high { border-left-color: #fd7e14; }
        .vulnerability.medium { border-left-color: #ffc107; }
        .vulnerability.low { border-left-color: #17a2b8; }
        .severity-badge {
            display: inline-block;
            padding: 4px 12px;
            border-radius: 4px;
            color: white;
            font-weight: bold;
            text-transform: uppercase;
            font-size: 0.8em;
        }
        .severity-critical { background: #dc3545; }
        .severity-high { background: #fd7e14; }
        .severity-medium { background: #ffc107; color: #000; }
        .severity-low { background: #17a2b8; }
        .code-block {
            background: #f8f9fa;
            border: 1px solid #e9ecef;
            border-radius: 4px;
            padding: 15px;
            font-family: 'Monaco', 'Menlo', monospace;
            font-size: 0.9em;
            overflow-x: auto;
            margin: 10px 0;
        }
        .remediation {
            background: #d4edda;
            border: 1px solid #c3e6cb;
            border-radius: 4px;
            padding: 15px;
            margin-top: 15px;
        }
        h1, h2, h3 {
            margin-top: 0;
        }
        .metadata {
            background: #e9ecef;
            padding: 15px;
            border-radius: 4px;
            margin-bottom: 30px;
        }
    </style>
</head>
<body>
    <div class="header">
        <h1>🔒 Security Audit Report</h1>
        <p><strong>JAR:</strong> ${metadata.jarPath} | <strong>Framework:</strong> ${metadata.framework} | <strong>Scan Time:</strong> ${metadata.scanStartTime.toLocaleString()}</p>
    </div>
    
    <div class="metadata">
        <h3>Scan Metadata</h3>
        <p><strong>Files Scanned:</strong> ${summary.filesScanned} | <strong>Agents Executed:</strong> ${summary.agentsExecuted} | <strong>Duration:</strong> ${summary.scanDuration}ms</p>
    </div>
    
    <div class="summary-box">
        <div class="stat-card">
            <div class="stat-number critical">${summary.criticalCount}</div>
            <div>Critical</div>
        </div>
        <div class="stat-card">
            <div class="stat-number high">${summary.highCount}</div>
            <div>High</div>
        </div>
        <div class="stat-card">
            <div class="stat-number medium">${summary.mediumCount}</div>
            <div>Medium</div>
        </div>
        <div class="stat-card">
            <div class="stat-number low">${summary.lowCount}</div>
            <div>Low</div>
        </div>
    </div>
    
    <h2>🔍 Vulnerabilities (${filteredVulns.length} found)</h2>
    
    ${filteredVulns.map(vuln => this.formatVulnerabilityHTML(vuln)).join('')}
    
    <footer style="text-align: center; margin-top: 50px; color: #6c757d;">
        <p>Generated by Code Security Audit Plugin</p>
    </footer>
</body>
</html>`
    
    return html
  }
  
  async generateMarkdownReport(scanResult: ScanResult): Promise<string> {
    const { vulnerabilities, summary, metadata } = scanResult
    const filteredVulns = this.filterVulnerabilitiesList(vulnerabilities)
    
    let md = `# Security Audit Report\n\n`
    md += `**JAR File:** \`${metadata.jarPath}\`  \n`
    md += `**Framework:** ${metadata.framework}  \n`
    md += `**Scan Time:** ${metadata.scanStartTime.toISOString()}  \n`
    md += `**Duration:** ${summary.scanDuration}ms  \n\n`
    
    md += `## Summary\n\n`
    md += `| Severity | Count |\n`
    md += `|----------|-------|\n`
    md += `| 🔴 Critical | ${summary.criticalCount} |\n`
    md += `| 🟠 High | ${summary.highCount} |\n`
    md += `| 🟡 Medium | ${summary.mediumCount} |\n`
    md += `| 🔵 Low | ${summary.lowCount} |\n`
    md += `| **Total** | **${summary.totalVulnerabilities}** |\n\n`
    
    md += `---\n\n`
    md += `## Vulnerabilities (${filteredVulns.length} found)\n\n`
    
    if (filteredVulns.length === 0) {
      md += `✅ No vulnerabilities found.\n\n`
    } else {
      for (const vuln of filteredVulns) {
        md += this.formatVulnerabilityMarkdown(vuln)
        md += '\n---\n\n'
      }
    }
    
    md += `## Recommendations\n\n`
    md += `1. Prioritize fixing **Critical** and **High** severity vulnerabilities\n`
    md += `2. Implement security testing in CI/CD pipeline\n`
    md += `3. Regularly update dependencies and security patches\n`
    md += `4. Conduct periodic security audits\n\n`
    
    md += `---\n\n`
    md += `*Report generated by Code Security Audit Plugin*\n`
    
    return md
  }
  
  private formatVulnerabilityConsole(vuln: Vulnerability, index: number): string {
    const severityEmoji = {
      'critical': '🔴',
      'high': '🟠',
      'medium': '🟡',
      'low': '🔵'
    }
    
    let output = ''
    output += `${index}. ${severityEmoji[vuln.severity]} [${vuln.severity.toUpperCase()}] ${vuln.title}\n`
    output += `   📍 ${vuln.location.className}:${vuln.location.lineNumber}\n`
    output += `   📝 ${vuln.description}\n`
    output += `   🔗 CWE: ${vuln.cwe} | OWASP: ${vuln.owasp}\n`
    
    if (this.options.includeEvidence && vuln.evidence) {
      output += `   📊 Evidence: ${vuln.evidence.sourceFlow?.join(' → ') || 'N/A'}\n`
    }
    
    if (this.options.includeRemediation) {
      output += `   💡 Fix: ${vuln.remediation.description}\n`
    }
    
    return output
  }
  
  private formatVulnerabilityHTML(vuln: Vulnerability): string {
    return `
    <div class="vulnerability ${vuln.severity}">
        <h3>${vuln.title}</h3>
        <p><span class="severity-badge severity-${vuln.severity}">${vuln.severity}</span></p>
        <p><strong>Location:</strong> ${vuln.location.className}:${vuln.location.lineNumber}</p>
        <p><strong>Description:</strong> ${vuln.description}</p>
        <p><strong>CWE:</strong> ${vuln.cwe} | <strong>OWASP:</strong> ${vuln.owasp}</p>
        
        <div class="code-block">
            <strong>Code:</strong><br>
            <pre>${this.escapeHtml(vuln.location.codeSnippet)}</pre>
        </div>
        
        <div class="remediation">
            <strong>Remediation:</strong><br>
            <p>${vuln.remediation.description}</p>
            ${vuln.remediation.codeExample ? `<pre><code>${this.escapeHtml(vuln.remediation.codeExample)}</code></pre>` : ''}
            ${vuln.remediation.references ? `<p><strong>References:</strong> ${vuln.remediation.references.join(', ')}</p>` : ''}
        </div>
    </div>`
  }
  
  private formatVulnerabilityMarkdown(vuln: Vulnerability): string {
    const severityEmoji = {
      'critical': '🔴',
      'high': '🟠',
      'medium': '🟡',
      'low': '🔵'
    }
    
    let md = `### ${severityEmoji[vuln.severity]} ${vuln.title}\n\n`
    md += `**Severity:** \`${vuln.severity.toUpperCase()}\`  \n`
    md += `**Location:** \`${vuln.location.className}:${vuln.location.lineNumber}\`  \n`
    md += `**CWE:** ${vuln.cwe}  \n`
    md += `**OWASP:** ${vuln.owasp}\n\n`
    
    md += `**Description:**\n${vuln.description}\n\n`
    
    if (this.options.includeEvidence && vuln.evidence) {
      md += `**Evidence:**\n`
      if (vuln.evidence.sourceFlow) {
        md += `- Source: ${vuln.evidence.sourceFlow.join(' → ')}\n`
      }
      if (vuln.evidence.sinkFlow) {
        md += `- Sink: ${vuln.evidence.sinkFlow.join(' → ')}\n`
      }
      md += '\n'
    }
    
    md += `**Remediation:**\n${vuln.remediation.description}\n\n`
    
    if (this.options.includeCodeExamples && vuln.remediation.codeExample) {
      md += `**Safe Code Example:**\n\`
\`\`java\n${vuln.remediation.codeExample}\n\`\`\`\n\n`
    }
    
    return md
  }
  
  private escapeHtml(text: string): string {
    return text
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#039;')
  }
  
  private filterVulnerabilities(scanResult: ScanResult): ScanResult {
    return {
      ...scanResult,
      vulnerabilities: this.filterVulnerabilitiesList(scanResult.vulnerabilities)
    }
  }
  
  private filterVulnerabilitiesList(vulnerabilities: Vulnerability[]): Vulnerability[] {
    return vulnerabilities.filter(v => 
      this.options.severityFilter?.includes(v.severity)
    )
  }
}
