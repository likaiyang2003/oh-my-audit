# Usage Guide - Java Code Security Audit Plugin

## Table of Contents

- [Installation](#installation)
- [Quick Start](#quick-start)
- [CLI Usage](#cli-usage)
- [Programmatic API](#programmatic-api)
- [Output Formats](#output-formats)
- [Common Use Cases](#common-use-cases)
- [Troubleshooting](#troubleshooting)

## Installation

### Prerequisites

- [Bun](https://bun.sh/) runtime (v1.0.0 or higher)
- Java JAR files to analyze

### Install as Dependency

```bash
# Using Bun (recommended)
bun install code-security-audit

# Or clone the repository
git clone https://github.com/your-org/code-security-audit.git
cd code-security-audit
bun install
```

### Build from Source

```bash
# Install dependencies
bun install

# Type check
bun run typecheck

# Run tests
bun test

# Build the project
bun run build
```

## Quick Start

### 1. Basic JAR Scan

```typescript
import { JarAnalyzer } from 'code-security-audit'

const analyzer = new JarAnalyzer()
const result = await analyzer.analyze('./target/application.jar')

console.log(`Framework: ${result.framework.type}`)
console.log(`Risk Score: ${result.riskScore}`)
console.log(`Entry Points: ${result.entryPoints.length}`)
```

### 2. Complete Security Audit

```typescript
import { JarAnalyzer, SentryAgent, ReportGenerator } from 'code-security-audit'
import { CFRDecompiler } from 'code-security-audit/decompiler'
import { DecompileManager } from 'code-security-audit/decompiler'

// 1. Analyze JAR structure
const analyzer = new JarAnalyzer()
const jarAnalysis = await analyzer.analyze('./app.jar')

// 2. Decompile critical classes
const decompiler = new CFRDecompiler()
const manager = new DecompileManager(decompiler)
const sources = await manager.decompileCriticalClasses('./app.jar', jarAnalysis.entryPoints)

// 3. Run security scan
const sentry = new SentryAgent()
const scanResult = await sentry.orchestrate('./app.jar', jarAnalysis, sources)

// 4. Generate report
const reporter = new ReportGenerator()
const report = await reporter.generateConsoleReport(scanResult)
console.log(report)
```

## CLI Usage

The plugin provides a CLI interface for quick scans:

```bash
# Basic scan
bun run scan ./target/app.jar

# Scan with specific severity filter
bun run scan ./target/app.jar --severity high

# Generate HTML report
bun run scan ./target/app.jar --format html --output report.html

# Scan with custom configuration
bun run scan ./target/app.jar --config ./audit-config.json
```

### CLI Options

| Option | Description | Default |
|--------|-------------|---------|
| `--severity` | Minimum severity level | `low` |
| `--format` | Output format (console, json, html, markdown) | `console` |
| `--output` | Output file path | stdout |
| `--config` | Configuration file path | - |
| `--parallel` | Enable parallel execution | `true` |
| `--max-concurrency` | Maximum concurrent agents | `5` |

## Programmatic API

### JarAnalyzer

Analyze JAR file structure and metadata:

```typescript
import { JarAnalyzer } from 'code-security-audit'

const analyzer = new JarAnalyzer({
  includeInnerClasses: true,
  maxEntryPoints: 100,
  riskThreshold: 0
})

const result = await analyzer.analyze('./app.jar')

// Access analysis results
console.log(result.manifest)
console.log(result.framework)
console.log(result.entryPoints)
console.log(result.dependencies)
console.log(result.configFiles)
console.log(result.riskScore)
```

### SentryAgent

Orchestrate security scanning with multiple specialized agents:

```typescript
import { SentryAgent } from 'code-security-audit'

const sentry = new SentryAgent({
  parallelExecution: true,
  maxConcurrency: 5,
  enableDeduplication: true,
  severityThreshold: 'medium'
})

const scanResult = await sentry.orchestrate(
  './app.jar',
  jarAnalysis,
  decompiledSources
)

// Access scan results
console.log(scanResult.vulnerabilities)
console.log(scanResult.summary)
console.log(scanResult.metadata)
```

### ReportGenerator

Generate reports in multiple formats:

```typescript
import { ReportGenerator } from 'code-security-audit'

const reporter = new ReportGenerator({
  includeEvidence: true,
  includeRemediation: true,
  includeCodeExamples: true,
  severityFilter: ['critical', 'high', 'medium']
})

// Console output
const consoleReport = await reporter.generateConsoleReport(scanResult)

// JSON output
const jsonReport = await reporter.generateJSONReport(scanResult)

// HTML report
const htmlReport = await reporter.generateHTMLReport(scanResult)

// Markdown report
const markdownReport = await reporter.generateMarkdownReport(scanResult)
```

## Output Formats

### Console Output

```
📊 SECURITY AUDIT REPORT
══════════════════════════════════════════════════

📁 JAR File: ./app.jar
🔍 Framework: spring-boot
📍 Entry Points: 42
⏱️  Duration: 1250ms
📅 Scan Time: 2026-01-31T12:00:00.000Z

VULNERABILITY SUMMARY
──────────────────────────────────────────────────
🔴 Critical: 2
🟠 High: 5
🟡 Medium: 8
🔵 Low: 3
📊 Total: 18

VULNERABILITY DETAILS
──────────────────────────────────────────────────

1. 🔴 [CRITICAL] SQL Injection via String Concatenation
   📍 UserController:45
   📝 SQL query built using string concatenation with user input
   🔗 CWE: CWE-89 | OWASP: A03:2021 - Injection
   📊 Evidence: name → executeQuery
   💡 Fix: Use PreparedStatement with parameterized queries
```

### JSON Output

```json
{
  "vulnerabilities": [
    {
      "id": "sql-inj-1234567890-abc123",
      "type": "SQL_INJECTION",
      "severity": "critical",
      "title": "SQL Injection via String Concatenation",
      "description": "SQL query built using string concatenation...",
      "location": {
        "className": "UserController",
        "methodName": "searchUsers",
        "lineNumber": 45,
        "codeSnippet": "String sql = \"SELECT * FROM users WHERE name = '" + name + "'\";"
      },
      "remediation": {
        "description": "Use PreparedStatement with parameterized queries",
        "codeExample": "PreparedStatement stmt = conn.prepareStatement(sql);",
        "references": [
          "https://owasp.org/www-community/attacks/SQL_Injection"
        ]
      }
    }
  ],
  "summary": {
    "totalVulnerabilities": 18,
    "criticalCount": 2,
    "highCount": 5,
    "mediumCount": 8,
    "lowCount": 3
  }
}
```

### HTML Report

The HTML report includes:
- Interactive vulnerability cards
- Syntax-highlighted code snippets
- Severity badges and statistics
- Remediation recommendations
- Responsive design

### Markdown Report

Markdown reports are ideal for:
- GitHub issues
- Documentation
- Email reports
- CI/CD pipeline artifacts

## Common Use Cases

### Use Case 1: CI/CD Integration

```typescript
// scan-ci.ts
import { JarAnalyzer, SentryAgent, ReportGenerator } from 'code-security-audit'

async function ciScan() {
  const jarPath = process.argv[2]
  const maxCritical = parseInt(process.argv[3] || '0')
  
  // Scan
  const analyzer = new JarAnalyzer()
  const sentry = new SentryAgent({ severityThreshold: 'high' })
  const reporter = new ReportGenerator()
  
  const jarAnalysis = await analyzer.analyze(jarPath)
  // ... decompile and scan ...
  
  // Fail build if too many critical vulnerabilities
  if (scanResult.summary.criticalCount > maxCritical) {
    console.error(`❌ Build failed: ${scanResult.summary.criticalCount} critical vulnerabilities found`)
    process.exit(1)
  }
  
  console.log('✅ Security check passed')
}

ciScan()
```

### Use Case 2: Batch Scanning

```typescript
// batch-scan.ts
import { glob } from 'glob'
import { JarAnalyzer, SentryAgent } from 'code-security-audit'

async function batchScan(directory: string) {
  const jars = await glob(`${directory}/**/*.jar`)
  
  const analyzer = new JarAnalyzer()
  const sentry = new SentryAgent()
  
  for (const jar of jars) {
    console.log(`\n🔍 Scanning: ${jar}`)
    const result = await analyzer.analyze(jar)
    // ... scan logic ...
  }
}

batchScan('./target')
```

### Use Case 3: Custom Rule Development

```typescript
// custom-agent.ts
import type { AttackEntry, Vulnerability, DecompileResult } from 'code-security-audit'

class CustomSecurityAgent {
  async audit(
    jarPath: string,
    entryPoints: AttackEntry[],
    decompiledSources: Map<string, DecompileResult>
  ): Promise<Vulnerability[]> {
    const vulnerabilities: Vulnerability[] = []
    
    for (const entry of entryPoints) {
      const source = decompiledSources.get(entry.className)
      if (!source) continue
      
      // Custom detection logic
      if (this.detectCustomIssue(source.sourceCode)) {
        vulnerabilities.push({
          id: `custom-${Date.now()}`,
          type: 'CUSTOM_ISSUE',
          severity: 'high',
          title: 'Custom Security Issue',
          // ... additional fields
        })
      }
    }
    
    return vulnerabilities
  }
}
```

### Use Case 4: Integration with Security Dashboard

```typescript
// dashboard-integration.ts
import { SentryAgent } from 'code-security-audit'

async function uploadToDashboard(scanResult: ScanResult) {
  const payload = {
    project: 'my-app',
    version: '1.0.0',
    timestamp: new Date().toISOString(),
    vulnerabilities: scanResult.vulnerabilities.map(v => ({
      id: v.id,
      severity: v.severity,
      title: v.title,
      cwe: v.cwe,
      owasp: v.owasp
    })),
    summary: scanResult.summary
  }
  
  await fetch('https://security-dashboard.company.com/api/scans', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload)
  })
}
```

## Troubleshooting

### Common Issues

#### Issue: "Failed to analyze JAR"

**Cause**: Corrupted or invalid JAR file

**Solution**:
```bash
# Verify JAR integrity
jar tf app.jar

# Check if it's a valid ZIP
unzip -t app.jar
```

#### Issue: "Out of memory during decompilation"

**Cause**: Large JAR files with many classes

**Solution**:
```typescript
const sentry = new SentryAgent({
  maxConcurrency: 2  // Reduce concurrency
})

const analyzer = new JarAnalyzer({
  maxEntryPoints: 50  // Limit entry points
})
```

#### Issue: "False positives in SQL injection detection"

**Cause**: Complex code patterns

**Solution**:
```typescript
const sqlAgent = new SQLInjectionAgent({
  strictMode: false,  // Be more lenient
  includeMyBatisXML: false  // Skip XML analysis
})
```

#### Issue: "Cache not working"

**Cause**: Cache directory permissions

**Solution**:
```bash
# Create cache directory with proper permissions
mkdir -p .security-audit/cache/decompile
chmod 755 .security-audit/cache/decompile
```

### Debug Mode

Enable verbose logging:

```typescript
const sentry = new SentryAgent({
  // Debug mode is enabled via environment variable
})

// Set before running
process.env.DEBUG_AUDIT = 'true'
```

### Performance Tips

1. **Use caching**: Enable disk caching for repeated scans
2. **Limit scope**: Scan only critical entry points
3. **Parallel execution**: Enable parallel agent execution
4. **Filter severity**: Set appropriate severity thresholds

```typescript
// Optimized configuration
const config = {
  analyzer: { maxEntryPoints: 50 },
  sentry: { 
    parallelExecution: true,
    maxConcurrency: 5,
    severityThreshold: 'medium'
  },
  report: {
    severityFilter: ['critical', 'high', 'medium']
  }
}
```

---

**Next Steps**: 
- Read the [API Reference](API.md) for detailed API documentation
- Check [Configuration Options](CONFIGURATION.md) for advanced settings
- See [FAQ](FAQ.md) for common questions
