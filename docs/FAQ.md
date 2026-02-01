# Frequently Asked Questions (FAQ)

## Table of Contents

- [General Questions](#general-questions)
- [Installation & Setup](#installation--setup)
- [Usage & Scanning](#usage--scanning)
- [Configuration](#configuration)
- [Vulnerabilities](#vulnerabilities)
- [Performance](#performance)
- [Integration](#integration)
- [Troubleshooting](#troubleshooting)
- [Contributing](#contributing)

## General Questions

### Q: What is the Java Code Security Audit Plugin?

**A:** A comprehensive security scanning tool for Java applications. It analyzes JAR files to detect:
- SQL Injection vulnerabilities
- Server-Side Request Forgery (SSRF)
- Remote Code Execution (RCE)
- Authentication bypasses
- Business logic flaws
- Hardcoded credentials

### Q: Is it free to use?

**A:** Yes, it's open-source under the MIT license. You can use it freely for personal and commercial projects.

### Q: What Java versions are supported?

**A:** The plugin analyzes bytecode from Java 8 through Java 21. The decompiler supports all modern Java features including:
- Records
- Sealed classes
- Pattern matching
- Text blocks
- Switch expressions

### Q: Can it analyze Android APKs?

**A:** Not directly. APKs use Dalvik bytecode (DEX format). However, you can:
1. Convert APK to JAR using tools like `dex2jar`
2. Analyze the resulting JAR file

```bash
dex2jar app.apk
bun run scan app-dex2jar.jar
```

### Q: Does it support Kotlin?

**A:** Yes! Since Kotlin compiles to JVM bytecode, the plugin can analyze Kotlin-compiled JARs. The decompiler will show Java-equivalent code.

### Q: How accurate is the detection?

**A:** Detection accuracy varies by vulnerability type:

| Vulnerability Type | Accuracy | False Positive Rate |
|-------------------|----------|-------------------|
| SQL Injection | 90%+ | Low |
| Hardcoded Credentials | 95%+ | Very Low |
| SSRF | 75% | Medium |
| RCE | 80% | Low-Medium |
| Auth Bypass | 70% | Medium |

For production use, we recommend manual review of findings.

## Installation & Setup

### Q: What are the prerequisites?

**A:** Required:
- Bun runtime v1.0.0 or higher
- 2GB+ RAM (4GB+ recommended for large JARs)
- Read access to target JAR files

Optional:
- Java runtime (for advanced decompilation features)

### Q: How do I install Bun?

**A:** 
```bash
# macOS/Linux
curl -fsSL https://bun.sh/install | bash

# Windows (via WSL or PowerShell)
powershell -c "irm bun.sh/install.ps1 | iex"
```

### Q: Installation fails with "Cannot find module"

**A:** Common fixes:

```bash
# Clear Bun cache
bun pm cache rm

# Reinstall dependencies
rm -rf node_modules bun.lockb
bun install

# Verify installation
bun --version
```

### Q: Can I use npm/yarn instead of Bun?

**A:** No. This plugin is built specifically for the Bun runtime and uses Bun-specific APIs (e.g., `Bun.file()`, `Bun.write()`).

## Usage & Scanning

### Q: How do I scan a single JAR file?

**A:**
```typescript
import { JarAnalyzer, SentryAgent, ReportGenerator } from 'code-security-audit'

const analyzer = new JarAnalyzer()
const sentry = new SentryAgent()
const reporter = new ReportGenerator()

const jarAnalysis = await analyzer.analyze('./app.jar')
// ... decompile and scan ...
const report = await reporter.generateConsoleReport(scanResult)
console.log(report)
```

### Q: How do I scan multiple JARs?

**A:**
```typescript
import { glob } from 'glob'

const jars = await glob('./libs/**/*.jar')

for (const jar of jars) {
  console.log(`\n🔍 Scanning: ${jar}`)
  const result = await analyzer.analyze(jar)
  // ... scan logic ...
}
```

### Q: Can I exclude certain files from scanning?

**A:** The analyzer doesn't have built-in exclusions, but you can filter entry points:

```typescript
const jarAnalysis = await analyzer.analyze('./app.jar')

// Filter out test classes
const filtered = jarAnalysis.entryPoints.filter(
  e => !e.className.includes('Test') && 
       !e.className.includes('Mock')
)
```

### Q: How do I scan a WAR file?

**A:** WAR files are JAR files with a specific structure. Extract and scan:

```bash
mkdir temp-war
cd temp-war
jar xf ../app.war
bun run scan WEB-INF/classes/*.jar
```

### Q: What output formats are supported?

**A:** Four formats:
- **Console**: Colored terminal output with emojis
- **JSON**: Machine-parseable format
- **HTML**: Styled web report
- **Markdown**: Documentation-friendly format

```typescript
const consoleReport = await reporter.generateConsoleReport(scanResult)
const jsonReport = await reporter.generateJSONReport(scanResult)
const htmlReport = await reporter.generateHTMLReport(scanResult)
const markdownReport = await reporter.generateMarkdownReport(scanResult)
```

### Q: Can I customize the report template?

**A:** Currently, templates are built-in. For custom templates, process the JSON output:

```typescript
const jsonReport = await reporter.generateJSONReport(scanResult)
const data = JSON.parse(jsonReport)

// Generate custom report
const customReport = `
# Custom Security Report
Total: ${data.summary.totalVulnerabilities}
Critical: ${data.summary.criticalCount}
`
```

## Configuration

### Q: How do I set the minimum severity level?

**A:**
```typescript
const sentry = new SentryAgent({
  severityThreshold: 'high'  // Only high and critical
})
```

### Q: How do I speed up scanning?

**A:** Several options:

```typescript
const sentry = new SentryAgent({
  parallelExecution: true,   // Run agents in parallel
  maxConcurrency: 5,         // Adjust based on CPU
  severityThreshold: 'high'  // Skip low/medium
})

const analyzer = new JarAnalyzer({
  maxEntryPoints: 50,        // Limit scope
  includeInnerClasses: false // Skip inner classes
})
```

### Q: How do I enable/disable specific vulnerability checks?

**A:** Currently, all agents run together. To run specific agents:

```typescript
import { SQLInjectionAgent, SSRFAgent } from 'code-security-audit/agents'

// Run only specific agents
const sqlAgent = new SQLInjectionAgent()
const ssrfAgent = new SSRFAgent()

const sqlVulns = await sqlAgent.audit(jarPath, entryPoints, sources)
const ssrfVulns = await ssrfAgent.audit(jarPath, entryPoints, sources)
```

### Q: Can I use a configuration file?

**A:** Yes, create a JSON config file:

```json
{
  "sentry": {
    "severityThreshold": "medium",
    "parallelExecution": true
  },
  "analyzer": {
    "maxEntryPoints": 100
  }
}
```

Load it:
```typescript
const config = await Bun.file('./audit-config.json').json()
const sentry = new SentryAgent(config.sentry)
```

### Q: How do environment variables work?

**A:**

```bash
export AUDIT_SEVERITY_THRESHOLD=high
export AUDIT_MAX_CONCURRENCY=3
export AUDIT_CACHE_DIR=/tmp/cache
```

Read in code:
```typescript
const severity = process.env.AUDIT_SEVERITY_THRESHOLD || 'low'
```

## Vulnerabilities

### Q: What vulnerability types are detected?

**A:** 11 vulnerability types across 5 categories:

1. **Injection**
   - SQL Injection (CWE-89)
   - RCE/Command Injection (CWE-78)
   - XSS (CWE-79)
   - XXE (CWE-611)

2. **Authentication**
   - Auth Bypass (CWE-287)
   - IDOR (CWE-639)
   - Hardcoded Credentials (CWE-798)

3. **Cryptography**
   - JWT None Algorithm (CWE-327)
   - JWT Weak Secret (CWE-326)

4. **Network**
   - SSRF (CWE-918)

5. **Logic**
   - Business Logic Flaws (CWE-840)

### Q: How are severity levels assigned?

**A:** Based on:
- **Exploitability**: How easy to exploit (network-accessible vs local)
- **Impact**: Data loss, remote code execution, privilege escalation
- **Prevalence**: How common the vulnerable pattern is
- **Context**: Framework security controls, deployment environment

### Q: What about false positives?

**A:** False positives can occur when:
- Code uses sanitization the plugin doesn't detect
- Framework security controls are applied
- Complex control flows confuse the analyzer

**Reducing false positives:**
```typescript
const sqlAgent = new SQLInjectionAgent({
  strictMode: false  // More lenient detection
})
```

### Q: Can I add custom vulnerability rules?

**A:** Yes, by extending the base agent:

```typescript
import type { AttackEntry, Vulnerability, DecompileResult } from 'code-security-audit'

class CustomAgent {
  async audit(
    jarPath: string,
    entryPoints: AttackEntry[],
    sources: Map<string, DecompileResult>
  ): Promise<Vulnerability[]> {
    // Custom detection logic
    return []
  }
}
```

### Q: Are 0-day vulnerabilities detected?

**A:** The plugin detects known vulnerability patterns (SQL injection patterns, dangerous API usage). It does not have a vulnerability database for CVEs. For CVE detection, use OWASP Dependency-Check alongside this plugin.

## Performance

### Q: How long does a scan take?

**A:** Typical scan times:

| JAR Size | Entry Points | Duration |
|----------|--------------|----------|
| 5MB | 10 | 10-20s |
| 20MB | 50 | 30-60s |
| 100MB | 200 | 2-5min |

Factors affecting speed:
- JAR size and complexity
- Number of entry points
- Decompilation depth
- Concurrent agent count

### Q: Why is my scan slow?

**A:** Common causes:

1. **Large JAR files**: Reduce `maxEntryPoints`
2. **Many inner classes**: Set `includeInnerClasses: false`
3. **High concurrency**: Lower `maxConcurrency`
4. **No caching**: Enable decompiler cache
5. **Complex obfuscation**: Some obfuscated code takes longer to decompile

### Q: How much memory is needed?

**A:** Memory requirements:

| JAR Size | Minimum RAM | Recommended |
|----------|-------------|-------------|
| < 10MB | 2GB | 4GB |
| 10-50MB | 4GB | 8GB |
| 50-200MB | 8GB | 16GB |
| > 200MB | 16GB | 32GB |

### Q: Can I scan in CI/CD?

**A:** Yes! Optimize for CI:

```typescript
// ci-scan.ts
const sentry = new SentryAgent({
  severityThreshold: 'high',
  maxConcurrency: 2  // Conservative for CI runners
})

const result = await sentry.orchestrate(jarPath, analysis, sources)

if (result.summary.criticalCount > 0) {
  process.exit(1)  // Fail build
}
```

### Q: Is there a progress indicator?

**A:** The plugin logs progress to console:

```
🚀 Sentry Agent 开始扫描: app.jar
📊 发现 42 个攻击面入口
🔍 框架类型: spring-boot
⚡ 并行执行所有检测 Agent...
  ✅ SQL Injection: 发现 3 个漏洞
  ✅ SSRF: 未发现漏洞
  ✅ RCE: 发现 1 个漏洞
✨ 扫描完成！总计发现 4 个漏洞
⏱️  耗时: 3250ms
```

## Integration

### Q: Can I integrate with Jenkins?

**A:** Yes, use a pipeline stage:

```groovy
pipeline {
  stages {
    stage('Security Scan') {
      steps {
        sh 'bun run scan target/*.jar --format json --output scan-results.json'
        archiveArtifacts artifacts: 'scan-results.json'
      }
    }
  }
}
```

### Q: Can I integrate with GitHub Actions?

**A:**

```yaml
name: Security Audit
on: [push, pull_request]

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: oven-sh/setup-bun@v1
      - run: bun install
      - run: bun run scan ./target/app.jar --format html --output report.html
      - uses: actions/upload-artifact@v4
        with:
          name: security-report
          path: report.html
```

### Q: Can I send results to Slack?

**A:**

```typescript
const summary = scanResult.summary

await fetch('https://hooks.slack.com/services/YOUR/WEBHOOK/URL', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({
    text: `🔒 Security Scan Complete\n` +
          `Critical: ${summary.criticalCount}\n` +
          `High: ${summary.highCount}\n` +
          `Total: ${summary.totalVulnerabilities}`
  })
})
```

### Q: Can I integrate with Jira?

**A:**

```typescript
for (const vuln of scanResult.vulnerabilities) {
  if (vuln.severity === 'critical' || vuln.severity === 'high') {
    await createJiraIssue({
      project: 'SEC',
      summary: `[${vuln.severity}] ${vuln.title}`,
      description: vuln.description,
      priority: vuln.severity === 'critical' ? 'Highest' : 'High',
      labels: ['security', vuln.type.toLowerCase()]
    })
  }
}
```

### Q: Is there a REST API?

**A:** Not built-in, but you can create one:

```typescript
import { Elysia } from 'elysia'

const app = new Elysia()
  .post('/scan', async ({ body }) => {
    const { jarPath } = body
    // ... scan logic ...
    return scanResult
  })
  .listen(3000)
```

## Troubleshooting

### Q: "Failed to analyze JAR" error

**A:**
1. Verify file exists: `ls -la app.jar`
2. Check it's a valid JAR: `jar tf app.jar`
3. Verify permissions: `chmod 644 app.jar`
4. Check disk space: `df -h`

### Q: Out of memory errors

**A:**
1. Reduce `maxEntryPoints` to 20-30
2. Set `includeInnerClasses: false`
3. Lower `maxConcurrency` to 1-2
4. Increase system memory or use swap

### Q: Decompilation fails

**A:**
1. Check if JAR is obfuscated (try `--obfuscation light`)
2. Increase timeout: `timeout: 60000`
3. Check Java version compatibility
4. Try a different decompiler engine

### Q: No vulnerabilities found (suspicious)

**A:** Possible reasons:
1. Application is actually secure (congratulations!)
2. Decompilation failed (check logs)
3. Entry points not detected (check framework type)
4. Obfuscation preventing analysis

Debug steps:
```typescript
console.log('Framework:', jarAnalysis.framework)
console.log('Entry points:', jarAnalysis.entryPoints.length)
console.log('Decompiled:', decompiledSources.size)
```

### Q: False positive rate is high

**A:**
1. Use `strictMode: false` for SQL injection
2. Increase `severityThreshold` to filter low-confidence findings
3. Review and whitelist safe patterns in your codebase

### Q: Cache not working

**A:**
1. Check directory permissions
2. Verify cache directory exists
3. Clear corrupted cache: `rm -rf .security-audit/cache`

## Contributing

### Q: How can I contribute?

**A:**
1. Report bugs via GitHub Issues
2. Submit PRs for bug fixes
3. Add new detection rules
4. Improve documentation
5. Share feedback and use cases

### Q: What coding standards are used?

**A:**
- Bun runtime (not Node.js)
- Strict TypeScript
- No `any` types
- Test-driven development (TDD)
- 100% test coverage for new code

### Q: How do I add a new vulnerability agent?

**A:**
1. Create `src/agents/my-agent/agent.ts`
2. Define types in `src/agents/my-agent/types.ts`
3. Add detection rules in `src/agents/my-agent/rules.ts`
4. Write tests in `src/agents/my-agent/agent.test.ts`
5. Export from `src/agents/my-agent/index.ts`
6. Register in SentryAgent orchestration

### Q: Where can I get help?

**A:**
- GitHub Issues: Bug reports and features
- GitHub Discussions: Questions and ideas
- Documentation: This guide and API docs

---

**Still have questions?** 

Open an issue on GitHub or check the other documentation:
- [Usage Guide](USAGE.md)
- [API Reference](API.md)
- [Configuration Guide](CONFIGURATION.md)
