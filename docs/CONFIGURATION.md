# Configuration Guide - Java Code Security Audit Plugin

## Table of Contents

- [Overview](#overview)
- [Analyzer Configuration](#analyzer-configuration)
- [Sentry Agent Configuration](#sentry-agent-configuration)
- [Report Generator Configuration](#report-generator-configuration)
- [Decompiler Configuration](#decompiler-configuration)
- [Severity Levels](#severity-levels)
- [Performance Tuning](#performance-tuning)
- [Cache Settings](#cache-settings)
- [Configuration File](#configuration-file)
- [Environment Variables](#environment-variables)

## Overview

The Code Security Audit Plugin provides extensive configuration options to customize the scanning behavior for different use cases. All configuration is type-safe and validated at runtime.

## Analyzer Configuration

### AnalyzerOptions

Controls how the JAR analyzer processes files.

```typescript
interface AnalyzerOptions {
  includeInnerClasses?: boolean    // Default: true
  maxEntryPoints?: number          // Default: 100
  riskThreshold?: number           // Default: 0
}
```

### Option Details

#### `includeInnerClasses`

Determines whether to include inner and anonymous classes in the analysis.

```typescript
const analyzer = new JarAnalyzer({
  includeInnerClasses: true   // Include $1, $2 inner classes
})
```

**When to disable:**
- Large JAR files with many inner classes
- Performance-critical scenarios
- When only main classes are relevant

**Impact:**
- Enabled: More comprehensive analysis, slower
- Disabled: Faster analysis, may miss vulnerabilities in inner classes

#### `maxEntryPoints`

Limits the number of attack entry points to analyze.

```typescript
const analyzer = new JarAnalyzer({
  maxEntryPoints: 50   // Only analyze top 50 entry points
})
```

**Recommended values:**
- Small apps (< 10 controllers): 50
- Medium apps (10-50 controllers): 100
- Large apps (50+ controllers): 200

**Impact:**
- Lower values: Faster scanning, may miss edge cases
- Higher values: Slower, more comprehensive

#### `riskThreshold`

Minimum risk score for including an entry point.

```typescript
const analyzer = new JarAnalyzer({
  riskThreshold: 20   // Only entry points with score >= 20
})
```

**Risk score calculation:**
- Vulnerable dependencies: +20 per dependency
- Hardcoded passwords: +15
- Hardcoded secrets: +15
- Maximum: 100

## Sentry Agent Configuration

### SentryAgentOptions

Controls the security scanning orchestration.

```typescript
interface SentryAgentOptions {
  parallelExecution?: boolean                    // Default: true
  maxConcurrency?: number                        // Default: 5
  enableDeduplication?: boolean                  // Default: true
  severityThreshold?: 'critical' | 'high' | 'medium' | 'low'  // Default: 'low'
}
```

### Option Details

#### `parallelExecution`

Run multiple security agents in parallel.

```typescript
const sentry = new SentryAgent({
  parallelExecution: true   // Run SQL, SSRF, RCE agents simultaneously
})
```

**Agents executed:**
1. SQLInjectionAgent
2. SSRFAgent
3. RCEAgent
4. AuthAnalyzerAgent
5. BusinessLogicAgent

**When to disable:**
- Memory-constrained environments
- Debugging specific agents
- Deterministic execution needed

#### `maxConcurrency`

Maximum number of concurrent agent executions.

```typescript
const sentry = new SentryAgent({
  maxConcurrency: 3   // Limit to 3 concurrent agents
})
```

**Resource usage by concurrency:**

| Concurrency | Memory | CPU | Recommended For |
|-------------|--------|-----|-----------------|
| 1 | Low | Low | CI/CD, constrained env |
| 3 | Medium | Medium | Standard usage |
| 5 | High | High | High-performance machines |
| 10+ | Very High | Very High | Dedicated audit servers |

#### `enableDeduplication`

Remove duplicate vulnerabilities found by multiple agents.

```typescript
const sentry = new SentryAgent({
  enableDeduplication: true   // Remove duplicates
})
```

**Deduplication key:**
```
{type}-{className}-{methodName}-{lineNumber}
```

**Example duplicates:**
- Same SQL injection found by SQLInjectionAgent and BusinessLogicAgent
- Same auth bypass found by AuthAnalyzerAgent and RCEAgent

#### `severityThreshold`

Minimum severity level to include in results.

```typescript
const sentry = new SentryAgent({
  severityThreshold: 'high'   // Only high and critical
})
```

**Severity order:**
```
critical (4) > high (3) > medium (2) > low (1)
```

**Use cases:**
- `critical`: Production emergency scans
- `high`: CI/CD gate checks
- `medium`: Standard development scans
- `low`: Comprehensive audits

## Report Generator Configuration

### ReportOptions

Controls report content and formatting.

```typescript
interface ReportOptions {
  includeEvidence?: boolean                           // Default: true
  includeRemediation?: boolean                        // Default: true
  includeCodeExamples?: boolean                       // Default: true
  severityFilter?: ('critical' | 'high' | 'medium' | 'low')[]  // Default: all
}
```

### Option Details

#### `includeEvidence`

Include vulnerability evidence (source/sink flow).

```typescript
const reporter = new ReportGenerator({
  includeEvidence: true
})
```

**Evidence includes:**
- Source flow (where user input enters)
- Sink flow (where vulnerability executes)
- Data flow path

**Example:**
```
Evidence: request.getParameter("name") → String sql = "SELECT..." + name → executeQuery()
```

#### `includeRemediation`

Include fix recommendations.

```typescript
const reporter = new ReportGenerator({
  includeRemediation: true
})
```

**Remediation includes:**
- Description of the fix
- Secure code examples
- Reference links

#### `includeCodeExamples`

Include secure code examples in reports.

```typescript
const reporter = new ReportGenerator({
  includeCodeExamples: true
})
```

**Examples provided:**
- JDBC PreparedStatement usage
- MyBatis #{} vs ${} syntax
- JPA parameterized queries

#### `severityFilter`

Filter vulnerabilities by severity in reports.

```typescript
const reporter = new ReportGenerator({
  severityFilter: ['critical', 'high']   // Exclude medium and low
})
```

**Common filter combinations:**

| Use Case | Filter | Result |
|----------|--------|--------|
| Executive summary | `['critical']` | Only critical issues |
| Security review | `['critical', 'high']` | High priority items |
| Full audit | `['critical', 'high', 'medium', 'low']` | Everything |

## Decompiler Configuration

### DecompileOptions

Controls Java class decompilation behavior.

```typescript
interface DecompileOptions {
  includeLineNumbers?: boolean    // Default: true
  includeImports?: boolean        // Default: true
  timeout?: number                // Default: 30000 (30s)
}
```

### Option Details

#### `includeLineNumbers`

Include original line numbers in decompiled source.

```typescript
const options: DecompileOptions = {
  includeLineNumbers: true
}
```

**Benefits:**
- Accurate vulnerability location reporting
- Easier to map to original source

**Trade-off:**
- Slightly larger output

#### `includeImports`

Include import statements in decompiled source.

```typescript
const options: DecompileOptions = {
  includeImports: true
}
```

**Benefits:**
- Better context for analysis
- Framework detection accuracy

#### `timeout`

Maximum time (milliseconds) to spend decompiling a single class.

```typescript
const options: DecompileOptions = {
  timeout: 60000   // 60 seconds
}
```

**Recommendations:**
- Small classes: 10000ms
- Medium classes: 30000ms
- Large/obfuscated: 60000ms+

## Severity Levels

### Severity Definitions

| Level | Score | Description | Response Time |
|-------|-------|-------------|---------------|
| **Critical** | 4 | Exploitable, high impact | Immediate (24h) |
| **High** | 3 | Likely exploitable | Urgent (1 week) |
| **Medium** | 2 | Possible with conditions | Planned (1 month) |
| **Low** | 1 | Minimal risk | Next release |

### Severity Assignment

Agents assign severity based on:

1. **Exploitability**: How easy to exploit
2. **Impact**: Data loss, RCE, etc.
3. **Prevalence**: How common the pattern
4. **Context**: Framework, deployment, etc.

### Custom Severity Rules

```typescript
// Example: Upgrade all SQL injection to critical
function adjustSeverity(vuln: Vulnerability): Severity {
  if (vuln.type === VulnerabilityType.SQL_INJECTION) {
    return Severity.CRITICAL
  }
  return vuln.severity
}
```

## Performance Tuning

### Memory Optimization

```typescript
// For large JAR files (100MB+)
const config = {
  analyzer: {
    maxEntryPoints: 50,
    includeInnerClasses: false
  },
  sentry: {
    parallelExecution: true,
    maxConcurrency: 2,      // Reduce memory pressure
    enableDeduplication: true
  },
  decompiler: {
    timeout: 30000
  }
}
```

### Speed Optimization

```typescript
// For quick scans
const config = {
  analyzer: {
    maxEntryPoints: 20,     // Limit scope
    riskThreshold: 30       // Skip low-risk classes
  },
  sentry: {
    severityThreshold: 'high',  // Skip low/medium
    parallelExecution: true
  },
  report: {
    severityFilter: ['critical', 'high']
  }
}
```

### Accuracy Optimization

```typescript
// For comprehensive audits
const config = {
  analyzer: {
    maxEntryPoints: 500,    // Analyze everything
    includeInnerClasses: true,
    riskThreshold: 0
  },
  sentry: {
    severityThreshold: 'low',  // Include everything
    enableDeduplication: false  // Keep all findings
  },
  report: {
    includeEvidence: true,
    includeRemediation: true,
    includeCodeExamples: true
  }
}
```

## Cache Settings

### Decompile Cache

The decompiler uses two-level caching:

1. **Memory Cache**: In-memory Map for current session
2. **Disk Cache**: Persistent JSON files

#### Cache Configuration

```typescript
const manager = new DecompileManager(
  engine,
  '.security-audit/cache/decompile'   // Custom cache directory
)
```

#### Cache Statistics

```typescript
const stats = manager.getCacheStats()
console.log(`Memory cache: ${stats.memorySize} entries`)
```

#### Cache Invalidation

```typescript
// Clear memory cache
await manager.clearCache()

// Clear disk cache (manual)
rm -rf .security-audit/cache/decompile/*
```

### Cache Key Format

```
{jarFileName}:{className}
```

Example: `app.jar:com.example.UserController`

### Cache Location

| Platform | Default Path |
|----------|--------------|
| Linux/macOS | `./.security-audit/cache/decompile` |
| Windows | `.\security-audit\cache\decompile` |

## Configuration File

### JSON Configuration

Create a `security-audit.json` file:

```json
{
  "analyzer": {
    "includeInnerClasses": true,
    "maxEntryPoints": 100,
    "riskThreshold": 0
  },
  "sentry": {
    "parallelExecution": true,
    "maxConcurrency": 5,
    "enableDeduplication": true,
    "severityThreshold": "medium"
  },
  "report": {
    "includeEvidence": true,
    "includeRemediation": true,
    "includeCodeExamples": true,
    "severityFilter": ["critical", "high", "medium"]
  },
  "decompiler": {
    "includeLineNumbers": true,
    "includeImports": true,
    "timeout": 30000
  },
  "cache": {
    "enabled": true,
    "directory": ".security-audit/cache"
  }
}
```

### Loading Configuration

```typescript
import { readFileSync } from 'fs'

const config = JSON.parse(
  readFileSync('./security-audit.json', 'utf-8')
)

const analyzer = new JarAnalyzer(config.analyzer)
const sentry = new SentryAgent(config.sentry)
const reporter = new ReportGenerator(config.report)
```

### Environment-Specific Configs

```typescript
// config/development.ts
export const devConfig = {
  sentry: { severityThreshold: 'low' },
  report: { severityFilter: ['critical', 'high', 'medium', 'low'] }
}

// config/production.ts
export const prodConfig = {
  sentry: { severityThreshold: 'high' },
  report: { severityFilter: ['critical', 'high'] }
}

// Load based on NODE_ENV
const config = process.env.NODE_ENV === 'production' 
  ? prodConfig 
  : devConfig
```

## Environment Variables

### Supported Variables

| Variable | Type | Default | Description |
|----------|------|---------|-------------|
| `AUDIT_CACHE_DIR` | string | `.security-audit/cache` | Cache directory path |
| `AUDIT_MAX_CONCURRENCY` | number | `5` | Max concurrent agents |
| `AUDIT_SEVERITY_THRESHOLD` | string | `low` | Minimum severity |
| `AUDIT_TIMEOUT` | number | `30000` | Decompile timeout (ms) |
| `AUDIT_DEBUG` | boolean | `false` | Enable debug logging |
| `AUDIT_REPORT_FORMAT` | string | `console` | Default report format |

### Usage

```bash
# Set environment variables
export AUDIT_CACHE_DIR=/tmp/security-cache
export AUDIT_MAX_CONCURRENCY=3
export AUDIT_SEVERITY_THRESHOLD=high
export AUDIT_DEBUG=true

# Run scan
bun run scan ./app.jar
```

### Reading in Code

```typescript
const config = {
  cacheDir: process.env.AUDIT_CACHE_DIR || '.security-audit/cache',
  maxConcurrency: parseInt(process.env.AUDIT_MAX_CONCURRENCY || '5'),
  severityThreshold: (process.env.AUDIT_SEVERITY_THRESHOLD || 'low') as Severity,
  debug: process.env.AUDIT_DEBUG === 'true'
}
```

---

**See Also:**
- [Usage Guide](USAGE.md) for practical examples
- [API Reference](API.md) for complete API documentation
- [FAQ](FAQ.md) for common questions
