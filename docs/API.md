# API Reference - Java Code Security Audit Plugin

## Table of Contents

- [Overview](#overview)
- [JarAnalyzer API](#jaranalyzer-api)
- [SentryAgent API](#sentryagent-api)
- [ReportGenerator API](#reportgenerator-api)
- [Decompiler API](#decompiler-api)
- [Type Definitions](#type-definitions)
- [Vulnerability Types](#vulnerability-types)
- [Error Handling](#error-handling)

## Overview

The Code Security Audit Plugin provides a modular API architecture with three main components:

1. **JarAnalyzer**: JAR file structure analysis
2. **SentryAgent**: Security vulnerability orchestration
3. **ReportGenerator**: Multi-format report generation

All APIs are Promise-based and designed for async/await usage.

## JarAnalyzer API

### Class: `JarAnalyzer`

Analyzes JAR file structure, extracts metadata, detects frameworks, and identifies attack entry points.

#### Constructor

```typescript
new JarAnalyzer(options?: AnalyzerOptions)
```

#### Methods

##### `analyze(jarPath: string): Promise<JarAnalysisResult>`

Analyzes a JAR file and returns comprehensive metadata.

**Parameters:**
- `jarPath` (string): Absolute or relative path to the JAR file

**Returns:** `Promise<JarAnalysisResult>`

**Example:**
```typescript
import { JarAnalyzer } from 'code-security-audit'

const analyzer = new JarAnalyzer({
  includeInnerClasses: true,
  maxEntryPoints: 100
})

try {
  const result = await analyzer.analyze('./target/app.jar')
  console.log(`Framework: ${result.framework.type}`)
  console.log(`Dependencies: ${result.dependencies.length}`)
} catch (error) {
  console.error('Analysis failed:', error.message)
}
```

**Error Cases:**
- File not found
- Invalid JAR format
- Permission denied
- Out of memory

### AnalyzerOptions

Configuration options for JarAnalyzer.

| Property | Type | Default | Description |
|----------|------|---------|-------------|
| `includeInnerClasses` | `boolean` | `true` | Include inner/anonymous classes in analysis |
| `maxEntryPoints` | `number` | `100` | Maximum number of entry points to extract |
| `riskThreshold` | `number` | `0` | Minimum risk score threshold (0-100) |

```typescript
interface AnalyzerOptions {
  includeInnerClasses?: boolean
  maxEntryPoints?: number
  riskThreshold?: number
}
```

### JarAnalysisResult

Complete analysis result for a JAR file.

```typescript
interface JarAnalysisResult {
  manifest: JarManifest           // JAR manifest information
  framework: DetectedFramework    // Detected framework type
  entryPoints: AttackEntry[]      // Attack surface entry points
  dependencies: Dependency[]      // Maven dependencies
  configFiles: ConfigFile[]       // Configuration files
  riskScore: number               // Calculated risk score (0-100)
}
```

#### JarManifest

```typescript
interface JarManifest {
  mainClass?: string              // Main-Class entry
  version?: string                // Implementation-Version
  implementationTitle?: string    // Implementation-Title
  implementationVersion?: string  // Implementation-Version
}
```

#### DetectedFramework

```typescript
interface DetectedFramework {
  type: 'spring-boot' | 'spring-mvc' | 'struts2' | 'servlet' | 'unknown'
  version?: string
  indicators: string[]            // Detected framework indicators
}
```

#### AttackEntry

```typescript
interface AttackEntry {
  type: 'servlet' | 'controller' | 'listener' | 'filter' | 'websocket'
  className: string
  methodName: string
  urlPattern?: string
  httpMethods: string[]
  parameters: ParameterInfo[]
  riskLevel: 'critical' | 'high' | 'medium' | 'low'
}
```

#### ParameterInfo

```typescript
interface ParameterInfo {
  name: string
  type: string
  annotation?: string
  source: 'query' | 'path' | 'body' | 'header' | 'cookie' | 'form'
}
```

#### Dependency

```typescript
interface Dependency {
  groupId: string
  artifactId: string
  version: string
  isVulnerable: boolean
  knownVulnerabilities?: string[]
}
```

#### ConfigFile

```typescript
interface ConfigFile {
  path: string
  type: 'xml' | 'yaml' | 'properties'
  content: string
}
```

## SentryAgent API

### Class: `SentryAgent`

Orchestrates multiple security scanning agents in parallel or serial mode.

#### Constructor

```typescript
new SentryAgent(options?: SentryAgentOptions)
```

#### Methods

##### `orchestrate(jarPath: string, jarAnalysis: JarAnalysisResult, decompiledSources: Map<string, DecompileResult>): Promise<ScanResult>`

Runs all security agents against the decompiled sources.

**Parameters:**
- `jarPath` (string): Path to JAR file being scanned
- `jarAnalysis` (JarAnalysisResult): Result from JarAnalyzer
- `decompiledSources` (Map<string, DecompileResult>): Map of class names to decompiled source

**Returns:** `Promise<ScanResult>`

**Example:**
```typescript
import { SentryAgent } from 'code-security-audit'
import type { JarAnalysisResult, DecompileResult } from 'code-security-audit'

const sentry = new SentryAgent({
  parallelExecution: true,
  maxConcurrency: 5,
  enableDeduplication: true,
  severityThreshold: 'medium'
})

const jarAnalysis: JarAnalysisResult = /* ... */
const decompiledSources: Map<string, DecompileResult> = /* ... */

const scanResult = await sentry.orchestrate(
  './app.jar',
  jarAnalysis,
  decompiledSources
)

console.log(`Found ${scanResult.summary.totalVulnerabilities} vulnerabilities`)
```

### SentryAgentOptions

| Property | Type | Default | Description |
|----------|------|---------|-------------|
| `parallelExecution` | `boolean` | `true` | Run agents in parallel |
| `maxConcurrency` | `number` | `5` | Maximum concurrent agents |
| `enableDeduplication` | `boolean` | `true` | Remove duplicate vulnerabilities |
| `severityThreshold` | `'critical' \| 'high' \| 'medium' \| 'low'` | `'low'` | Minimum severity to report |

```typescript
interface SentryAgentOptions {
  parallelExecution?: boolean
  maxConcurrency?: number
  enableDeduplication?: boolean
  severityThreshold?: 'critical' | 'high' | 'medium' | 'low'
}
```

### ScanResult

```typescript
interface ScanResult {
  vulnerabilities: Vulnerability[]
  summary: ScanSummary
  metadata: ScanMetadata
}
```

#### ScanSummary

```typescript
interface ScanSummary {
  totalVulnerabilities: number
  criticalCount: number
  highCount: number
  mediumCount: number
  lowCount: number
  scanDuration: number      // Milliseconds
  filesScanned: number
  agentsExecuted: number
}
```

#### ScanMetadata

```typescript
interface ScanMetadata {
  jarPath: string
  scanStartTime: Date
  scanEndTime: Date
  framework: string
  entryPointsCount: number
}
```

## ReportGenerator API

### Class: `ReportGenerator`

Generates security audit reports in multiple formats.

#### Constructor

```typescript
new ReportGenerator(options?: ReportOptions)
```

#### Methods

##### `generateConsoleReport(scanResult: ScanResult): Promise<string>`

Generates a formatted console/terminal report.

**Returns:** Formatted string with emojis and alignment

##### `generateJSONReport(scanResult: ScanResult): Promise<string>`

Generates a JSON report suitable for parsing.

**Returns:** JSON string (prettified with 2-space indentation)

##### `generateHTMLReport(scanResult: ScanResult): Promise<string>`

Generates an HTML report with styling.

**Returns:** Complete HTML document string

##### `generateMarkdownReport(scanResult: ScanResult): Promise<string>`

Generates a Markdown report.

**Returns:** Markdown formatted string

**Example:**
```typescript
import { ReportGenerator } from 'code-security-audit'
import type { ScanResult } from 'code-security-audit'

const reporter = new ReportGenerator({
  includeEvidence: true,
  includeRemediation: true,
  includeCodeExamples: true,
  severityFilter: ['critical', 'high', 'medium']
})

const scanResult: ScanResult = /* ... */

// Generate all formats
const consoleReport = await reporter.generateConsoleReport(scanResult)
const jsonReport = await reporter.generateJSONReport(scanResult)
const htmlReport = await reporter.generateHTMLReport(scanResult)
const markdownReport = await reporter.generateMarkdownReport(scanResult)

// Save to files
await Bun.write('report.html', htmlReport)
await Bun.write('report.md', markdownReport)
```

### ReportOptions

| Property | Type | Default | Description |
|----------|------|---------|-------------|
| `includeEvidence` | `boolean` | `true` | Include vulnerability evidence |
| `includeRemediation` | `boolean` | `true` | Include fix recommendations |
| `includeCodeExamples` | `boolean` | `true` | Include safe code examples |
| `severityFilter` | `('critical' \| 'high' \| 'medium' \| 'low')[]` | All | Filter vulnerabilities by severity |

```typescript
interface ReportOptions {
  includeEvidence?: boolean
  includeRemediation?: boolean
  includeCodeExamples?: boolean
  severityFilter?: ('critical' | 'high' | 'medium' | 'low')[]
}
```

## Decompiler API

### Class: `DecompileManager`

Manages Java class decompilation with caching support.

#### Constructor

```typescript
new DecompileManager(engine: DecompilerEngine, cacheDir?: string)
```

#### Methods

##### `decompileClass(jarPath: string, className: string, options?: DecompileOptions): Promise<DecompileResult>`

Decompiles a single class from a JAR file.

##### `decompileBatch(jarPath: string, classNames: string[], options?: DecompileOptions, batchSize?: number): Promise<DecompileResult[]>`

Decompiles multiple classes in batches.

##### `decompileCriticalClasses(jarPath: string, entryPoints: AttackEntry[], options?: DecompileOptions): Promise<Map<string, DecompileResult>>`

Intelligently decompiles only critical/high-risk classes.

**Example:**
```typescript
import { DecompileManager } from 'code-security-audit/decompiler'
import { CFRDecompiler } from 'code-security-audit/decompiler'

const engine = new CFRDecompiler()
const manager = new DecompileManager(engine, '.security-audit/cache')

// Decompile single class
const result = await manager.decompileClass('./app.jar', 'com.example.UserController')

// Decompile in batch
const results = await manager.decompileBatch(
  './app.jar',
  ['UserController', 'OrderService', 'PaymentGateway'],
  { includeLineNumbers: true },
  5
)
```

### DecompileOptions

```typescript
interface DecompileOptions {
  includeLineNumbers?: boolean
  includeImports?: boolean
  timeout?: number
}
```

### DecompileResult

```typescript
interface DecompileResult {
  className: string
  sourceCode: string
  packageName: string
  imports: string[]
  methods: MethodInfo[]
  fields: FieldInfo[]
  isSuccess: boolean
  error?: string
  decompileTime: number
  cacheHit: boolean
}
```

## Type Definitions

### Severity Enum

```typescript
enum Severity {
  CRITICAL = 'critical',
  HIGH = 'high',
  MEDIUM = 'medium',
  LOW = 'low'
}
```

### VulnerabilityType Enum

```typescript
enum VulnerabilityType {
  SQL_INJECTION = 'SQL_INJECTION',
  SSRF = 'SSRF',
  RCE = 'RCE',
  XSS = 'XSS',
  XXE = 'XXE',
  AUTH_BYPASS = 'AUTH_BYPASS',
  IDOR = 'IDOR',
  HARDCODED_CREDENTIALS = 'HARDCODED_CREDENTIALS',
  BUSINESS_LOGIC = 'BUSINESS_LOGIC',
  JWT_NONE_ALGORITHM = 'JWT_NONE_ALGORITHM',
  JWT_WEAK_SECRET = 'JWT_WEAK_SECRET'
}
```

### Vulnerability Interface

```typescript
interface Vulnerability {
  id: string
  type: VulnerabilityType
  cwe: string
  owasp: string
  severity: Severity
  title: string
  description: string
  location: {
    className: string
    methodName: string
    lineNumber: number
    codeSnippet: string
  }
  evidence: {
    sourceFlow?: string[]
    sinkFlow?: string[]
  }
  remediation: {
    description: string
    codeExample?: string
    references: string[]
  }
}
```

## Vulnerability Types

The following vulnerability types are detected by the built-in agents:

| Type | Agent | CWE | OWASP Category |
|------|-------|-----|----------------|
| SQL_INJECTION | SQLInjectionAgent | CWE-89 | A03:2021 - Injection |
| SSRF | SSRFAgent | CWE-918 | A10:2021 - SSRF |
| RCE | RCEAgent | CWE-78 | A03:2021 - Injection |
| XSS | XSSAgent | CWE-79 | A03:2021 - Injection |
| XXE | XXEAgent | CWE-611 | A05:2021 - Security Misconfiguration |
| AUTH_BYPASS | AuthAnalyzerAgent | CWE-287 | A07:2021 - Auth Failure |
| IDOR | AuthAnalyzerAgent | CWE-639 | A01:2021 - Broken Access Control |
| HARDCODED_CREDENTIALS | AuthAnalyzerAgent | CWE-798 | A07:2021 - Auth Failure |
| BUSINESS_LOGIC | BusinessLogicAgent | CWE-840 | A04:2021 - Insecure Design |
| JWT_NONE_ALGORITHM | AuthAnalyzerAgent | CWE-327 | A02:2021 - Crypto Failure |
| JWT_WEAK_SECRET | AuthAnalyzerAgent | CWE-326 | A02:2021 - Crypto Failure |

## Error Handling

All APIs throw typed errors that can be caught and handled:

```typescript
import { JarAnalyzer } from 'code-security-audit'

try {
  const analyzer = new JarAnalyzer()
  const result = await analyzer.analyze('./app.jar')
} catch (error) {
  if (error instanceof Error) {
    // Handle specific error types
    if (error.message.includes('Failed to analyze JAR')) {
      console.error('JAR file is corrupted or invalid')
    } else if (error.message.includes('Permission denied')) {
      console.error('Check file permissions')
    } else {
      console.error('Unexpected error:', error.message)
    }
  }
}
```

### Common Error Patterns

| Error Message | Cause | Solution |
|---------------|-------|----------|
| `Failed to analyze JAR` | Invalid/corrupted JAR | Verify file integrity |
| `Class not found in JAR` | Missing class file | Check JAR contents |
| `Out of memory` | Large JAR file | Reduce maxEntryPoints |
| `Permission denied` | File permissions | Check access rights |

---

**See Also:**
- [Usage Guide](USAGE.md) for practical examples
- [Configuration](CONFIGURATION.md) for advanced options
- [FAQ](FAQ.md) for common questions
