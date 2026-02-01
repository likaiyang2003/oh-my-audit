#!/usr/bin/env bun
/**
 * Advanced Scan Example - Java Code Security Audit Plugin
 * 
 * This example demonstrates advanced features:
 * - Custom configuration
 * - Batch scanning multiple JARs
 * - Custom filtering and post-processing
 * - Integration with external systems
 * - Export to multiple formats
 * 
 * Usage:
 *   bun run examples/advanced-scan.ts ./target
 */

import { JarAnalyzer } from '../src/tools/jar-analyzer/index'
import { SentryAgent } from '../src/agents/sentry/index'
import { ReportGenerator } from '../src/hooks/report-generator/index'
import { DecompileManager } from '../src/tools/decompiler/manager'
import { CFRDecompiler } from '../src/tools/decompiler/cfr'
import { SQLInjectionAgent } from '../src/agents/sql-injector/index'
import { SSRFAgent } from '../src/agents/ssrf-hunter/index'
import type { 
  JarAnalysisResult, 
  Vulnerability,
  Severity 
} from '../src/types/index'
import type { DecompileResult } from '../src/tools/decompiler/types'
import type { ScanResult } from '../src/agents/sentry/types'
import { Severity as SeverityEnum } from '../src/types/index'

interface ScanConfig {
  minSeverity: 'critical' | 'high' | 'medium' | 'low'
  maxEntryPoints: number
  parallelAgents: boolean
  maxConcurrency: number
  includeInnerClasses: boolean
  outputFormats: ('console' | 'json' | 'html' | 'markdown')[]
  excludePatterns: RegExp[]
  customRules: boolean
}

interface BatchScanResult {
  jarPath: string
  scanResult: ScanResult
  duration: number
  success: boolean
  error?: string
}

class AdvancedSecurityScanner {
  private config: ScanConfig
  private analyzer: JarAnalyzer
  private sentry: SentryAgent
  private reporter: ReportGenerator
  private decompiler: CFRDecompiler
  private decompileManager: DecompileManager

  constructor(config: Partial<ScanConfig> = {}) {
    this.config = {
      minSeverity: config.minSeverity || 'medium',
      maxEntryPoints: 100,
      parallelAgents: true,
      maxConcurrency: 5,
      includeInnerClasses: false,
      outputFormats: ['console', 'json', 'html'],
      excludePatterns: [/Test\.class$/, /Mock.*\.class$/],
      customRules: true,
      ...config
    }

    // Initialize components with custom configuration
    this.analyzer = new JarAnalyzer({
      includeInnerClasses: this.config.includeInnerClasses,
      maxEntryPoints: this.config.maxEntryPoints
    })

    this.sentry = new SentryAgent({
      parallelExecution: this.config.parallelAgents,
      maxConcurrency: this.config.maxConcurrency,
      enableDeduplication: true,
      severityThreshold: this.config.minSeverity
    })

    this.reporter = new ReportGenerator({
      includeEvidence: true,
      includeRemediation: true,
      includeCodeExamples: true,
      severityFilter: this.getSeverityFilter()
    })

    this.decompiler = new CFRDecompiler()
    this.decompileManager = new DecompileManager(
      this.decompiler,
      '.security-audit/cache/advanced'
    )
  }

  private getSeverityFilter(): ('critical' | 'high' | 'medium' | 'low')[] {
    const allSeverities: ('critical' | 'high' | 'medium' | 'low')[] = 
      ['critical', 'high', 'medium', 'low']
    
    const minIndex = allSeverities.indexOf(this.config.minSeverity)
    return allSeverities.slice(0, minIndex + 1)
  }

  async scanSingleJar(jarPath: string): Promise<ScanResult> {
    const jarAnalysis = await this.analyzer.analyze(jarPath)
    
    // Filter entry points based on exclude patterns
    const filteredEntries = jarAnalysis.entryPoints.filter(entry => {
      return !this.config.excludePatterns.some(pattern => 
        pattern.test(entry.className)
      )
    })

    jarAnalysis.entryPoints = filteredEntries

    const decompiledSources = await this.decompileManager.decompileCriticalClasses(
      jarPath,
      jarAnalysis.entryPoints,
      { includeLineNumbers: true }
    )

    // If custom rules enabled, run additional checks
    if (this.config.customRules) {
      return await this.scanWithCustomRules(jarPath, jarAnalysis, decompiledSources)
    }

    return await this.sentry.orchestrate(jarPath, jarAnalysis, decompiledSources)
  }

  private async scanWithCustomRules(
    jarPath: string,
    jarAnalysis: JarAnalysisResult,
    decompiledSources: Map<string, DecompileResult>
  ): Promise<ScanResult> {
    // Run standard sentry scan
    const standardResult = await this.sentry.orchestrate(
      jarPath, 
      jarAnalysis, 
      decompiledSources
    )

    // Run custom SQL injection agent with strict mode
    const sqlAgent = new SQLInjectionAgent({
      strictMode: true,
      includeMyBatisXML: true
    })
    
    const sqlVulns = await sqlAgent.audit(
      jarPath,
      jarAnalysis.entryPoints,
      decompiledSources
    )

    // Run SSRF agent with extended checks
    const ssrfAgent = new SSRFAgent()
    const ssrfVulns = await ssrfAgent.audit(
      jarPath,
      jarAnalysis.entryPoints,
      decompiledSources
    )

    // Merge and deduplicate
    const allVulns = [...standardResult.vulnerabilities, ...sqlVulns, ...ssrfVulns]
    const uniqueVulns = this.deduplicateVulnerabilities(allVulns)

    return {
      ...standardResult,
      vulnerabilities: uniqueVulns,
      summary: {
        ...standardResult.summary,
        totalVulnerabilities: uniqueVulns.length
      }
    }
  }

  private deduplicateVulnerabilities(vulns: Vulnerability[]): Vulnerability[] {
    const seen = new Set<string>()
    return vulns.filter(vuln => {
      const key = `${vuln.type}-${vuln.location.className}-${vuln.location.lineNumber}`
      if (seen.has(key)) return false
      seen.add(key)
      return true
    })
  }

  async batchScan(directory: string): Promise<BatchScanResult[]> {
    // Find all JAR files
    const jarPattern = new URL(`file://${directory}/**/*.jar`)
    const glob = new Bun.Glob('**/*.jar')
    const jarFiles: string[] = []
    
    for await (const file of glob.scan({
      absolute: true,
      cwd: directory
    })) {
      jarFiles.push(file)
    }

    console.log(`🔍 Found ${jarFiles.length} JAR files to scan\n`)

    const results: BatchScanResult[] = []

    for (const jarPath of jarFiles) {
      const startTime = Date.now()
      
      try {
        console.log(`📦 Scanning: ${jarPath}`)
        const scanResult = await this.scanSingleJar(jarPath)
        const duration = Date.now() - startTime

        results.push({
          jarPath,
          scanResult,
          duration,
          success: true
        })

        console.log(`  ✅ Complete in ${duration}ms - ${scanResult.summary.totalVulnerabilities} issues\n`)
      } catch (error) {
        const duration = Date.now() - startTime
        results.push({
          jarPath,
          scanResult: null as any,
          duration,
          success: false,
          error: error instanceof Error ? error.message : String(error)
        })

        console.log(`  ❌ Failed: ${error instanceof Error ? error.message : String(error)}\n`)
      }
    }

    return results
  }

  async generateReports(scanResult: ScanResult, basePath: string): Promise<string[]> {
    const generatedFiles: string[] = []
    const timestamp = Date.now()

    for (const format of this.config.outputFormats) {
      let content: string
      let extension: string

      switch (format) {
        case 'console':
          content = await this.reporter.generateConsoleReport(scanResult)
          console.log(content)
          continue
        case 'json':
          content = await this.reporter.generateJSONReport(scanResult)
          extension = 'json'
          break
        case 'html':
          content = await this.reporter.generateHTMLReport(scanResult)
          extension = 'html'
          break
        case 'markdown':
          content = await this.reporter.generateMarkdownReport(scanResult)
          extension = 'md'
          break
      }

      const filePath = `${basePath}/security-report-${timestamp}.${extension}`
      await Bun.write(filePath, content)
      generatedFiles.push(filePath)
    }

    return generatedFiles
  }

  async uploadToDashboard(result: ScanResult, jarPath: string): Promise<void> {
    // Example: Upload to security dashboard API
    const payload = {
      timestamp: new Date().toISOString(),
      jarPath,
      summary: result.summary,
      vulnerabilities: result.vulnerabilities.map(v => ({
        id: v.id,
        type: v.type,
        severity: v.severity,
        title: v.title,
        cwe: v.cwe,
        owasp: v.owasp,
        location: v.location
      }))
    }

    console.log('📤 Would upload to dashboard:', JSON.stringify(payload, null, 2))
    
    // Actual implementation:
    // await fetch('https://dashboard.company.com/api/security-scans', {
    //   method: 'POST',
    //   headers: { 'Content-Type': 'application/json', 'Authorization': 'Bearer token' },
    //   body: JSON.stringify(payload)
    // })
  }

  generateAggregateReport(results: BatchScanResult[]): string {
    let totalVulns = 0
    let totalCritical = 0
    let totalHigh = 0
    let totalDuration = 0
    let successCount = 0

    for (const result of results) {
      if (result.success) {
        totalVulns += result.scanResult.summary.totalVulnerabilities
        totalCritical += result.scanResult.summary.criticalCount
        totalHigh += result.scanResult.summary.highCount
        totalDuration += result.duration
        successCount++
      }
    }

    return `
╔════════════════════════════════════════════════════════╗
║         Advanced Security Audit - Aggregate Report     ║
╚════════════════════════════════════════════════════════╝

Scanned JARs:    ${results.length}
Successful:      ${successCount}
Failed:          ${results.length - successCount}
Total Duration:  ${totalDuration}ms

VULNERABILITY SUMMARY
═════════════════════
Total:           ${totalVulns}
Critical:        ${totalCritical} 🔴
High:            ${totalHigh} 🟠

Per-JAR Breakdown:
${results.map(r => `  ${r.success ? '✅' : '❌'} ${r.jarPath.split('/').pop()}: ${r.success ? r.scanResult.summary.totalVulnerabilities + ' issues' : 'FAILED'}`).join('\n')}

Recommendations:
${totalCritical > 0 ? '🔴 Address critical vulnerabilities immediately!' : '✅ No critical vulnerabilities found'}
${totalHigh > 5 ? '🟠 Review high severity issues before deployment' : ''}
`
  }
}

// Main execution
async function main(): Promise<void> {
  const targetPath = process.argv[2]

  if (!targetPath) {
    console.error('Usage: bun run examples/advanced-scan.ts <directory-or-jar>')
    console.error('Example: bun run examples/advanced-scan.ts ./target')
    console.error('Example: bun run examples/advanced-scan.ts ./target/app.jar')
    process.exit(1)
  }

  console.log('🔒 Advanced Security Audit\n')

  // Create scanner with custom configuration
  const scanner = new AdvancedSecurityScanner({
    minSeverity: 'medium' as const,
    maxEntryPoints: 75,
    parallelAgents: true,
    maxConcurrency: 3,
    outputFormats: ['console', 'json', 'html'],
    excludePatterns: [/Test.*\.class$/, /.*Spec\.class$/],
    customRules: true
  })

  // Check if target is file or directory
  const isDirectory = await Bun.file(targetPath).exists() === false ||
    (await Bun.file(targetPath).stat())?.isDirectory()

  if (isDirectory) {
    // Batch scan
    console.log(`📁 Batch scanning directory: ${targetPath}\n`)
    const results = await scanner.batchScan(targetPath)
    
    // Generate aggregate report
    console.log(scanner.generateAggregateReport(results))

    // Generate individual reports for each JAR
    for (const result of results) {
      if (result.success) {
        const reportFiles = await scanner.generateReports(
          result.scanResult,
          targetPath
        )
        console.log(`📄 Reports saved: ${reportFiles.join(', ')}`)
      }
    }

    // Check if any critical vulnerabilities found
    const hasCritical = results.some(r => 
      r.success && r.scanResult.summary.criticalCount > 0
    )

    process.exit(hasCritical ? 1 : 0)
  } else {
    // Single JAR scan
    console.log(`📦 Scanning: ${targetPath}\n`)
    const scanResult = await scanner.scanSingleJar(targetPath)
    
    // Generate reports
    const reportFiles = await scanner.generateReports(scanResult, './')
    console.log(`\n📄 Reports saved:`)
    reportFiles.forEach(f => console.log(`   - ${f}`))

    // Upload to dashboard (example)
    await scanner.uploadToDashboard(scanResult, targetPath)

    // Exit based on severity
    if (scanResult.summary.criticalCount > 0) {
      console.log('\n❌ Critical vulnerabilities found!')
      process.exit(1)
    } else if (scanResult.summary.highCount > 3) {
      console.log('\n⚠️  Multiple high severity vulnerabilities found!')
      process.exit(2)
    } else {
      console.log('\n✅ Scan completed successfully!')
      process.exit(0)
    }
  }
}

main().catch(error => {
  console.error('Fatal error:', error)
  process.exit(1)
})
