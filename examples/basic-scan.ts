#!/usr/bin/env bun
/**
 * Basic Scan Example - Java Code Security Audit Plugin
 * 
 * This example demonstrates the basic usage of the plugin
 * for scanning a single JAR file with default settings.
 * 
 * Usage:
 *   bun run examples/basic-scan.ts ./path/to/app.jar
 */

import { JarAnalyzer } from '../src/tools/jar-analyzer/index'
import { SentryAgent } from '../src/agents/sentry/index'
import { ReportGenerator } from '../src/hooks/report-generator/index'
import { DecompileManager } from '../src/tools/decompiler/manager'
import { CFRDecompiler } from '../src/tools/decompiler/cfr'
import type { JarAnalysisResult } from '../src/types/index'
import type { DecompileResult } from '../src/tools/decompiler/types'
import type { ScanResult } from '../src/agents/sentry/types'

async function basicScan(jarPath: string): Promise<void> {
  console.log('🔒 Java Code Security Audit - Basic Scan')
  console.log('=' .repeat(50))
  console.log(`Target: ${jarPath}\n`)

  const startTime = Date.now()

  try {
    // Step 1: Analyze JAR structure
    console.log('📦 Step 1: Analyzing JAR structure...')
    const analyzer = new JarAnalyzer({
      includeInnerClasses: true,
      maxEntryPoints: 50
    })
    
    const jarAnalysis: JarAnalysisResult = await analyzer.analyze(jarPath)
    
    console.log(`  ✅ Framework: ${jarAnalysis.framework.type}`)
    console.log(`  ✅ Entry Points: ${jarAnalysis.entryPoints.length}`)
    console.log(`  ✅ Dependencies: ${jarAnalysis.dependencies.length}`)
    console.log(`  ✅ Risk Score: ${jarAnalysis.riskScore}/100\n`)

    // Step 2: Decompile critical classes
    console.log('🔍 Step 2: Decompiling critical classes...')
    const decompiler = new CFRDecompiler()
    const decompileManager = new DecompileManager(
      decompiler,
      '.security-audit/cache/decompile'
    )
    
    const decompiledSources: Map<string, DecompileResult> = 
      await decompileManager.decompileCriticalClasses(
        jarPath,
        jarAnalysis.entryPoints,
        { includeLineNumbers: true, includeImports: true }
      )
    
    console.log(`  ✅ Decompiled ${decompiledSources.size} classes\n`)

    // Step 3: Run security scan
    console.log('🛡️  Step 3: Running security scan...')
    const sentry = new SentryAgent({
      parallelExecution: true,
      maxConcurrency: 3,
      enableDeduplication: true,
      severityThreshold: 'low'
    })
    
    const scanResult: ScanResult = await sentry.orchestrate(
      jarPath,
      jarAnalysis,
      decompiledSources
    )
    
    console.log(`  ✅ Scan complete\n`)

    // Step 4: Generate report
    console.log('📊 Step 4: Generating report...')
    const reporter = new ReportGenerator({
      includeEvidence: true,
      includeRemediation: true,
      includeCodeExamples: true,
      severityFilter: ['critical', 'high', 'medium', 'low']
    })
    
    // Console report
    const consoleReport = await reporter.generateConsoleReport(scanResult)
    console.log('\n' + consoleReport)
    
    // Also save JSON report
    const jsonReport = await reporter.generateJSONReport(scanResult)
    const reportPath = `./security-report-${Date.now()}.json`
    await Bun.write(reportPath, jsonReport)
    console.log(`📄 JSON report saved to: ${reportPath}`)

    // Summary
    const duration = Date.now() - startTime
    console.log('\n' + '='.repeat(50))
    console.log('📈 Scan Summary')
    console.log('='.repeat(50))
    console.log(`⏱️  Total Duration: ${duration}ms`)
    console.log(`🐛 Total Vulnerabilities: ${scanResult.summary.totalVulnerabilities}`)
    console.log(`🔴 Critical: ${scanResult.summary.criticalCount}`)
    console.log(`🟠 High: ${scanResult.summary.highCount}`)
    console.log(`🟡 Medium: ${scanResult.summary.mediumCount}`)
    console.log(`🔵 Low: ${scanResult.summary.lowCount}`)
    
    // Exit code based on findings
    if (scanResult.summary.criticalCount > 0) {
      console.log('\n❌ Critical vulnerabilities found!')
      process.exit(1)
    } else if (scanResult.summary.highCount > 0) {
      console.log('\n⚠️  High severity vulnerabilities found!')
      process.exit(2)
    } else {
      console.log('\n✅ No critical or high severity vulnerabilities found!')
      process.exit(0)
    }

  } catch (error) {
    console.error('\n❌ Scan failed:', error instanceof Error ? error.message : String(error))
    process.exit(1)
  }
}

// Main entry point
const jarPath = process.argv[2]

if (!jarPath) {
  console.error('Usage: bun run examples/basic-scan.ts <path-to-jar>')
  console.error('Example: bun run examples/basic-scan.ts ./target/app.jar')
  process.exit(1)
}

basicScan(jarPath)
