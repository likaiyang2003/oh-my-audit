import { JarAnalyzer } from '../tools/jar-analyzer'
import { DecompileManager, CFRDecompiler } from '../tools/decompiler'
import { SentryAgent } from '../agents/sentry'
import { ReportGenerator } from '../hooks/report-generator'
import type { AuditWorkflowOptions, AuditWorkflowResult } from './types'

/**
 * Run complete audit workflow from JAR to reports
 */
export async function runAuditWorkflow(options: AuditWorkflowOptions): Promise<AuditWorkflowResult> {
  const startTime = performance.now()
  
  try {
    // Initialize components
    const jarAnalyzer = new JarAnalyzer()
    const cfrEngine = new CFRDecompiler()
    const decompilerManager = new DecompileManager(cfrEngine)
    const sentryAgent = new SentryAgent({
      severityThreshold: options.severityThreshold || 'low'
    })
    const reportGenerator = new ReportGenerator()
    
    // Step 1: Analyze JAR
    const jarAnalysis = await jarAnalyzer.analyze(options.jarPath)
    
    // Step 2: Decompile critical classes
    const decompiledSources = await decompilerManager.decompileCriticalClasses(
      options.jarPath,
      jarAnalysis.entryPoints,
      { includeLineNumbers: true }
    )
    
    // Step 3: Run security scan
    const scanResult = await sentryAgent.orchestrate(
      options.jarPath,
      jarAnalysis,
      decompiledSources
    )
    
    // Step 4: Generate reports
    const reports: AuditWorkflowResult['reports'] = {}
    const formats = options.reportFormats || ['console']
    
    for (const format of formats) {
      switch (format) {
        case 'console':
          reports.console = await reportGenerator.generateConsoleReport(scanResult)
          break
        case 'json':
          reports.json = await reportGenerator.generateJSONReport(scanResult)
          break
        case 'html':
          reports.html = await reportGenerator.generateHTMLReport(scanResult)
          break
        case 'markdown':
          reports.markdown = await reportGenerator.generateMarkdownReport(scanResult)
          break
      }
    }
    
    const executionTime = performance.now() - startTime
    
    return {
      scanResult,
      reports,
      executionTime,
      success: true
    }
  } catch (error) {
    const executionTime = performance.now() - startTime
    return {
      scanResult: {
        vulnerabilities: [],
        summary: {
          totalVulnerabilities: 0,
          criticalCount: 0,
          highCount: 0,
          mediumCount: 0,
          lowCount: 0,
          scanDuration: executionTime,
          filesScanned: 0,
          agentsExecuted: 0
        },
        metadata: {
          jarPath: options.jarPath,
          scanStartTime: new Date(),
          scanEndTime: new Date(),
          framework: 'unknown',
          entryPointsCount: 0
        }
      },
      reports: {},
      executionTime,
      success: false,
      error: error instanceof Error ? error.message : String(error)
    }
  }
}
