/**
 * Code Security Audit Plugin for OpenCode
 * 
 * This plugin provides comprehensive Java security auditing capabilities:
 * - JAR file analysis and decompilation
 * - Vulnerability detection (SQL injection, SSRF, RCE, etc.)
 * - Taint analysis and data flow tracking
 * - Report generation in multiple formats
 * 
 * @version 1.0.0
 * @author likaiyang2003
 */

import { tool } from '@opencode-ai/plugin'
import { z } from 'zod'
import type { PluginInput, Hooks } from '@opencode-ai/plugin'

// Core types
export type {
  JarAnalysisResult,
  JarManifest,
  DetectedFramework,
  AttackEntry,
  ParameterInfo,
  Dependency,
  ConfigFile,
  Vulnerability
} from './types/index'

// Enums
export { Severity, VulnerabilityType } from './types/index'

// JAR Analysis
export { JarAnalyzer } from './tools/jar-analyzer/index'

// Decompiler
export { DecompileManager, CFRDecompiler } from './tools/decompiler/index'

// Taint Engine
export { TaintEngine } from './tools/taint-engine/index'

// Performance Optimizer
export { 
  PerformanceOptimizer,
  CacheManager,
  ParallelExecutor
} from './tools/performance-optimizer/index'

// Agents
export { SQLInjectionAgent } from './agents/sql-injector/index'
export { SSRFAgent } from './agents/ssrf-hunter/index'
export { RCEAgent } from './agents/rce-detector/index'
export { AuthAnalyzerAgent } from './agents/auth-analyzer/index'
export { BusinessLogicAgent } from './agents/logic-inspector/index'

// Sentry Orchestrator
export { SentryAgent } from './agents/sentry/index'

// Report Generator
export { ReportGenerator } from './hooks/report-generator/index'

// Integration
export { runAuditWorkflow as auditWorkflow } from './integration/index'
export type { 
  AuditWorkflowOptions, 
  AuditWorkflowResult 
} from './integration/index'

// Plugin implementation
import { JarAnalyzer } from './tools/jar-analyzer/index'
import { DecompileManager } from './tools/decompiler/index'
import { CFRDecompiler } from './tools/decompiler/index'
import { TaintEngine } from './tools/taint-engine/index'
import { SQLInjectionAgent } from './agents/sql-injector/index'
import { SSRFAgent } from './agents/ssrf-hunter/index'
import { RCEAgent } from './agents/rce-detector/index'
import { AuthAnalyzerAgent } from './agents/auth-analyzer/index'
import { BusinessLogicAgent } from './agents/logic-inspector/index'
import { SentryAgent } from './agents/sentry/index'
import { ReportGenerator } from './hooks/report-generator/index'
import { runAuditWorkflow } from './integration/index'
import { VulnerabilityType, Severity } from './types/index'
import type { AttackEntry, ConfigFile, Vulnerability } from './types/index'
import type { DecompileResult } from './tools/decompiler/types'
import type { ScanResult } from './agents/sentry/types'
import type { SQLInjectionVulnerability } from './agents/sql-injector/types'
import type { SSRFVulnerability } from './agents/ssrf-hunter/types'
import type { RCEVulnerability } from './agents/rce-detector/types'
import type { BusinessLogicVulnerability } from './agents/logic-inspector/types'

export default async function plugin(input: PluginInput): Promise<Hooks> {
  return {
    tool: {
      // Tool 1: Full JAR security audit
      audit_jar: tool({
        description: 'Security audit a Java JAR file - analyzes dependencies, frameworks, configuration files, and detects potential vulnerabilities using all available security agents',
        args: {
          jarPath: z.string().describe('Path to the JAR file to audit'),
          severityThreshold: z.enum(['critical', 'high', 'medium', 'low']).optional().describe('Filter vulnerabilities by minimum severity level'),
          reportFormat: z.enum(['json', 'html', 'markdown', 'console']).optional().describe('Output format for the audit report')
        },
        async execute(args, context): Promise<string> {
          try {
            const workflowResult = await runAuditWorkflow({
              jarPath: args.jarPath,
              severityThreshold: args.severityThreshold
            })
            
            const reportGenerator = new ReportGenerator()
            let report: string
            
            switch (args.reportFormat || 'json') {
              case 'console':
                report = await reportGenerator.generateConsoleReport(workflowResult.scanResult)
                break
              case 'html':
                report = await reportGenerator.generateHTMLReport(workflowResult.scanResult)
                break
              case 'markdown':
                report = await reportGenerator.generateMarkdownReport(workflowResult.scanResult)
                break
              case 'json':
              default:
                report = await reportGenerator.generateJSONReport(workflowResult.scanResult)
                break
            }
            
            return JSON.stringify({
              success: workflowResult.success,
              jarPath: args.jarPath,
              report,
              summary: workflowResult.scanResult.summary,
              vulnerabilitiesCount: workflowResult.scanResult.vulnerabilities.length
            }, null, 2)
          } catch (error) {
            return JSON.stringify({
              success: false,
              error: error instanceof Error ? error.message : String(error)
            })
          }
        }
      }),

      // Tool 2: Decompile Java class
      decompile_class: tool({
        description: 'Decompile a Java class file from a JAR to readable Java source code for security analysis',
        args: {
          jarPath: z.string().describe('Path to the JAR file containing the class'),
          className: z.string().describe('Fully qualified class name to decompile (e.g., com.example.MyClass)'),
          includeLineNumbers: z.boolean().optional().describe('Include line numbers in decompiled code'),
          includeImports: z.boolean().optional().describe('Include import statements'),
          timeout: z.number().optional().describe('Decompilation timeout in milliseconds')
        },
        async execute(args, context): Promise<string> {
          const decompiler = new DecompileManager(new CFRDecompiler())
          
          try {
            const result = await decompiler.decompileClass(args.jarPath, args.className, {
              includeLineNumbers: args.includeLineNumbers,
              includeImports: args.includeImports,
              timeout: args.timeout
            })
            
            return JSON.stringify({
              success: result.isSuccess,
              className: args.className,
              jarPath: args.jarPath,
              sourceCode: result.sourceCode,
              packageName: result.packageName,
              imports: result.imports,
              methods: result.methods.map(m => ({ name: m.name, signature: m.signature })),
              fields: result.fields.map(f => ({ name: f.name, type: f.type })),
              error: result.error,
              cacheHit: result.cacheHit,
              decompileTime: result.decompileTime
            }, null, 2)
          } catch (error) {
            return JSON.stringify({
              success: false,
              error: error instanceof Error ? error.message : String(error)
            })
          }
        }
      }),

      // Tool 3: Taint analysis
      analyze_taint: tool({
        description: 'Perform taint analysis on a specific Java method to track data flow from sources (user input) to sinks (dangerous operations)',
        args: {
          jarPath: z.string().describe('Path to the JAR file to analyze'),
          className: z.string().describe('Fully qualified class name containing the method'),
          methodName: z.string().describe('Method name to analyze'),
          sourcePatterns: z.array(z.string()).optional().describe('Custom source patterns to track (e.g., request.getParameter)'),
          sinkPatterns: z.array(z.string()).optional().describe('Custom sink patterns to track (e.g., executeQuery, exec)')
        },
        async execute(args, context): Promise<string> {
          const decompiler = new DecompileManager(new CFRDecompiler())
          const taintEngine = new TaintEngine()
          
          try {
            // First decompile the class
            const decompileResult = await decompiler.decompileClass(args.jarPath, args.className)
            
            if (!decompileResult.isSuccess) {
              return JSON.stringify({
                success: false,
                error: `Failed to decompile class: ${decompileResult.error}`
              })
            }
            
            // Find the target method
            const targetMethod = decompileResult.methods.find(m => m.name === args.methodName)
            
            if (!targetMethod) {
              return JSON.stringify({
                success: false,
                error: `Method ${args.methodName} not found in class ${args.className}`
              })
            }
            
            // Analyze taint flow
            const taintResult = await taintEngine.analyze({
              methodName: args.methodName,
              className: args.className,
              sourceCode: decompileResult.sourceCode,
              parameters: targetMethod.parameters
            })
            
            return JSON.stringify({
              success: true,
              jarPath: args.jarPath,
              className: args.className,
              methodName: args.methodName,
              taintFlows: taintResult.flows,
              summary: taintResult.summary,
              totalFlows: taintResult.flows.length,
              vulnerableFlows: taintResult.summary.vulnerableFlows
            }, null, 2)
          } catch (error) {
            return JSON.stringify({
              success: false,
              error: error instanceof Error ? error.message : String(error)
            })
          }
        }
      }),

      // Tool 4: SQL injection detection
      detect_sql_injection: tool({
        description: 'Detect SQL injection vulnerabilities in Java code by analyzing SQL query construction patterns and data flow',
        args: {
          jarPath: z.string().describe('Path to the JAR file to analyze'),
          strictMode: z.boolean().optional().describe('Enable strict mode for more aggressive detection (default: true)')
        },
        async execute(args, context): Promise<string> {
          const analyzer = new JarAnalyzer()
          const decompiler = new DecompileManager(new CFRDecompiler())
          const agent = new SQLInjectionAgent({ strictMode: args.strictMode !== false })
          
          try {
            // Analyze JAR structure
            const jarAnalysis = await analyzer.analyze(args.jarPath)
            
            // Decompile all entry point classes
            const decompiledSources = new Map<string, DecompileResult>()
            for (const entry of jarAnalysis.entryPoints) {
              const result = await decompiler.decompileClass(args.jarPath, entry.className)
              if (result.isSuccess) {
                decompiledSources.set(entry.className, result)
              }
            }
            
            // Run SQL injection detection
            const vulnerabilities = await agent.audit(args.jarPath, jarAnalysis.entryPoints, decompiledSources)
            
            return JSON.stringify({
              success: true,
              jarPath: args.jarPath,
              vulnerabilities: vulnerabilities.map(v => ({
                id: v.id,
                type: v.type,
                severity: v.severity,
                title: v.title,
                description: v.description,
                location: v.location,
                details: v.details
              })),
              totalVulnerabilities: vulnerabilities.length,
              entryPointsAnalyzed: jarAnalysis.entryPoints.length
            }, null, 2)
          } catch (error) {
            return JSON.stringify({
              success: false,
              error: error instanceof Error ? error.message : String(error)
            })
          }
        }
      }),

      // Tool 5: SSRF detection
      detect_ssrf: tool({
        description: 'Detect Server-Side Request Forgery (SSRF) vulnerabilities in Java applications by analyzing URL construction patterns',
        args: {
          jarPath: z.string().describe('Path to the JAR file to analyze'),
          checkInternalHosts: z.boolean().optional().describe('Check for requests to internal/private IP addresses (default: true)'),
          strictMode: z.boolean().optional().describe('Enable strict mode for more aggressive detection (default: true)')
        },
        async execute(args, context): Promise<string> {
          const analyzer = new JarAnalyzer()
          const decompiler = new DecompileManager(new CFRDecompiler())
          const agent = new SSRFAgent({ 
            detectInternalIPs: args.checkInternalHosts !== false,
            strictMode: args.strictMode !== false
          })
          
          try {
            const jarAnalysis = await analyzer.analyze(args.jarPath)
            
            const decompiledSources = new Map<string, DecompileResult>()
            for (const entry of jarAnalysis.entryPoints) {
              const result = await decompiler.decompileClass(args.jarPath, entry.className)
              if (result.isSuccess) {
                decompiledSources.set(entry.className, result)
              }
            }
            
            const vulnerabilities = await agent.audit(args.jarPath, jarAnalysis.entryPoints, decompiledSources)
            
            return JSON.stringify({
              success: true,
              jarPath: args.jarPath,
              vulnerabilities: vulnerabilities.map(v => ({
                id: v.id,
                type: v.type,
                severity: v.severity,
                title: v.title,
                description: v.description,
                location: v.location,
                details: v.details,
                attackScenarios: v.attackScenarios
              })),
              totalVulnerabilities: vulnerabilities.length,
              entryPointsAnalyzed: jarAnalysis.entryPoints.length
            }, null, 2)
          } catch (error) {
            return JSON.stringify({
              success: false,
              error: error instanceof Error ? error.message : String(error)
            })
          }
        }
      }),

      // Tool 6: RCE detection
      detect_rce: tool({
        description: 'Detect Remote Code Execution (RCE) vulnerabilities including command injection, unsafe deserialization, and expression language injection',
        args: {
          jarPath: z.string().describe('Path to the JAR file to analyze'),
          checkDeserialization: z.boolean().optional().describe('Check for unsafe deserialization patterns (default: true)'),
          strictMode: z.boolean().optional().describe('Enable strict mode (default: true)')
        },
        async execute(args, context): Promise<string> {
          const analyzer = new JarAnalyzer()
          const decompiler = new DecompileManager(new CFRDecompiler())
          const agent = new RCEAgent({
            detectDeserialization: args.checkDeserialization !== false,
            strictMode: args.strictMode !== false
          })
          
          try {
            const jarAnalysis = await analyzer.analyze(args.jarPath)
            
            const decompiledSources = new Map<string, DecompileResult>()
            for (const entry of jarAnalysis.entryPoints) {
              const result = await decompiler.decompileClass(args.jarPath, entry.className)
              if (result.isSuccess) {
                decompiledSources.set(entry.className, result)
              }
            }
            
            const vulnerabilities = await agent.audit(args.jarPath, jarAnalysis.entryPoints, decompiledSources)
            
            return JSON.stringify({
              success: true,
              jarPath: args.jarPath,
              vulnerabilities: vulnerabilities.map(v => ({
                id: v.id,
                type: v.type,
                severity: v.severity,
                title: v.title,
                description: v.description,
                location: v.location,
                details: v.details,
                attackPayloads: v.attackPayloads
              })),
              totalVulnerabilities: vulnerabilities.length,
              entryPointsAnalyzed: jarAnalysis.entryPoints.length
            }, null, 2)
          } catch (error) {
            return JSON.stringify({
              success: false,
              error: error instanceof Error ? error.message : String(error)
            })
          }
        }
      }),

      // Tool 7: Auth vulnerabilities detection
      detect_auth_vulnerabilities: tool({
        description: 'Detect authentication and authorization vulnerabilities including bypasses, IDOR, weak session management, JWT flaws, and hardcoded credentials',
        args: {
          jarPath: z.string().describe('Path to the JAR file to analyze'),
          checkSessionManagement: z.boolean().optional().describe('Check for weak session management (default: true)'),
          checkJwtIssues: z.boolean().optional().describe('Check for JWT implementation flaws (default: true)'),
          checkAccessControl: z.boolean().optional().describe('Check for broken access control (default: true)'),
          strictMode: z.boolean().optional().describe('Enable strict mode (default: true)')
        },
        async execute(args, context): Promise<string> {
          const analyzer = new JarAnalyzer()
          const decompiler = new DecompileManager(new CFRDecompiler())
          const agent = new AuthAnalyzerAgent({
            detectJWTIssues: args.checkJwtIssues !== false,
            detectIDOR: args.checkAccessControl !== false,
            detectHardcodedCredentials: args.checkSessionManagement !== false,
            strictMode: args.strictMode !== false
          })
          
          try {
            const jarAnalysis = await analyzer.analyze(args.jarPath)
            
            const decompiledSources = new Map<string, DecompileResult>()
            for (const entry of jarAnalysis.entryPoints) {
              const result = await decompiler.decompileClass(args.jarPath, entry.className)
              if (result.isSuccess) {
                decompiledSources.set(entry.className, result)
              }
            }
            
            const vulnerabilities = await agent.audit(
              args.jarPath, 
              jarAnalysis.entryPoints, 
              decompiledSources,
              jarAnalysis.configFiles
            )
            
            return JSON.stringify({
              success: true,
              jarPath: args.jarPath,
              vulnerabilities: vulnerabilities.map(v => ({
                id: v.id,
                type: v.type,
                severity: v.severity,
                title: v.title,
                description: v.description,
                location: v.location,
                evidence: v.evidence
              })),
              totalVulnerabilities: vulnerabilities.length,
              entryPointsAnalyzed: jarAnalysis.entryPoints.length
            }, null, 2)
          } catch (error) {
            return JSON.stringify({
              success: false,
              error: error instanceof Error ? error.message : String(error)
            })
          }
        }
      }),

      // Tool 8: Business logic flaws detection
      detect_business_logic: tool({
        description: 'Detect business logic vulnerabilities including price manipulation, race conditions, workflow bypasses, missing captcha protection, and improper state validation',
        args: {
          jarPath: z.string().describe('Path to the JAR file to analyze'),
          checkRaceConditions: z.boolean().optional().describe('Check for race condition vulnerabilities (default: true)'),
          checkWorkflowBypass: z.boolean().optional().describe('Check for workflow bypass possibilities (default: true)'),
          strictMode: z.boolean().optional().describe('Enable strict mode (default: true)')
        },
        async execute(args, context): Promise<string> {
          const analyzer = new JarAnalyzer()
          const decompiler = new DecompileManager(new CFRDecompiler())
          const agent = new BusinessLogicAgent({
            detectRaceConditions: args.checkRaceConditions !== false,
            detectPaymentIssues: true,
            detectCaptchaIssues: true,
            strictMode: args.strictMode !== false
          })
          
          try {
            const jarAnalysis = await analyzer.analyze(args.jarPath)
            
            const decompiledSources = new Map<string, DecompileResult>()
            for (const entry of jarAnalysis.entryPoints) {
              const result = await decompiler.decompileClass(args.jarPath, entry.className)
              if (result.isSuccess) {
                decompiledSources.set(entry.className, result)
              }
            }
            
            const vulnerabilities = await agent.audit(args.jarPath, jarAnalysis.entryPoints, decompiledSources)
            
            return JSON.stringify({
              success: true,
              jarPath: args.jarPath,
              vulnerabilities: vulnerabilities.map(v => ({
                id: v.id,
                type: v.type,
                severity: v.severity,
                title: v.title,
                description: v.description,
                location: v.location,
                details: v.details
              })),
              totalVulnerabilities: vulnerabilities.length,
              entryPointsAnalyzed: jarAnalysis.entryPoints.length
            }, null, 2)
          } catch (error) {
            return JSON.stringify({
              success: false,
              error: error instanceof Error ? error.message : String(error)
            })
          }
        }
      }),

      // Tool 9: Generate audit report
      generate_audit_report: tool({
        description: 'Generate comprehensive security audit report from scan results in various formats',
        args: {
          scanResultJson: z.string().describe('JSON string containing the scan result from a previous audit'),
          format: z.enum(['json', 'html', 'markdown', 'console']).describe('Output format for the report'),
          includeRemediation: z.boolean().optional().describe('Include remediation recommendations (default: true)'),
          includeEvidence: z.boolean().optional().describe('Include vulnerability evidence and code snippets (default: true)')
        },
        async execute(args, context): Promise<string> {
          const reportGenerator = new ReportGenerator({
            includeRemediation: args.includeRemediation !== false,
            includeEvidence: args.includeEvidence !== false
          })
          
          try {
            // Parse the scan result
            const scanResult: ScanResult = JSON.parse(args.scanResultJson)
            
            let report: string
            switch (args.format) {
              case 'console':
                report = await reportGenerator.generateConsoleReport(scanResult)
                break
              case 'html':
                report = await reportGenerator.generateHTMLReport(scanResult)
                break
              case 'markdown':
                report = await reportGenerator.generateMarkdownReport(scanResult)
                break
              case 'json':
              default:
                report = await reportGenerator.generateJSONReport(scanResult)
                break
            }
            
            return JSON.stringify({
              success: true,
              format: args.format,
              report,
              reportLength: report.length,
              vulnerabilityCount: scanResult.vulnerabilities?.length || 0
            }, null, 2)
          } catch (error) {
            return JSON.stringify({
              success: false,
              error: error instanceof Error ? error.message : String(error)
            })
          }
        }
      })
    }
  }
}
