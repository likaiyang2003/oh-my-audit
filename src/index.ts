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

// Default export for OpenCode plugin loader
import { JarAnalyzer } from './tools/jar-analyzer/index'
import { DecompileManager } from './tools/decompiler/index'
import { TaintEngine } from './tools/taint-engine/index'
import { SQLInjectionAgent } from './agents/sql-injector/index'
import { SSRFAgent } from './agents/ssrf-hunter/index'
import { RCEAgent } from './agents/rce-detector/index'
import { AuthAnalyzerAgent } from './agents/auth-analyzer/index'
import { BusinessLogicAgent } from './agents/logic-inspector/index'
import { SentryAgent } from './agents/sentry/index'
import { ReportGenerator } from './hooks/report-generator/index'
import { PerformanceOptimizer } from './tools/performance-optimizer/index'
import { runAuditWorkflow as auditWorkflow } from './integration/index'

export default {
  name: 'code-security-audit',
  version: '1.0.0',
  description: 'Professional Java code security audit plugin',
  
  // Export all main classes for OpenCode to use
  JarAnalyzer,
  DecompileManager,
  TaintEngine,
  SQLInjectionAgent,
  SSRFAgent,
  RCEAgent,
  AuthAnalyzerAgent,
  BusinessLogicAgent,
  SentryAgent,
  ReportGenerator,
  PerformanceOptimizer,
  
  // Export audit workflow function
  auditWorkflow
}
