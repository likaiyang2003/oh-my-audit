import type { Vulnerability, JarAnalysisResult } from '../../types'

export interface ScanResult {
  vulnerabilities: Vulnerability[]
  summary: ScanSummary
  metadata: ScanMetadata
}

export interface ScanSummary {
  totalVulnerabilities: number
  criticalCount: number
  highCount: number
  mediumCount: number
  lowCount: number
  scanDuration: number
  filesScanned: number
  agentsExecuted: number
}

export interface ScanMetadata {
  jarPath: string
  scanStartTime: Date
  scanEndTime: Date
  framework: string
  entryPointsCount: number
}

export interface SentryAgentOptions {
  parallelExecution?: boolean
  maxConcurrency?: number
  enableDeduplication?: boolean
  severityThreshold?: 'critical' | 'high' | 'medium' | 'low'
}
