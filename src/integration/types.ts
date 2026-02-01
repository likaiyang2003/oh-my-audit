import type { ScanResult } from '../agents/sentry/types'

export interface AuditWorkflowOptions {
  jarPath: string
  outputDir?: string
  reportFormats?: ('console' | 'json' | 'html' | 'markdown')[]
  severityThreshold?: 'critical' | 'high' | 'medium' | 'low'
}

export interface AuditWorkflowResult {
  scanResult: ScanResult
  reports: {
    console?: string
    json?: string
    html?: string
    markdown?: string
  }
  executionTime: number
  success: boolean
  error?: string
}
