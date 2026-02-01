import type { ScanResult } from '../../agents/sentry/types'

export interface ReportFormat {
  console: string
  json: string
  html: string
  markdown: string
}

export interface ReportOptions {
  includeEvidence?: boolean
  includeRemediation?: boolean
  includeCodeExamples?: boolean
  severityFilter?: ('critical' | 'high' | 'medium' | 'low')[]
}

export interface HTMLReportTemplate {
  title: string
  css: string
  header: string
  footer: string
}

export interface MarkdownReportTemplate {
  title: string
  sections: string[]
}
