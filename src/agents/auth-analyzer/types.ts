import type { Vulnerability, AttackEntry, ParameterInfo } from '../../types'

export type AuthVulnerabilityType = 
  | 'AUTH_BYPASS'
  | 'IDOR'
  | 'JWT_NONE_ALGORITHM'
  | 'JWT_WEAK_SECRET'
  | 'HARDCODED_CREDENTIALS'
  | 'INSECURE_COOKIE'

export interface AuthVulnerabilityDetails {
  authType: string
  description: string
  severity: 'critical' | 'high' | 'medium' | 'low'
  confidence: number
  entryPoint?: AttackEntry
  missingChecks?: string[]
  vulnerableParameter?: ParameterInfo
  affectedResource?: string
}

export interface AuthAnalyzerOptions {
  detectJWTIssues?: boolean
  detectIDOR?: boolean
  detectHardcodedCredentials?: boolean
  strictMode?: boolean
}
