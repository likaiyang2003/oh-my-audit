import type { Vulnerability } from '../../types'

export interface SQLInjectionVulnerability extends Vulnerability {
  details: {
    ormFramework: 'jdbc' | 'mybatis' | 'jpa' | 'hibernate' | 'unknown'
    injectionType: 'string_concatenation' | 'format_string' | 'dynamic_query' | 'mybatis_dollar_placeholder' | 'order_by_injection'
    sinkMethod: string
    vulnerableParameter?: string
    sqlQuery?: string
  }
}

export interface SQLInjectionRule {
  name: string
  description: string
  severity: 'critical' | 'high' | 'medium'
  patterns: RegExp[]
  ormFramework: 'jdbc' | 'mybatis' | 'jpa' | 'hibernate' | 'unknown'
  injectionType: SQLInjectionVulnerability['details']['injectionType']
  safeAlternative: string
}

export interface SQLInjectionAnalyzerOptions {
  includeMyBatisXML?: boolean
  strictMode?: boolean
  maxQueryLength?: number
}
