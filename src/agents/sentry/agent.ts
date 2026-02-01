import type { JarAnalysisResult, Vulnerability } from '../../types'
import { Severity } from '../../types'
import type { DecompileResult } from '../../tools/decompiler/types'
import { SQLInjectionAgent } from '../sql-injector/agent'
import { SSRFAgent } from '../ssrf-hunter/agent'
import { RCEAgent } from '../rce-detector/agent'
import { AuthAnalyzerAgent } from '../auth-analyzer/agent'
import { BusinessLogicAgent } from '../logic-inspector/agent'
import type { ScanResult, ScanSummary, ScanMetadata, SentryAgentOptions } from './types'

export class SentryAgent {
  private options: SentryAgentOptions
  private agents: {
    sql: SQLInjectionAgent
    ssrf: SSRFAgent
    rce: RCEAgent
    auth: AuthAnalyzerAgent
    logic: BusinessLogicAgent
  }
  
  constructor(options: SentryAgentOptions = {}) {
    this.options = {
      parallelExecution: true,
      maxConcurrency: 5,
      enableDeduplication: true,
      severityThreshold: 'low',
      ...options
    }
    
    // 初始化所有专项 Agent
    this.agents = {
      sql: new SQLInjectionAgent(),
      ssrf: new SSRFAgent(),
      rce: new RCEAgent(),
      auth: new AuthAnalyzerAgent(),
      logic: new BusinessLogicAgent()
    }
  }
  
  async orchestrate(
    jarPath: string,
    jarAnalysis: JarAnalysisResult,
    decompiledSources: Map<string, DecompileResult>
  ): Promise<ScanResult> {
    const scanStartTime = new Date()
    
    console.log(`🚀 Sentry Agent 开始扫描: ${jarPath}`)
    console.log(`📊 发现 ${jarAnalysis.entryPoints.length} 个攻击面入口`)
    console.log(`🔍 框架类型: ${jarAnalysis.framework.type}`)
    
    let allVulnerabilities: Vulnerability[] = []
    let agentsExecuted = 0
    
    // 并行执行所有 Agent
    if (this.options.parallelExecution) {
      console.log('⚡ 并行执行所有检测 Agent...')
      
      const agentPromises = [
        this.runAgent('SQL Injection', () => 
          this.agents.sql.audit(jarPath, jarAnalysis.entryPoints, decompiledSources)
        ),
        this.runAgent('SSRF', () => 
          this.agents.ssrf.audit(jarPath, jarAnalysis.entryPoints, decompiledSources)
        ),
        this.runAgent('RCE', () => 
          this.agents.rce.audit(jarPath, jarAnalysis.entryPoints, decompiledSources)
        ),
        this.runAgent('Auth', () => 
          this.agents.auth.audit(jarPath, jarAnalysis.entryPoints, decompiledSources, jarAnalysis.configFiles)
        ),
        this.runAgent('Business Logic', () => 
          this.agents.logic.audit(jarPath, jarAnalysis.entryPoints, decompiledSources)
        )
      ]
      
      const results = await Promise.all(agentPromises)
      
      for (const result of results) {
        if (result.vulnerabilities.length > 0) {
          allVulnerabilities = allVulnerabilities.concat(result.vulnerabilities)
          console.log(`  ✅ ${result.agentName}: 发现 ${result.vulnerabilities.length} 个漏洞`)
        } else {
          console.log(`  ✅ ${result.agentName}: 未发现漏洞`)
        }
        agentsExecuted++
      }
    } else {
      // 串行执行
      console.log('🔄 串行执行检测 Agent...')
      
      const sqlVulns = await this.agents.sql.audit(jarPath, jarAnalysis.entryPoints, decompiledSources)
      allVulnerabilities = allVulnerabilities.concat(sqlVulns)
      agentsExecuted++
      
      const ssrfVulns = await this.agents.ssrf.audit(jarPath, jarAnalysis.entryPoints, decompiledSources)
      allVulnerabilities = allVulnerabilities.concat(ssrfVulns)
      agentsExecuted++
      
      const rceVulns = await this.agents.rce.audit(jarPath, jarAnalysis.entryPoints, decompiledSources)
      allVulnerabilities = allVulnerabilities.concat(rceVulns)
      agentsExecuted++
      
      const authVulns = await this.agents.auth.audit(jarPath, jarAnalysis.entryPoints, decompiledSources, jarAnalysis.configFiles)
      allVulnerabilities = allVulnerabilities.concat(authVulns)
      agentsExecuted++
      
      const logicVulns = await this.agents.logic.audit(jarPath, jarAnalysis.entryPoints, decompiledSources)
      allVulnerabilities = allVulnerabilities.concat(logicVulns)
      agentsExecuted++
    }
    
    // 去重
    if (this.options.enableDeduplication) {
      allVulnerabilities = this.deduplicateVulnerabilities(allVulnerabilities)
    }
    
    // 过滤严重级别
    allVulnerabilities = this.filterBySeverity(allVulnerabilities)
    
    // 排序（按严重级别）
    allVulnerabilities = this.sortVulnerabilities(allVulnerabilities)
    
    const scanEndTime = new Date()
    const scanDuration = scanEndTime.getTime() - scanStartTime.getTime()
    
    console.log(`\n✨ 扫描完成！总计发现 ${allVulnerabilities.length} 个漏洞`)
    console.log(`⏱️  耗时: ${scanDuration}ms`)
    
    return {
      vulnerabilities: allVulnerabilities,
      summary: this.generateSummary(allVulnerabilities, scanDuration, decompiledSources.size, agentsExecuted),
      metadata: {
        jarPath,
        scanStartTime,
        scanEndTime,
        framework: jarAnalysis.framework.type,
        entryPointsCount: jarAnalysis.entryPoints.length
      }
    }
  }
  
  private async runAgent(
    agentName: string, 
    auditFn: () => Promise<Vulnerability[]>
  ): Promise<{ agentName: string; vulnerabilities: Vulnerability[] }> {
    try {
      const vulnerabilities = await auditFn()
      return { agentName, vulnerabilities }
    } catch (error) {
      console.error(`❌ ${agentName} Agent 执行失败:`, error)
      return { agentName, vulnerabilities: [] }
    }
  }
  
  private deduplicateVulnerabilities(vulnerabilities: Vulnerability[]): Vulnerability[] {
    const seen = new Set<string>()
    const unique: Vulnerability[] = []
    
    for (const vuln of vulnerabilities) {
      // 基于类型、类名、方法名和行号生成唯一键
      const key = `${vuln.type}-${vuln.location.className}-${vuln.location.methodName}-${vuln.location.lineNumber}`
      
      if (!seen.has(key)) {
        seen.add(key)
        unique.push(vuln)
      }
    }
    
    return unique
  }
  
  private filterBySeverity(vulnerabilities: Vulnerability[]): Vulnerability[] {
    const severityOrder = { 'critical': 4, 'high': 3, 'medium': 2, 'low': 1 }
    const threshold = severityOrder[this.options.severityThreshold || 'low']
    
    return vulnerabilities.filter(v => {
      const severity = severityOrder[v.severity] || 0
      return severity >= threshold
    })
  }
  
  private sortVulnerabilities(vulnerabilities: Vulnerability[]): Vulnerability[] {
    const severityOrder = { 'critical': 4, 'high': 3, 'medium': 2, 'low': 1 }
    
    return vulnerabilities.sort((a, b) => {
      const severityA = severityOrder[a.severity] || 0
      const severityB = severityOrder[b.severity] || 0
      return severityB - severityA
    })
  }
  
  private generateSummary(
    vulnerabilities: Vulnerability[], 
    duration: number,
    filesScanned: number,
    agentsExecuted: number
  ): ScanSummary {
    const counts = {
      critical: 0,
      high: 0,
      medium: 0,
      low: 0
    }
    
    for (const vuln of vulnerabilities) {
      if (vuln.severity === Severity.CRITICAL) counts.critical++
      else if (vuln.severity === Severity.HIGH) counts.high++
      else if (vuln.severity === Severity.MEDIUM) counts.medium++
      else if (vuln.severity === Severity.LOW) counts.low++
    }
    
    return {
      totalVulnerabilities: vulnerabilities.length,
      criticalCount: counts.critical,
      highCount: counts.high,
      mediumCount: counts.medium,
      lowCount: counts.low,
      scanDuration: duration,
      filesScanned,
      agentsExecuted
    }
  }
}
