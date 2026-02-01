import type { AttackEntry, Vulnerability } from '../../types'
import { VulnerabilityType, Severity } from '../../types'
import type { DecompileResult } from '../../tools/decompiler/types'
import type { SQLInjectionVulnerability, SQLInjectionAnalyzerOptions } from './types'
import { SQL_INJECTION_RULES, SQL_EXECUTION_SINKS, usesPreparedStatement } from './rules'

export class SQLInjectionAgent {
  private options: SQLInjectionAnalyzerOptions
  
  constructor(options: SQLInjectionAnalyzerOptions = {}) {
    this.options = {
      includeMyBatisXML: true,
      strictMode: true,
      maxQueryLength: 1000,
      ...options
    }
  }
  
  async audit(
    jarPath: string,
    entryPoints: AttackEntry[],
    decompiledSources: Map<string, DecompileResult>
  ): Promise<SQLInjectionVulnerability[]> {
    const vulnerabilities: SQLInjectionVulnerability[] = []
    
    for (const entry of entryPoints) {
      const source = decompiledSources.get(entry.className)
      if (!source || !source.isSuccess) continue
      
      // 检查是否使用了安全的 PreparedStatement
      if (!this.options.strictMode && usesPreparedStatement(source.sourceCode)) {
        // 使用了 PreparedStatement，风险较低
        continue
      }
      
      // 分析每个 SQL 注入规则
      for (const rule of SQL_INJECTION_RULES) {
        const matches = this.findMatches(source.sourceCode, rule.patterns)
        
        for (const match of matches) {
          // 检查是否有用户输入到达 SQL 执行
          if (await this.hasUserInputFlow(entry, match, source.sourceCode)) {
            const vuln = this.createVulnerability(entry, source, rule, match)
            if (vuln) {
              vulnerabilities.push(vuln)
            }
          }
        }
      }
    }
    
    return vulnerabilities
  }
  
  private findMatches(sourceCode: string, patterns: RegExp[]): Array<{ line: number; code: string; match: string }> {
    const matches: Array<{ line: number; code: string; match: string }> = []
    const lines = sourceCode.split('\n')
    
    for (let i = 0; i < lines.length; i++) {
      const line = lines[i]
      
      for (const pattern of patterns) {
        const lineMatches = Array.from(line.matchAll(pattern))
        
        for (const match of lineMatches) {
          matches.push({
            line: i + 1,
            code: line.trim(),
            match: match[0]
          })
        }
      }
    }
    
    return matches
  }
  
  private async hasUserInputFlow(
    entry: AttackEntry,
    match: { line: number; code: string; match: string },
    sourceCode: string
  ): Promise<boolean> {
    // 简化版：检查入口点的参数是否在匹配代码附近
    // 实际应该使用污点追踪引擎
    
    // 检查参数名是否出现在 SQL 构建代码中
    for (const param of entry.parameters) {
      if (match.code.includes(param.name)) {
        return true
      }
      
      // 检查是否在前后几行内
      const lines = sourceCode.split('\n')
      const contextStart = Math.max(0, match.line - 5)
      const contextEnd = Math.min(lines.length, match.line + 5)
      
      for (let i = contextStart; i < contextEnd; i++) {
        if (lines[i] && lines[i].includes(param.name)) {
          return true
        }
      }
    }
    
    // 检查是否有 request.getParameter 等源
    if (/request\.(getParameter|getHeader|getInputStream)/.test(sourceCode)) {
      return true
    }
    
    return false
  }
  
  private createVulnerability(
    entry: AttackEntry,
    source: DecompileResult,
    rule: typeof SQL_INJECTION_RULES[0],
    match: { line: number; code: string; match: string }
  ): SQLInjectionVulnerability | null {
    // 提取 SQL 查询（简化版）
    let sqlQuery: string | undefined
    const sqlMatch = match.code.match(/["']([^"']*(?:SELECT|INSERT|UPDATE|DELETE)[^"']*)["']/i)
    if (sqlMatch) {
      sqlQuery = sqlMatch[1]
    }
    
    // 生成漏洞 ID
    const id = `sql-inj-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`
    
    // 确定严重级别
    const severity = rule.severity === 'critical' ? Severity.CRITICAL : 
                     rule.severity === 'high' ? Severity.HIGH : Severity.MEDIUM
    
    return {
      id,
      type: VulnerabilityType.SQL_INJECTION,
      cwe: 'CWE-89',
      owasp: 'A03:2021 - Injection',
      severity,
      title: `SQL Injection via ${rule.name}`,
      description: `${rule.description}\n\n匹配代码: ${match.code}`,
      location: {
        className: entry.className,
        methodName: entry.methodName,
        lineNumber: match.line,
        codeSnippet: match.code
      },
      evidence: {
        sourceFlow: entry.parameters.map(p => p.name),
        sinkFlow: [match.match]
      },
      remediation: {
        description: rule.safeAlternative,
        codeExample: this.generateSafeCodeExample(rule),
        references: [
          'https://owasp.org/www-community/attacks/SQL_Injection',
          'https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html'
        ]
      },
      details: {
        ormFramework: rule.ormFramework,
        injectionType: rule.injectionType,
        sinkMethod: this.extractSinkMethod(match.code),
        vulnerableParameter: entry.parameters.find(p => match.code.includes(p.name))?.name,
        sqlQuery
      }
    }
  }
  
  private extractSinkMethod(code: string): string {
    for (const sink of SQL_EXECUTION_SINKS) {
      if (code.includes(sink)) {
        return sink
      }
    }
    return 'unknown'
  }
  
  private generateSafeCodeExample(rule: typeof SQL_INJECTION_RULES[0]): string {
    switch (rule.ormFramework) {
      case 'jdbc':
        return `// 危险代码：
String sql = "SELECT * FROM users WHERE name = '" + name + "'";
statement.executeQuery(sql);

// 安全代码：
String sql = "SELECT * FROM users WHERE name = ?";
PreparedStatement stmt = connection.prepareStatement(sql);
stmt.setString(1, name);
ResultSet rs = stmt.executeQuery();`
        
      case 'mybatis':
        return `// 危险代码：
@Select("SELECT * FROM users WHERE name = '\${name}'")
User findByName(@Param("name") String name);

// 安全代码：
@Select("SELECT * FROM users WHERE name = #{name}")
User findByName(@Param("name") String name);`
        
      case 'jpa':
        return `// 危险代码：
@Query("SELECT u FROM User u WHERE u.name = '" + name + "'")
User findByName(String name);

// 安全代码：
@Query("SELECT u FROM User u WHERE u.name = :name")
User findByName(@Param("name") String name);`
        
      default:
        return rule.safeAlternative
    }
  }
}
