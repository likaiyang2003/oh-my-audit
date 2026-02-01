import type { AttackEntry, Vulnerability } from '../../types'
import { VulnerabilityType, Severity } from '../../types'
import type { DecompileResult } from '../../tools/decompiler/types'
import type { BusinessLogicVulnerability, BusinessLogicAnalyzerOptions } from './types'
import { BUSINESS_LOGIC_RULES, hasCaptchaProtection, hasSynchronization, usesOptimisticLocking } from './rules'

export class BusinessLogicAgent {
  private options: BusinessLogicAnalyzerOptions
  
  constructor(options: BusinessLogicAnalyzerOptions = {}) {
    this.options = {
      detectPaymentIssues: true,
      detectRaceConditions: true,
      detectCaptchaIssues: true,
      strictMode: true,
      ...options
    }
  }
  
  async audit(
    jarPath: string,
    entryPoints: AttackEntry[],
    decompiledSources: Map<string, DecompileResult>
  ): Promise<BusinessLogicVulnerability[]> {
    const vulnerabilities: BusinessLogicVulnerability[] = []
    
    for (const entry of entryPoints) {
      const source = decompiledSources.get(entry.className)
      if (!source || !source.isSuccess) continue
      
      // 分析每个业务逻辑规则
      for (const rule of BUSINESS_LOGIC_RULES) {
        // 跳过不启用的检测类型
        if (rule.logicType === 'PRICE_MANIPULATION' && !this.options.detectPaymentIssues) continue
        if (rule.logicType === 'RACE_CONDITION' && !this.options.detectRaceConditions) continue
        if (rule.logicType === 'MISSING_CAPTCHA' && !this.options.detectCaptchaIssues) continue
        
        const matches = this.findMatches(source.sourceCode, rule.patterns)
        
        for (const match of matches) {
          // 检查是否有防护机制
          if (this.hasProtection(source.sourceCode, rule.logicType)) {
            continue
          }
          
          const vuln = this.createVulnerability(entry, source, rule, match)
          if (vuln) {
            vulnerabilities.push(vuln)
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
  
  private hasProtection(sourceCode: string, logicType: string): boolean {
    switch (logicType) {
      case 'MISSING_CAPTCHA':
        return hasCaptchaProtection(sourceCode)
      case 'RACE_CONDITION':
        return hasSynchronization(sourceCode) || usesOptimisticLocking(sourceCode)
      default:
        return false
    }
  }
  
  private createVulnerability(
    entry: AttackEntry,
    source: DecompileResult,
    rule: typeof BUSINESS_LOGIC_RULES[0],
    match: { line: number; code: string; match: string }
  ): BusinessLogicVulnerability | null {
    const id = `logic-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`
    
    const severity = rule.severity === 'critical' ? Severity.CRITICAL : 
                     rule.severity === 'high' ? Severity.HIGH : Severity.MEDIUM
    
    let financialImpact: string | undefined
    if (rule.logicType === 'PRICE_MANIPULATION') {
      financialImpact = '攻击者可将商品价格改为 0.01 元，造成重大财务损失'
    } else if (rule.logicType === 'RACE_CONDITION') {
      financialImpact = '可能导致超卖，需要赔偿用户或取消订单'
    }
    
    return {
      id,
      type: VulnerabilityType.BUSINESS_LOGIC,
      cwe: this.getCWEFromLogicType(rule.logicType),
      owasp: 'A04:2021 - Insecure Design',
      severity,
      title: `Business Logic: ${rule.name}`,
      description: `${rule.description}\n\n业务影响: ${rule.businessImpact}`,
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
        description: this.getRemediation(rule.logicType),
        codeExample: this.getSafeCodeExample(rule.logicType),
        references: [
          'https://owasp.org/www-community/attacks/Business_Logic_Attacks',
          'https://cheatsheetseries.owasp.org/cheatsheets/Transaction_Authorization_Cheat_Sheet.html'
        ]
      },
      details: {
        logicType: rule.logicType as any,
        businessImpact: rule.businessImpact,
        financialImpact,
        affectedResource: entry.urlPattern
      }
    }
  }
  
  private getCWEFromLogicType(logicType: string): string {
    const cweMap: Record<string, string> = {
      'PRICE_MANIPULATION': 'CWE-639',
      'RACE_CONDITION': 'CWE-362',
      'MISSING_CAPTCHA': 'CWE-307',
      'WORKFLOW_BYPASS': 'CWE-840',
      'COUPON_REUSE': 'CWE-362'
    }
    return cweMap[logicType] || 'CWE-840'
  }
  
  private getRemediation(logicType: string): string {
    const remediationMap: Record<string, string> = {
      'PRICE_MANIPULATION': '从数据库查询商品价格，绝不接受客户端传入价格',
      'RACE_CONDITION': '使用数据库乐观锁或分布式锁保证原子性',
      'MISSING_CAPTCHA': '集成验证码服务（reCAPTCHA、极验）或实施速率限制',
      'WORKFLOW_BYPASS': '实施状态机验证，确保状态转换合法',
      'COUPON_REUSE': '使用数据库唯一索引或分布式锁保证幂等性'
    }
    return remediationMap[logicType] || '修复业务逻辑缺陷'
  }
  
  private getSafeCodeExample(logicType: string): string {
    const examples: Record<string, string> = {
      'PRICE_MANIPULATION': `// 危险代码：
order.setPrice(request.getPrice());

// 安全代码：
Product product = productRepository.findById(request.getProductId());
order.setPrice(product.getPrice()); // 从数据库获取价格`,
      
      'RACE_CONDITION': `// 危险代码：
if (product.getInventory() >= quantity) {
    product.setInventory(product.getInventory() - quantity);
}

// 安全代码（乐观锁）：
UPDATE products 
SET inventory = inventory - ?, version = version + 1 
WHERE id = ? AND version = ? AND inventory >= ?`,
      
      'MISSING_CAPTCHA': `// 添加验证码验证
if (!captchaService.verify(request.getCaptchaToken())) {
    throw new InvalidCaptchaException("验证码错误");
}`
    }
    return examples[logicType] || '// 参考业务逻辑安全最佳实践'
  }
}
