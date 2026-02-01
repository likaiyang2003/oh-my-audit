import type { AttackEntry } from '../../types'
import { VulnerabilityType, Severity } from '../../types'
import type { DecompileResult } from '../../tools/decompiler/types'
import type { RCEVulnerability, RCEAnalyzerOptions } from './types'
import { RCE_RULES, RCE_ATTACK_PAYLOADS, hasCommandSanitization } from './rules'

export class RCEAgent {
  private options: RCEAnalyzerOptions
  
  constructor(options: RCEAnalyzerOptions = {}) {
    this.options = {
      detectCommandChaining: true,
      detectDeserialization: true,
      strictMode: true,
      ...options
    }
  }
  
  async audit(
    jarPath: string,
    entryPoints: AttackEntry[],
    decompiledSources: Map<string, DecompileResult>
  ): Promise<RCEVulnerability[]> {
    const vulnerabilities: RCEVulnerability[] = []
    
    for (const entry of entryPoints) {
      const source = decompiledSources.get(entry.className)
      if (!source || !source.isSuccess) continue
      
      // 检查命令净化
      const sanitization = hasCommandSanitization(source.sourceCode)
      
      // 如果不严格且已有净化，降低风险等级但不跳过
      const hasSanitization = sanitization.hasSanitization
      
      // 分析每个 RCE 规则
      for (const rule of RCE_RULES) {
        // 跳过反序列化检测（如果禁用）
        if (rule.rceType === 'deserialization_rce' && !this.options.detectDeserialization) {
          continue
        }
        
        const matches = this.findMatches(source.sourceCode, rule.patterns)
        
        for (const match of matches) {
          // 检查是否有用户输入到达危险方法
          if (await this.hasUserInputToSink(entry, match, source.sourceCode)) {
            const vuln = this.createVulnerability(entry, source, rule, match, sanitization)
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
  
  private async hasUserInputToSink(
    entry: AttackEntry,
    match: { line: number; code: string; match: string },
    sourceCode: string
  ): Promise<boolean> {
    // 检查入口点的参数是否用于危险方法
    for (const param of entry.parameters) {
      if (match.code.includes(param.name)) {
        return true
      }
      
      // 检查上下文（前后10行）
      const lines = sourceCode.split('\n')
      const contextStart = Math.max(0, match.line - 10)
      const contextEnd = Math.min(lines.length, match.line + 10)
      
      for (let i = contextStart; i < contextEnd; i++) {
        const line = lines[i]
        // 检查参数是否传递给危险方法
        if (line && line.includes(param.name) && 
            (/exec|eval|readObject|invoke/.test(line))) {
          return true
        }
      }
    }
    
    // 检查是否有 request.getParameter 等输入源
    if (/request\.(getParameter|getHeader|getInputStream|getReader)/.test(sourceCode)) {
      return true
    }
    
    // 检查是否有文件上传或输入流
    if (/MultipartFile|InputStream|getBytes/.test(sourceCode)) {
      return true
    }
    
    return false
  }
  
  private createVulnerability(
    entry: AttackEntry,
    source: DecompileResult,
    rule: typeof RCE_RULES[0],
    match: { line: number; code: string; match: string },
    sanitization: { hasSanitization: boolean; type?: string }
  ): RCEVulnerability | null {
    const id = `rce-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`
    
    // 确定严重级别（如果有净化则降级）
    let severity: Severity
    if (sanitization.hasSanitization && !this.options.strictMode) {
      severity = Severity.MEDIUM
    } else {
      severity = rule.severity === 'critical' ? Severity.CRITICAL : 
                 rule.severity === 'high' ? Severity.HIGH : Severity.MEDIUM
    }
    
    // 提取命令链信息
    const commandChain = this.extractCommandChain(match.code, source.sourceCode)
    
    // 查找相关参数
    const vulnerableParameter = entry.parameters.find(p => {
      const context = this.getContext(source.sourceCode, match.line, 10)
      return context.includes(p.name)
    })?.name
    
    return {
      id,
      type: VulnerabilityType.RCE,
      cwe: this.getCWEFromRCEType(rule.rceType),
      owasp: 'A03:2021 - Injection',
      severity,
      title: `RCE via ${rule.name}`,
      description: `${rule.description}\n\n攻击者可能利用此漏洞在服务器上执行任意代码或命令。`,
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
          'https://owasp.org/www-community/attacks/Code_Injection',
          'https://cheatsheetseries.owasp.org/cheatsheets/OS_Command_Injection_Defense_Cheat_Sheet.html'
        ]
      },
      details: {
        rceType: rule.rceType,
        sinkType: rule.rceType,
        sinkMethod: rule.sinkMethods[0],
        vulnerableParameter,
        commandChain,
        isDirectUserInput: !!vulnerableParameter,
        hasSanitization: sanitization.hasSanitization,
        sanitizationType: sanitization.type
      },
      attackPayloads: this.getRelevantPayloads(rule.rceType)
    }
  }
  
  private getCWEFromRCEType(rceType: string): string {
    const cweMap: Record<string, string> = {
      'command_injection': 'CWE-78',
      'script_injection': 'CWE-94',
      'deserialization_rce': 'CWE-502',
      'el_expression_injection': 'CWE-917',
      'template_injection': 'CWE-1336',
      'reflection_rce': 'CWE-470',
    }
    return cweMap[rceType] || 'CWE-94'
  }
  
  private extractCommandChain(code: string, sourceCode: string): string[] | undefined {
    // 提取命令构造链
    const chain: string[] = []
    
    // 检查命令拼接
    if (/\+/.test(code)) {
      chain.push('string_concatenation')
    }
    
    // 检查数组形式
    if (/new\s+String\[\]/.test(code)) {
      chain.push('array_construction')
    }
    
    // 检查 ProcessBuilder
    if (/ProcessBuilder/.test(code)) {
      chain.push('process_builder')
    }
    
    return chain.length > 0 ? chain : undefined
  }
  
  private getContext(sourceCode: string, lineNumber: number, contextSize: number): string {
    const lines = sourceCode.split('\n')
    const start = Math.max(0, lineNumber - contextSize - 1)
    const end = Math.min(lines.length, lineNumber + contextSize)
    return lines.slice(start, end).join('\n')
  }
  
  private generateSafeCodeExample(rule: typeof RCE_RULES[0]): string {
    switch (rule.rceType) {
      case 'command_injection':
        return `// 危险代码：
String cmd = request.getParameter("cmd");
Runtime.getRuntime().exec(cmd);

// 安全代码：使用数组形式
String[] cmd = {"/bin/sh", "-c", "safescript.sh"};
new ProcessBuilder(cmd).start();

// 或者使用白名单
List<String> allowedCmds = Arrays.asList("ls", "pwd", "whoami");
if (!allowedCmds.contains(userCmd)) {
    throw new SecurityException("Command not allowed");
}`
        
      case 'script_injection':
        return `// 危险代码：
engine.eval(userInput);

// 安全代码：禁止执行用户脚本
// 如果需要脚本功能，使用沙箱：
ScriptContext context = new SimpleScriptContext();
context.setAttribute("userData", safeData, ScriptContext.ENGINE_SCOPE);
// 限制脚本权限`  
        
      case 'deserialization_rce':
        return `// 危险代码：
ObjectInputStream ois = new ObjectInputStream(input);
Object obj = ois.readObject();

// 安全代码：使用白名单过滤
ObjectInputStream ois = new ObjectInputStream(input) {
    protected Class<?> resolveClass(ObjectStreamClass desc) {
        if (!allowedClasses.contains(desc.getName())) {
            throw new InvalidClassException("Unauthorized deserialization", desc.getName());
        }
        return super.resolveClass(desc);
    }
};

// 或者使用 JSON 替代
User user = new Gson().fromJson(jsonInput, User.class);`
        
      default:
        return rule.safeAlternative
    }
  }
  
  private getRelevantPayloads(rceType: string): RCEVulnerability['attackPayloads'] {
    if (rceType === 'deserialization_rce') {
      return RCE_ATTACK_PAYLOADS.filter(p => p.type === 'YSOSERIAL')
    } else if (rceType === 'command_injection') {
      return RCE_ATTACK_PAYLOADS.filter(p => 
        p.type === 'COMMAND_CHAIN' || p.type === 'COMMAND_CHAIN_WIN' || 
        p.type === 'BACKTICK' || p.type === 'PIPE'
      )
    }
    return []
  }
}
