import type { AttackEntry } from '../../types'
import { VulnerabilityType, Severity } from '../../types'
import type { DecompileResult } from '../../tools/decompiler/types'
import type { SSRFVulnerability, SSRFAnalyzerOptions } from './types'
import { SSRF_RULES, SSRF_ATTACK_SCENARIOS, hasURLValidation } from './rules'

export class SSRFAgent {
  private options: SSRFAnalyzerOptions
  
  constructor(options: SSRFAnalyzerOptions = {}) {
    this.options = {
      detectInternalIPs: true,
      detectMetadataEndpoints: true,
      detectFileProtocol: true,
      strictMode: true,
      ...options
    }
  }
  
  async audit(
    jarPath: string,
    entryPoints: AttackEntry[],
    decompiledSources: Map<string, DecompileResult>
  ): Promise<SSRFVulnerability[]> {
    const vulnerabilities: SSRFVulnerability[] = []
    
    for (const entry of entryPoints) {
      const source = decompiledSources.get(entry.className)
      if (!source || !source.isSuccess) continue
      
      // 检查 URL 验证
      const validation = hasURLValidation(source.sourceCode)
      
      // 如果不严格且已有验证，则跳过
      if (!this.options.strictMode && validation.hasValidation) {
        continue
      }
      
      // 分析每个 SSRF 规则
      for (const rule of SSRF_RULES) {
        const matches = this.findMatches(source.sourceCode, rule.patterns)
        
        for (const match of matches) {
          // 检查是否有用户输入到达 URL
          if (await this.hasUserInputToURL(entry, match, source.sourceCode)) {
            const vuln = this.createVulnerability(entry, source, rule, match, validation)
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
  
  private async hasUserInputToURL(
    entry: AttackEntry,
    match: { line: number; code: string; match: string },
    sourceCode: string
  ): Promise<boolean> {
    // 检查入口点的参数是否用于 URL 构造
    for (const param of entry.parameters) {
      if (match.code.includes(param.name)) {
        return true
      }
      
      // 检查上下文
      const lines = sourceCode.split('\n')
      const contextStart = Math.max(0, match.line - 10)
      const contextEnd = Math.min(lines.length, match.line + 5)
      
      for (let i = contextStart; i < contextEnd; i++) {
        const line = lines[i]
        // 检查参数是否传递给 URL 构造函数或 uri() 方法
        if (line && line.includes(param.name) && 
            (/new\s+URL|URI\.create|\.uri\s*\(/.test(line))) {
          return true
        }
      }
    }
    
    // 检查是否有 request.getParameter 等输入源
    if (/request\.(getParameter|getHeader|getInputStream)/.test(sourceCode)) {
      return true
    }
    
    return false
  }
  
  private createVulnerability(
    entry: AttackEntry,
    source: DecompileResult,
    rule: typeof SSRF_RULES[0],
    match: { line: number; code: string; match: string },
    validation: { hasValidation: boolean; validationType?: string }
  ): SSRFVulnerability | null {
    const id = `ssrf-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`
    
    // 确定严重级别
    const severity = rule.severity === 'critical' ? Severity.CRITICAL : 
                     rule.severity === 'high' ? Severity.HIGH : Severity.MEDIUM
    
    // 提取 URL 构造方式
    const urlConstruction = this.extractURLConstruction(match.code, source.sourceCode)
    
    // 提取相关参数
    const vulnerableParameter = entry.parameters.find(p => {
      // 检查参数名是否出现在 URL 构造相关的代码中
      const context = this.getContext(source.sourceCode, match.line, 10)
      return context.includes(p.name)
    })?.name
    
    return {
      id,
      type: VulnerabilityType.SSRF,
      cwe: 'CWE-918',
      owasp: 'A10:2021 - Server-Side Request Forgery',
      severity,
      title: `SSRF via ${rule.name}`,
      description: `${rule.description}\n\n攻击者可能利用此漏洞访问内网服务、云服务元数据或本地文件系统。`,
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
          'https://owasp.org/www-community/attacks/Server_Side_Request_Forgery',
          'https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html'
        ]
      },
      details: {
        ssrfType: rule.ssrfType,
        httpClient: rule.httpClient,
        sinkMethod: rule.sinkMethods[0],
        vulnerableParameter,
        urlConstruction,
        hasValidation: validation.hasValidation,
        validationType: validation.validationType
      },
      attackScenarios: SSRF_ATTACK_SCENARIOS
    }
  }
  
  private extractURLConstruction(matchCode: string, sourceCode: string): string {
    // 提取 URL 构造方式
    if (/new\s+URL\s*\(/.test(matchCode)) {
      return 'new URL(userInput)'
    } else if (/URI\.create\s*\(/.test(matchCode)) {
      return 'URI.create(userInput)'
    } else if (/\.uri\s*\(/.test(matchCode)) {
      return 'builder.uri(userInput)'
    }
    return 'unknown'
  }
  
  private getContext(sourceCode: string, lineNumber: number, contextSize: number): string {
    const lines = sourceCode.split('\n')
    const start = Math.max(0, lineNumber - contextSize - 1)
    const end = Math.min(lines.length, lineNumber + contextSize)
    return lines.slice(start, end).join('\n')
  }
  
  private generateSafeCodeExample(rule: typeof SSRF_RULES[0]): string {
    const urlValidationCode = `// 1. 解析 URL
URL url = new URL(userInput);
String host = url.getHost();
String protocol = url.getProtocol();

// 2. 验证协议
if (!protocol.equals("http") && !protocol.equals("https")) {
    throw new IllegalArgumentException("Only HTTP/HTTPS allowed");
}

// 3. 验证域名白名单
List<String> allowedHosts = Arrays.asList("api.example.com", "data.example.com");
if (!allowedHosts.contains(host)) {
    throw new IllegalArgumentException("Host not in whitelist");
}

// 4. 禁止内网 IP
if (isInternalIP(host)) {
    throw new IllegalArgumentException("Internal IPs not allowed");
}

// 5. 发起请求
HttpURLConnection conn = (HttpURLConnection) url.openConnection();`

    switch (rule.httpClient) {
      case 'HttpURLConnection':
        return urlValidationCode
        
      case 'RestTemplate':
        return `// 配置 UriTemplateHandler 进行验证
RestTemplate restTemplate = new RestTemplate();
restTemplate.setUriTemplateHandler(new DefaultUriBuilderFactory() {
    @Override
    public URI expand(String uriTemplate, Map<String, ?> uriVariables) {
        URI uri = super.expand(uriTemplate, uriVariables);
        validateURL(uri); // 自定义验证
        return uri;
    }
});`
        
      default:
        return rule.safeAlternative + '\n\n' + urlValidationCode
    }
  }
}
