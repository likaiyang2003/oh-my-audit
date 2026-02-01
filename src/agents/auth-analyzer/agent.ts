import type { AttackEntry, Vulnerability, ConfigFile } from '../../types'
import { VulnerabilityType, Severity } from '../../types'
import type { DecompileResult } from '../../tools/decompiler/types'
import type { AuthAnalyzerOptions } from './types'
import { AUTH_PATTERNS, AUTH_CHECK_METHODS, hasIDORProtection, detectHardcodedCredentials, checkJWTSecurity } from './rules'

export class AuthAnalyzerAgent {
  private options: AuthAnalyzerOptions
  
  constructor(options: AuthAnalyzerOptions = {}) {
    this.options = {
      detectJWTIssues: true,
      detectIDOR: true,
      detectHardcodedCredentials: true,
      strictMode: true,
      ...options
    }
  }
  
  async audit(
    jarPath: string,
    entryPoints: AttackEntry[],
    decompiledSources: Map<string, DecompileResult>,
    configFiles: ConfigFile[]
  ): Promise<Vulnerability[]> {
    const vulnerabilities: Vulnerability[] = []
    
    // 1. 检测认证绕过
    for (const entry of entryPoints) {
      const source = decompiledSources.get(entry.className)
      if (!source || !source.isSuccess) continue
      
      // 检查是否有认证注解
      const hasAuth = this.hasAuthenticationCheck(source.sourceCode)
      
      // 如果高风险端点没有认证检查
      if (!hasAuth && (entry.riskLevel === 'high' || entry.riskLevel === 'critical')) {
        // 检查是否是管理员端点
        if (entry.urlPattern?.includes('admin') || entry.className.includes('Admin')) {
          vulnerabilities.push(this.createAuthBypassVulnerability(entry, source, 'admin_endpoint'))
        }
      }
      
      // 2. 检测 IDOR（水平越权）
      if (this.options.detectIDOR) {
        const idorVuln = this.detectIDOR(entry, source)
        if (idorVuln) {
          vulnerabilities.push(idorVuln)
        }
      }
      
      // 3. 检测 JWT 安全问题
      if (this.options.detectJWTIssues) {
        const jwtVuln = this.detectJWTIssues(entry, source)
        if (jwtVuln) {
          vulnerabilities.push(jwtVuln)
        }
      }
    }
    
    // 4. 检测配置文件中的硬编码凭证
    if (this.options.detectHardcodedCredentials) {
      for (const config of configFiles) {
        const credentials = detectHardcodedCredentials(config.content)
        for (const cred of credentials) {
          vulnerabilities.push(this.createHardcodedCredentialVulnerability(config, cred))
        }
      }
    }
    
    return vulnerabilities
  }
  
  private hasAuthenticationCheck(sourceCode: string): boolean {
    // 检查是否有认证相关的注解或代码
    for (const pattern of AUTH_CHECK_METHODS) {
      if (sourceCode.includes(pattern)) {
        return true
      }
    }
    
    // 检查 Spring Security 注解
    if (/@PreAuthorize|@Secured|@RolesAllowed/.test(sourceCode)) {
      return true
    }
    
    return false
  }
  
  private detectIDOR(entry: AttackEntry, source: DecompileResult): Vulnerability | null {
    // 检查是否有用户 ID 参数
    const hasUserIdParam = entry.parameters.some(p => 
      /userId|user_id|id/i.test(p.name)
    )
    
    if (!hasUserIdParam) return null
    
    // 检查是否有 IDOR 防护
    if (hasIDORProtection(source.sourceCode)) {
      return null
    }
    
    // 检查是否查询了用户数据
    if (!/findById|getById|queryById|findUser|getUser/i.test(source.sourceCode)) {
      return null
    }
    
    return {
      id: `idor-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`,
      type: VulnerabilityType.IDOR,
      cwe: 'CWE-639',
      owasp: 'A01:2021 - Broken Access Control',
      severity: Severity.HIGH,
      title: 'IDOR - Insecure Direct Object Reference',
      description: 'API 端点接受用户 ID 参数查询数据，但未验证当前用户是否有权访问该数据。攻击者可通过修改 ID 参数访问其他用户的数据。',
      location: {
        className: entry.className,
        methodName: entry.methodName,
        lineNumber: 0,
        codeSnippet: entry.urlPattern || ''
      },
      evidence: {
        sourceFlow: entry.parameters.filter(p => /userId|user_id|id/i.test(p.name)).map(p => p.name),
        sinkFlow: ['数据库查询操作']
      },
      remediation: {
        description: '始终验证数据所有权',
        codeExample: `// 危险代码：
User user = userDao.findById(userId);

// 安全代码：
Long currentUserId = getCurrentUserId();
User user = userDao.findByIdAndOwner(userId, currentUserId);
if (user == null) {
  throw new AccessDeniedException("无权访问此数据");
}`,
        references: [
          'https://owasp.org/www-community/attacks/Insecure_Direct_Object_References',
          'https://cheatsheetseries.owasp.org/cheatsheets/Insecure_Direct_Object_Reference_Prevention_Cheat_Sheet.html'
        ]
      }
    }
  }
  
  private detectJWTIssues(entry: AttackEntry, source: DecompileResult): Vulnerability | null {
    const jwtCheck = checkJWTSecurity(source.sourceCode)
    
    if (!jwtCheck.hasVulnerability) return null
    
    if (jwtCheck.type === 'jwt_none_algorithm') {
      return {
        id: `jwt-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`,
        type: VulnerabilityType.AUTH_BYPASS,
        cwe: 'CWE-327',
        owasp: 'A02:2021 - Cryptographic Failures',
        severity: Severity.CRITICAL,
        title: 'JWT None Algorithm Vulnerability',
        description: 'JWT 解析器接受 "none" 算法，攻击者可以伪造任意 JWT Token 并绕过身份验证。',
        location: {
          className: entry.className,
          methodName: entry.methodName,
          lineNumber: 0,
          codeSnippet: 'Jwts.parser().setAllowedAlgorithms("none", ...)'
        },
        evidence: {
          sourceFlow: ['JWT Token'],
          sinkFlow: ['JWT Parser with none algorithm']
        },
        remediation: {
          description: '移除 "none" 算法，只允许安全的算法（HS256, RS256 等）',
          codeExample: `// 危险代码：
Jwts.parser().setAllowedAlgorithms("none", "HS256").parseClaimsJws(token);

// 安全代码：
Jwts.parser().setAllowedAlgorithms("HS256", "RS256").parseClaimsJws(token);`,
          references: [
            'https://auth0.com/blog/critical-vulnerabilities-in-json-web-token-libraries/',
            'https://tools.ietf.org/html/rfc7518'
          ]
        }
      }
    }
    
    return null
  }
  
  private createAuthBypassVulnerability(
    entry: AttackEntry,
    source: DecompileResult,
    type: string
  ): Vulnerability {
    return {
      id: `auth-bypass-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`,
      type: VulnerabilityType.AUTH_BYPASS,
      cwe: 'CWE-306',
      owasp: 'A01:2021 - Broken Access Control',
      severity: Severity.CRITICAL,
      title: 'Authentication Bypass - Missing Auth Check',
      description: `管理端点 ${entry.urlPattern} 缺少身份验证检查，任何人都可以访问敏感功能。`,
      location: {
        className: entry.className,
        methodName: entry.methodName,
        lineNumber: 0,
        codeSnippet: source.sourceCode.substring(0, 200)
      },
      evidence: {
        sourceFlow: [],
        sinkFlow: [entry.urlPattern || 'admin endpoint']
      },
      remediation: {
        description: '为管理端点添加身份验证和授权检查',
        codeExample: `// 添加 Spring Security 注解
@PreAuthorize("hasRole('ADMIN')")
@GetMapping("/admin/users")
public List<User> getAllUsers() { ... }`,
        references: [
          'https://owasp.org/www-project-top-ten/2021/A01_2021-Broken_Access_Control',
          'https://docs.spring.io/spring-security/site/docs/current/reference/html5/'
        ]
      }
    }
  }
  
  private createHardcodedCredentialVulnerability(
    config: ConfigFile,
    cred: { type: string; value: string; line: number }
  ): Vulnerability {
    return {
      id: `hardcoded-cred-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`,
      type: VulnerabilityType.HARDCODED_CREDENTIALS,
      cwe: 'CWE-798',
      owasp: 'A02:2021 - Cryptographic Failures',
      severity: Severity.HIGH,
      title: `Hardcoded ${cred.type} in Configuration`,
      description: `配置文件 ${config.path} 中发现硬编码的 ${cred.type}，可能导致凭证泄露。`,
      location: {
        className: config.path,
        methodName: '',
        lineNumber: cred.line,
        codeSnippet: `${cred.type} = "${cred.value.substring(0, 10)}..."`
      },
      evidence: {
        sourceFlow: ['Configuration file'],
        sinkFlow: [cred.type]
      },
      remediation: {
        description: '使用环境变量或密钥管理服务存储敏感信息',
        codeExample: `# 使用环境变量
${cred.type} = \${${cred.type.toUpperCase()}}

# 或使用 Spring Cloud Config
spring.cloud.config.uri=http://config-server:8888`,
        references: [
          'https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html',
          'https://docs.aws.amazon.com/secretsmanager/latest/userguide/intro.html'
        ]
      }
    }
  }
}
