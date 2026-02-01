// 认证授权检测规则

export const AUTH_PATTERNS = {
  // Spring Security 注解
  PRE_AUTHORIZE: /@PreAuthorize\s*\(/g,
  SECURED: /@Secured\s*\(/g,
  ROLES_ALLOWED: /@RolesAllowed\s*\(/g,
  
  // JWT 相关
  JWT_PARSE: /Jwts\.parser\(\)/g,
  JWT_SET_ALLOWED_ALGORITHMS: /setAllowedAlgorithms\s*\(/g,
  JWT_NONE_ALGORITHM: /"none"|'none'/gi,
  JWT_VERIFY: /\.verify\s*\(/g,
  
  // IDOR 相关
  USER_ID_PARAM: /userId|user_id|userid/gi,
  FIND_BY_ID: /findById|getById|queryById/gi,
  
  // 硬编码凭证
  PASSWORD_PATTERN: /password\s*=\s*["'][^"']+["']/gi,
  SECRET_PATTERN: /secret\s*=\s*["'][^"']+["']/gi,
  API_KEY_PATTERN: /api[_-]?key\s*=\s*["'][^"']+["']/gi,
  JWT_SECRET_PATTERN: /jwt[_-]?secret\s*=\s*["'][^"']+["']/gi,
}

// 认证检查方法
export const AUTH_CHECK_METHODS = [
  '@PreAuthorize',
  '@Secured', 
  '@RolesAllowed',
  'SecurityContextHolder.getContext()',
  'getCurrentUser()',
  'checkPermission()',
  'isAuthenticated()',
  'hasRole()',
  'hasAuthority()'
]

// IDOR 防护检查
export function hasIDORProtection(sourceCode: string): boolean {
  // 检查是否有用户所有权验证
  const ownershipChecks = [
    /getCurrentUserId|currentUser|loggedInUser/gi,
    /ownership|belongsTo|isOwner/gi,
    /userId\s*==\s*currentUser|currentUser\.getId/gi,
  ]
  
  return ownershipChecks.some(pattern => pattern.test(sourceCode))
}

// 检测硬编码凭证
export function detectHardcodedCredentials(content: string): Array<{ type: string; value: string; line: number }> {
  const credentials: Array<{ type: string; value: string; line: number }> = []
  const lines = content.split('\n')
  
  // 调试输出：显示输入内容的行数
  console.log(`[DEBUG] detectHardcodedCredentials: 扫描 ${lines.length} 行内容`)
  
  const patterns = [
    { type: 'password', regex: /password\s*=\s*["']([^"']+)["']/gi },
    { type: 'secret', regex: /secret\s*=\s*["']([^"']+)["']/gi },
    { type: 'api_key', regex: /api[_-]?key\s*=\s*["']([^"']+)["']/gi },
    { type: 'jwt_secret', regex: /jwt[_-]?secret\s*=\s*["']([^"']+)["']/gi },
  ]
  
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i]
    
    for (const { type, regex } of patterns) {
      const matches = Array.from(line.matchAll(regex))
      for (const match of matches) {
        if (match[1]) {
          credentials.push({
            type,
            value: match[1],
            line: i + 1
          })
        }
      }
    }
  }
  
  return credentials
}

// JWT 安全检查
export function checkJWTSecurity(sourceCode: string): { hasVulnerability: boolean; type?: string } {
  // 检查 None 算法
  if (/setAllowedAlgorithms\s*\([^)]*["']none["']/gi.test(sourceCode)) {
    return { hasVulnerability: true, type: 'jwt_none_algorithm' }
  }
  
  // 检查弱密钥
  if (/jwt[_-]?secret\s*=\s*["'][^"']{1,16}["']/gi.test(sourceCode)) {
    return { hasVulnerability: true, type: 'jwt_weak_secret' }
  }
  
  return { hasVulnerability: false }
}
