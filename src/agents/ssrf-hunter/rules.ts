import type { SSRFRule } from './types'

export const SSRF_RULES: SSRFRule[] = [
  {
    name: 'Java URL.openConnection',
    description: '使用 URL.openConnection() 发起请求，URL 参数可能被攻击者控制',
    severity: 'high',
    patterns: [
      /new\s+URL\s*\([^)]+\).*openConnection/g,
      /URL\s+\w+\s*=\s*new\s+URL\s*\([^)]+\)/g,
      /\w+\.openConnection\s*\(/g,
    ],
    ssrfType: 'url_connection',
    httpClient: 'HttpURLConnection',
    sinkMethods: ['URL.openConnection', 'HttpURLConnection.connect', 'HttpURLConnection.getResponseCode'],
    safeAlternative: '使用 URL 白名单验证，限制协议为 http/https，禁止内网 IP'
  },
  
  {
    name: 'Java HttpClient',
    description: 'Java 11+ HttpClient 发送请求',
    severity: 'high',
    patterns: [
      /HttpClient\.newHttpClient/g,
      /HttpRequest\.newBuilder/g,
      /\.uri\s*\(\s*URI\.create\s*\(/g,
      /client\.send\s*\(/g,
    ],
    ssrfType: 'http_client',
    httpClient: 'HttpClient',
    sinkMethods: ['HttpClient.send', 'HttpClient.sendAsync'],
    safeAlternative: '实施 URL 白名单，使用正则验证域名'
  },
  
  {
    name: 'Spring RestTemplate',
    description: 'Spring RestTemplate 发起 HTTP 请求',
    severity: 'high',
    patterns: [
      /RestTemplate\s+\w+\s*=\s*new\s+RestTemplate/g,
      /restTemplate\.(getForEntity|getForObject|postForEntity|postForObject|exchange)\s*\(/g,
    ],
    ssrfType: 'rest_template',
    httpClient: 'RestTemplate',
    sinkMethods: ['RestTemplate.getForEntity', 'RestTemplate.postForEntity', 'RestTemplate.exchange'],
    safeAlternative: '使用 RestTemplate 配置 UriTemplateHandler 进行 URL 验证'
  },
  
  {
    name: 'Apache HttpClient',
    description: 'Apache HttpClient 发起请求',
    severity: 'high',
    patterns: [
      /HttpClientBuilder\./g,
      /CloseableHttpClient/g,
      /HttpGet\s*\(/g,
      /HttpPost\s*\(/g,
      /httpClient\.execute\s*\(/g,
    ],
    ssrfType: 'apache_http_client',
    httpClient: 'ApacheHttpClient',
    sinkMethods: ['HttpClient.execute', 'CloseableHttpClient.execute'],
    safeAlternative: '实施请求 URL 白名单验证'
  },
  
  {
    name: 'OkHttp',
    description: 'OkHttp 客户端发起请求',
    severity: 'high',
    patterns: [
      /OkHttpClient\s+\w+\s*=\s*new\s+OkHttpClient/g,
      /Request\.Builder\(\)/g,
      /\.url\s*\(/g,
      /client\.newCall\s*\(/g,
    ],
    ssrfType: 'okhttp',
    httpClient: 'OkHttp',
    sinkMethods: ['OkHttpClient.newCall', 'Call.execute'],
    safeAlternative: '拦截器中添加 URL 验证逻辑'
  },
  
  {
    name: 'Spring WebClient',
    description: 'Spring WebFlux WebClient',
    severity: 'high',
    patterns: [
      /WebClient\s*\.\s*builder\(\)/g,
      /WebClient\.create\s*\(/g,
      /\.uri\s*\(/g,
      /\.retrieve\s*\(/g,
    ],
    ssrfType: 'web_client',
    httpClient: 'WebClient',
    sinkMethods: ['WebClient.uri', 'WebClient.retrieve'],
    safeAlternative: '使用 UriBuilderFactory 进行 URL 验证'
  },
]

// SSRF 攻击场景
export const SSRF_ATTACK_SCENARIOS = [
  {
    name: '内网端口扫描',
    description: '利用 SSRF 扫描内网开放端口',
    payload: 'http://127.0.0.1:8080/admin',
    impact: '可访问内网管理后台'
  },
  {
    name: '云服务元数据窃取',
    description: '访问 AWS/GCP/阿里云元数据服务',
    payload: 'http://169.254.169.254/latest/meta-data/',
    impact: '获取云服务器 IAM 凭证'
  },
  {
    name: '本地文件读取',
    description: '通过 file 协议读取服务器文件',
    payload: 'file:///etc/passwd',
    impact: '读取系统敏感文件'
  },
  {
    name: 'Gopher 协议攻击',
    description: '使用 gopher 协议攻击内网服务',
    payload: 'gopher://127.0.0.1:6379/_*1%0d%0a...',
    impact: '攻击 Redis/MySQL 等内网服务'
  },
  {
    name: '内网主机发现',
    description: '探测内网存活主机',
    payload: 'http://10.0.0.1/ http://192.168.1.1/',
    impact: '发现内网拓扑结构'
  }
]

// 检测是否有 URL 验证
export function hasURLValidation(sourceCode: string): { hasValidation: boolean; validationType?: string } {
  // 检查 startsWith 验证
  if (/url\.(startsWith|contains)\s*\(\s*["'][^"']+["']\s*\)/.test(sourceCode)) {
    return { hasValidation: true, validationType: 'startsWith' }
  }
  
  // 检查正则验证
  if (/Pattern\.matches\s*\(|url\.(matches|regex)\s*\(/.test(sourceCode)) {
    return { hasValidation: true, validationType: 'regex' }
  }
  
  // 检查白名单数组验证
  if (/whitelist|allowedUrls|validDomains/i.test(sourceCode)) {
    return { hasValidation: true, validationType: 'whitelist' }
  }
  
  // 检查 URL 解析验证
  if (/new\s+URL\s*\([^)]+\).*\.getHost\s*\(/.test(sourceCode)) {
    return { hasValidation: true, validationType: 'host_validation' }
  }
  
  return { hasValidation: false }
}
