# 代码安全审计插件设计文档

**项目**: code-security-audit  
**目标**: 基于 oh-my-opencode 架构的专业 Java 代码安全审计插件  
**创建日期**: 2026-01-31  
**状态**: 设计阶段 - 已保存核心架构

---

## 1. 项目概述

### 1.1 目标用户
安全工程师/渗透测试人员（需要专业级深度分析）

### 1.2 核心功能
- OWASP Top 10 漏洞检测（SQL 注入、XSS、SSRF、RCE、XXE 等）
- 认证/授权类漏洞（越权访问、JWT 安全问题、会话管理）
- 业务逻辑漏洞（支付逻辑、验证码绕过、并发问题）
- 配置/部署类漏洞（硬编码密钥、不安全反序列化、组件漏洞）
- JAR 包反编译与审计（本地反编译方案）

### 1.3 技术栈
- **运行时**: Bun (仅限 Bun)
- **基础**: @opencode-ai/sdk (参考 oh-my-opencode)
- **构建**: bun build + TypeScript
- **类型**: bun-types (绝不使用 @types/node)

---

## 2. 整体架构设计

### 2.1 目录结构

```
code-security-audit/
├── src/
│   ├── agents/                    # 专业检测 Agent
│   │   ├── sentry/               # 主控 Agent - 任务分发与编排
│   │   ├── jar-scanner/          # JAR 快速扫描（第 1 层）
│   │   ├── decompiler/           # 反编译协调 Agent
│   │   ├── sql-injector/         # SQL 注入深度审计
│   │   ├── ssrf-hunter/          # SSRF 检测专家
│   │   ├── rce-detector/         # RCE/命令注入检测
│   │   ├── xss-analyzer/         # XSS/前端漏洞
│   │   ├── xxefinder/            # XXE 检测
│   │   ├── auth-analyzer/        # 认证授权审计
│   │   ├── logic-inspector/      # 业务逻辑漏洞
│   │   └── crypto-checker/       # 加密/密钥安全
│   ├── tools/                     # 核心工具集
│   │   ├── jar-analyzer/         # JAR 结构分析工具
│   │   ├── decompiler/           # 反编译工具（CFR/FernFlower 封装）
│   │   ├── ast-security/         # 安全语义 AST 分析
│   │   ├── taint-engine/         # 污点追踪引擎
│   │   ├── call-graph/           # 调用链分析
│   │   ├── entry-finder/         # 攻击面发现（Servlet/Controller/Listener）
│   │   └── config-parser/        # XML/YAML/Properties 安全配置解析
│   ├── rules/                     # 检测规则库
│   │   ├── java/
│   │   │   ├── sql-injection/    # MyBatis/JDBC/JPA 注入规则
│   │   │   ├── ssrf/            # URL 构造/HTTP 客户端规则
│   │   │   ├── rce/             # Runtime.exec/ProcessBuilder 规则
│   │   │   ├── xss/             # 输出渲染规则
│   │   │   ├── xxe/             # XML 解析器配置规则
│   │   │   ├── auth/            # 认证绕过/越权规则
│   │   │   └── crypto/          # 不安全加密算法规则
│   │   └── severity/            # 严重级别映射
│   ├── hooks/                     # 生命周期钩子
│   │   ├── pre-scan/            # 扫描前：解压 JAR/识别框架
│   │   ├── severity-filter/     # 根据配置过滤级别
│   │   ├── evidence-collector/  # 证据链收集
│   │   └── report-generator/    # 生成专业报告
│   └── index.ts                   # 插件入口
├── tests/                         # 测试文件
├── docs/                          # 文档
├── package.json                   # 项目配置
└── AGENTS.md                      # 开发规范
```

### 2.2 核心设计理念

1. **多 Agent 协作** - 每个漏洞类型由专门 Agent 处理，类似 oh-my-opencode 的 Sisyphus 委派模式
2. **分层审计** - 三层审计流程：快速攻击面识别 → 智能反编译 → 深度漏洞审计
3. **深度分析** - 结合 AST 分析 + 污点追踪 + 语义理解
4. **证据链完整** - 每个漏洞报告包含完整的数据流追踪路径
5. **本地反编译** - 集成 CFR/FernFlower，完全自动化

---

## 3. 三层审计工作流

### 3.1 第 1 层：快速攻击面识别（30秒内完成）

**目标**: 快速发现攻击面，初步风险评估

**执行步骤**:
1. 解析 JAR Manifest，识别框架（Spring/Struts）
2. 提取所有 Servlet/Controller/Listener 入口
3. 扫描配置文件（web.xml/spring.xml）找危险配置
4. 识别高危依赖（如 Log4j 漏洞版本）

**输出**: 攻击面清单 + 高风险入口点

### 3.2 第 2 层：智能反编译（按需反编译）

**目标**: 只反编译关键类，避免性能开销

**执行步骤**:
1. 识别关键类（入口类 + 调用链相关类）
2. 使用 CFR/FernFlower 反编译
3. 识别危险函数（Runtime.exec/URL.openConnection 等）
4. 使用缓存避免重复反编译

**输出**: 反编译源码 + 危险函数位置

### 3.3 第 3 层：深度漏洞审计（并行 Agent 执行）

**目标**: 深度分析，生成带证据链的漏洞报告

**执行步骤**:
1. SQL 注入 Agent：追踪污点从入口到数据库
2. SSRF Agent：分析 URL 构造和请求发起
3. RCE Agent：追踪命令执行链
4. 逻辑漏洞 Agent：分析条件判断和权限检查

**输出**: 带完整证据链的漏洞报告

---

## 4. 核心组件设计（已规划）

### 4.1 JAR 分析工具 (`tools/jar-analyzer/`)

**功能**: 快速识别 JAR 结构、框架类型、攻击面入口

**核心接口**:
```typescript
interface JarAnalysisResult {
  manifest: JarManifest                    // JAR 元数据
  framework: DetectedFramework             // 检测到的框架
  entryPoints: AttackEntry[]              // 攻击面入口
  dependencies: Dependency[]              // 依赖库清单
  configFiles: ConfigFile[]               // 配置文件
  riskScore: number                       // 初步风险评分
}

interface AttackEntry {
  type: 'servlet' | 'controller' | 'listener' | 'filter' | 'websocket'
  className: string
  urlPattern?: string                      // 如 /api/user/*
  httpMethods: string[]                   // GET/POST/PUT/DELETE
  parameters: ParameterInfo[]             // 参数名称和类型
  riskLevel: 'critical' | 'high' | 'medium' | 'low'
}
```

**工作原理**:
1. 解压 JAR 到临时目录（使用 bun 的解压能力）
2. 读取 `META-INF/MANIFEST.MF` 识别主类、版本
3. 扫描 `WEB-INF/web.xml` 找 Servlet 映射
4. 识别 Spring 注解（`@Controller`, `@RequestMapping`）
5. 分析类路径找危险依赖（如存在漏洞的组件）

**输出示例**:
```
[攻击面识别完成]
框架: Spring Boot 2.7.0
入口点: 23 个
  - CRITICAL: 3 个 (文件上传/命令执行入口)
  - HIGH: 8 个 (用户输入处理)
配置文件: 5 个 (发现数据库配置、JWT密钥)
依赖风险: 2 个高危依赖 (Log4j 2.14.1)
```

### 4.2 反编译工具 (`tools/decompiler/`)

**设计目标：**
- 集成 CFR/FernFlower 反编译器
- 智能缓存避免重复反编译
- 按需反编译（只反编译关键类）
- 批量并行反编译优化

**核心架构：**

```typescript
// 反编译器接口
interface DecompilerEngine {
  decompile(classFile: Buffer, className: string): Promise<DecompileResult>
  decompileBatch(classFiles: ClassFile[], options: BatchOptions): Promise<DecompileResult[]>
}

// CFR 反编译器实现
class CFRDecompiler implements DecompilerEngine {
  private cfrJarPath: string
  private javaPath: string
  
  async decompile(classFile: Buffer, className: string): Promise<DecompileResult> {
    // 调用 CFR 反编译单个类
  }
}

// 反编译管理器（核心）
class DecompileManager {
  private cache: Map<string, DecompileResult>  // MD5 -> 结果缓存
  private engine: DecompilerEngine
  
  async decompileClass(
    jarPath: string, 
    className: string, 
    options: DecompileOptions
  ): Promise<DecompileResult> {
    // 1. 检查缓存
    const cacheKey = this.generateCacheKey(jarPath, className)
    if (this.cache.has(cacheKey)) {
      return this.cache.get(cacheKey)!
    }
    
    // 2. 从 JAR 提取 class 文件
    const classFile = await this.extractClass(jarPath, className)
    
    // 3. 反编译
    const result = await this.engine.decompile(classFile, className)
    
    // 4. 缓存结果
    this.cache.set(cacheKey, result)
    
    return result
  }
  
  // 智能批量反编译（关键类优先）
  async decompileCriticalClasses(
    jarPath: string,
    classNames: string[],
    priority: 'high' | 'medium' | 'low'
  ): Promise<DecompileResult[]> {
    const batchSize = 10  // 每批 10 个类
    const results: DecompileResult[] = []
    
    for (let i = 0; i < classNames.length; i += batchSize) {
      const batch = classNames.slice(i, i + batchSize)
      const batchResults = await Promise.all(
        batch.map(name => this.decompileClass(jarPath, name, {}))
      )
      results.push(...batchResults)
    }
    
    return results
  }
}

// 反编译结果
interface DecompileResult {
  className: string
  sourceCode: string                    // Java 源代码
  packageName: string
  imports: string[]                     // 导入语句
  methods: MethodInfo[]                 // 方法列表
  fields: FieldInfo[]                   // 字段列表
  innerClasses: string[]                // 内部类
  isSuccess: boolean
  error?: string                        // 反编译失败原因
  decompileTime: number                 // 反编译耗时(ms)
  cacheHit: boolean                     // 是否命中缓存
}

interface MethodInfo {
  name: string
  signature: string                     // 完整方法签名
  parameters: ParameterInfo[]
  returnType: string
  isPublic: boolean
  annotations: string[]
  body: string                          // 方法体代码
  linesOfCode: number
}
```

**缓存策略：**

```typescript
// 缓存存储结构
interface DecompileCache {
  version: string                       // 缓存版本
  entries: Map<string, CacheEntry>
}

interface CacheEntry {
  md5: string                           // class 文件 MD5
  sourceCode: string
  timestamp: number
  jarPath: string                       // 原始 JAR 路径
  className: string
}

// 缓存管理
class DecompileCacheManager {
  private cacheDir: string = '.security-audit/cache/decompile'
  
  generateCacheKey(jarPath: string, className: string): string {
    const md5 = calculateFileMD5(jarPath)
    return `${md5}:${className}`
  }
  
  // 缓存清理（LRU 策略）
  async cleanup(maxAge: number = 7 * 24 * 60 * 60 * 1000): Promise<void> {
    // 删除超过7天的缓存
  }
}
```

**性能优化策略：**

1. **预解压 JAR** - 一次性解压到临时目录，避免重复 IO
2. **并行反编译** - 使用 Promise.all 批量处理（每批 10 个类）
3. **内存缓存** - 热点类常驻内存
4. **磁盘缓存** - 持久化缓存，重启后仍然有效
5. **增量更新** - 只反编译变更的类

**错误处理：**

```typescript
enum DecompileErrorType {
  CLASS_NOT_FOUND = 'CLASS_NOT_FOUND',
  CORRUPTED_CLASS = 'CORRUPTED_CLASS',
  UNSUPPORTED_VERSION = 'UNSUPPORTED_VERSION',
  OBFUSCATED = 'OBFUSCATED',
  OUT_OF_MEMORY = 'OUT_OF_MEMORY',
}

class DecompileError extends Error {
  type: DecompileErrorType
  className: string
  jarPath: string
}
```

### 4.3 污点追踪引擎 (`tools/taint-engine/`)

**设计目标：**
- 精准识别污点数据源（用户输入）
- 追踪数据流传播路径
- 识别污点汇聚点（危险操作）

**核心架构：**

```typescript
// 污点追踪引擎
class TaintEngine {
  private callGraph: CallGraph
  private dataFlowGraph: DataFlowGraph
  private sourceIdentifiers: SourceIdentifier[]
  private sinkIdentifiers: SinkIdentifier[]
  
  async analyze(
    entryMethod: MethodInfo, 
    sourceCode: string,
    classContext: ClassContext
  ): Promise<TaintAnalysisResult> {
    // 1. 构建数据流图
    this.buildDataFlowGraph(sourceCode)
    
    // 2. 识别所有污染源
    const sources = this.identifySources(entryMethod)
    
    // 3. 从每个源开始追踪
    const flows: TaintFlow[] = []
    for (const source of sources) {
      const flow = this.trackTaint(source)
      if (flow.reachesSink) {
        flows.push(flow)
      }
    }
    
    return { flows, summary: this.generateSummary(flows) }
  }
  
  // 追踪单个污点
  private trackTaint(source: TaintSource): TaintFlow {
    const visited = new Set<string>()
    const path: TaintStep[] = []
    
    const dfs = (current: DataFlowNode, depth: number = 0) => {
      if (depth > 50) return // 防止无限递归
      if (visited.has(current.id)) return
      visited.add(current.id)
      
      // 检查是否是汇聚点
      if (this.isSink(current)) {
        path.push({ node: current, type: 'sink' })
        return { reached: true, sink: current }
      }
      
      // 继续追踪传播
      for (const next of this.getPropagations(current)) {
        path.push({ node: current, type: 'propagation', to: next })
        const result = dfs(next, depth + 1)
        if (result.reached) return result
      }
      
      return { reached: false }
    }
    
    return {
      source,
      path,
      reachesSink: path.some(p => p.type === 'sink'),
      sink: path.find(p => p.type === 'sink')?.node
    }
  }
}

// 污点源定义（用户可控输入）
interface TaintSource {
  type: SourceType
  variable: string
  location: SourceLocation
  method: string
  context: string
}

enum SourceType {
  HTTP_PARAMETER = 'HTTP_PARAMETER',
  HTTP_HEADER = 'HTTP_HEADER',
  HTTP_BODY = 'HTTP_BODY',
  PATH_VARIABLE = 'PATH_VARIABLE',
  QUERY_STRING = 'QUERY_STRING',
  COOKIE = 'COOKIE',
  FILE_UPLOAD = 'FILE_UPLOAD',
  EXTERNAL_API = 'EXTERNAL_API',
  DATABASE = 'DATABASE',
}

// 污点汇聚点定义（危险操作）
interface TaintSink {
  type: SinkType
  method: string
  location: SourceLocation
  vulnerability: VulnerabilityType
  severity: 'critical' | 'high' | 'medium'
}

enum SinkType {
  SQL_EXECUTION = 'SQL_EXECUTION',
  COMMAND_EXECUTION = 'COMMAND_EXECUTION',
  URL_CONNECTION = 'URL_CONNECTION',
  FILE_OPERATION = 'FILE_OPERATION',
  RESPONSE_WRITE = 'RESPONSE_WRITE',
  XML_PARSE = 'XML_PARSE',
  DESERIALIZATION = 'DESERIALIZATION',
  REFLECTION = 'REFLECTION',
}

// 污点传播规则
interface PropagationRule {
  from: string
  to: string
  through: string
  isSanitizer: boolean
  confidence: number
}

// 预定义的传播规则库
const DEFAULT_PROPAGATION_RULES: PropagationRule[] = [
  // String 操作 - 传播污点
  { from: '$a', to: '$result', through: 'String.concat', isSanitizer: false, confidence: 1.0 },
  { from: '$a', to: '$result', through: 'StringBuilder.append', isSanitizer: false, confidence: 1.0 },
  { from: '$a', to: '$result', through: 'String.format', isSanitizer: false, confidence: 1.0 },
  
  // 净化操作
  { from: '$a', to: '$result', through: 'ESAPI.encoder.encodeForSQL', isSanitizer: true, confidence: 0.95 },
  { from: '$a', to: '$result', through: 'PreparedStatement.setString', isSanitizer: true, confidence: 0.90 },
  
  // 集合操作
  { from: '$list', to: '$element', through: 'List.get', isSanitizer: false, confidence: 1.0 },
  { from: '$element', to: '$list', through: 'List.add', isSanitizer: false, confidence: 1.0 },
]
```

**污点追踪结果：**

```typescript
interface TaintAnalysisResult {
  flows: TaintFlow[]
  summary: TaintSummary
  coverage: AnalysisCoverage
}

interface TaintFlow {
  id: string
  source: TaintSource
  sink: TaintSink
  path: TaintStep[]
  reachesSink: boolean
  vulnerability: VulnerabilityInfo
  evidence: EvidenceChain
}

interface EvidenceChain {
  sourceLocation: string
  sinkLocation: string
  dataFlow: string[]
  variables: string[]
  methods: string[]
}

interface VulnerabilityInfo {
  type: VulnerabilityType
  cwe: string
  owasp: string
  severity: 'critical' | 'high' | 'medium' | 'low'
  description: string
  remediation: string
  references: string[]
}

enum VulnerabilityType {
  SQL_INJECTION = 'SQL_INJECTION',
  COMMAND_INJECTION = 'COMMAND_INJECTION',
  SSRF = 'SSRF',
  XSS = 'XSS',
  XXE = 'XXE',
  PATH_TRAVERSAL = 'PATH_TRAVERSAL',
  INSECURE_DESERIALIZATION = 'INSECURE_DESERIALIZATION',
  HARDCODED_CREDENTIALS = 'HARDCODED_CREDENTIALS',
}
```

### 4.4 SQL 注入 Agent (`agents/sql-injector/`)

**设计目标：**
- 检测 JDBC、MyBatis、JPA 等多种数据访问方式的 SQL 注入
- 区分不同严重级别（拼接 SQL vs 参数化查询误用）
- 提供完整的修复建议

**核心架构：**

```typescript
// SQL 注入检测 Agent
class SQLInjectionAgent {
  private taintEngine: TaintEngine
  private sqlPatternMatcher: SQLPatternMatcher
  private ormDetector: ORMFrameworkDetector
  
  async audit(
    jarPath: string,
    entryPoints: AttackEntry[],
    decompiledSources: Map<string, DecompileResult>
  ): Promise<SQLInjectionVulnerability[]> {
    const vulnerabilities: SQLInjectionVulnerability[] = []
    
    for (const entry of entryPoints) {
      const source = decompiledSources.get(entry.className)
      if (!source) continue
      
      // 使用污点引擎追踪到 SQL 执行点
      const taintResult = await this.taintEngine.analyze(
        { name: entry.methodName, className: entry.className },
        source.sourceCode,
        { package: source.packageName, imports: source.imports }
      )
      
      // 分析每条到达 SQL 执行的污点流
      for (const flow of taintResult.flows) {
        if (flow.sink.type === 'SQL_EXECUTION') {
          const vuln = await this.analyzeSQLInjection(flow, source)
          if (vuln) vulnerabilities.push(vuln)
        }
      }
    }
    
    return vulnerabilities
  }
  
  // MyBatis 专项检测
  private analyzeMyBatisInjection(flow: TaintFlow, source: DecompileResult): SQLInjectionVulnerability | null {
    const sinkMethod = flow.sink.method
    
    // 检测 ${} 拼接（高危）
    if (sinkMethod.includes('${')) {
      return {
        type: 'SQL_INJECTION',
        cwe: 'CWE-89',
        details: {
          ormFramework: 'mybatis',
          injectionType: 'string_concatenation',
          severity: 'critical'
        },
        remediation: {
          description: '使用 #{} 替代 ${} 进行参数绑定',
          safeCodeExample: 'SELECT * FROM users WHERE id = #{userId}'
        }
      } as SQLInjectionVulnerability
    }
    
    return null
  }
}

// SQL 注入漏洞报告
interface SQLInjectionVulnerability {
  id: string
  type: 'SQL_INJECTION'
  cwe: 'CWE-89'
  owasp: 'A03:2021 - Injection'
  
  location: {
    className: string
    methodName: string
    lineNumber: number
    codeSnippet: string
  }
  
  evidence: {
    source: TaintSource
    sink: TaintSink
    dataFlow: TaintStep[]
    sqlQuery?: string
  }
  
  details: {
    ormFramework: 'mybatis' | 'jpa' | 'jdbc' | 'hibernate' | 'unknown'
    injectionType: string
    severity: 'critical' | 'high' | 'medium'
    confidence: number
  }
  
  remediation: {
    description: string
    safeCodeExample: string
    steps: string[]
    references: string[]
  }
}
```

### 4.5 SSRF Agent (`agents/ssrf-hunter/`)

**设计目标：**
- 检测服务器端请求伪造（SSRF）漏洞
- 支持多种 HTTP 客户端（HttpURLConnection、Apache HttpClient、OkHttp、RestTemplate）
- 识别内网攻击、云服务元数据访问、文件读取等 SSRF 场景

**核心架构：**

```typescript
class SSRFAgent {
  private taintEngine: TaintEngine
  private urlPatternMatcher: URLPatternMatcher
  private httpClientDetector: HTTPClientDetector
  
  async audit(
    jarPath: string,
    entryPoints: AttackEntry[],
    decompiledSources: Map<string, DecompileResult>
  ): Promise<SSRFVulnerability[]> {
    const vulnerabilities: SSRFVulnerability[] = []
    
    for (const entry of entryPoints) {
      const source = decompiledSources.get(entry.className)
      if (!source) continue
      
      const taintResult = await this.taintEngine.analyze(
        { name: entry.methodName, className: entry.className },
        source.sourceCode,
        { package: source.packageName, imports: source.imports }
      )
      
      for (const flow of taintResult.flows) {
        if (flow.sink.type === 'URL_CONNECTION') {
          const vuln = await this.analyzeSSRF(flow, source)
          if (vuln) vulnerabilities.push(vuln)
        }
      }
    }
    
    return vulnerabilities
  }
}

enum SSRFType {
  INTERNAL_NETWORK_ACCESS = 'INTERNAL_NETWORK_ACCESS',
  CLOUD_METADATA_ACCESS = 'CLOUD_METADATA_ACCESS',
  FILE_READ = 'FILE_READ',
  PROTOCOL_SPOOFING = 'PROTOCOL_SPOOFING',
  GENERIC = 'GENERIC'
}

type HTTPClientType = 
  | 'HttpURLConnection' 
  | 'ApacheHttpClient' 
  | 'OkHttp' 
  | 'RestTemplate'
  | 'WebClient'
  | 'Unknown'

interface SSRFVulnerability {
  id: string
  type: 'SSRF'
  cwe: 'CWE-918'
  owasp: 'A10:2021 - Server-Side Request Forgery'
  
  details: {
    ssrfType: SSRFType
    httpClient: HTTPClientType
    severity: 'critical' | 'high' | 'medium'
    confidence: number
    canAccessInternalNetwork: boolean
    canAccessMetadata: boolean
    canReadFiles: boolean
  }
  
  attackScenarios: {
    name: string
    description: string
    payload: string
    impact: string
  }[]
}
```

### 4.6 RCE Agent (`agents/rce-detector/`)

**设计目标：**
- 检测远程代码执行（RCE）和命令注入漏洞
- 支持多种命令执行方式（Runtime.exec、ProcessBuilder、ScriptEngine、EL 表达式等）
- 识别命令链构造、参数注入、反序列化导致的 RCE

**核心架构：**

```typescript
class RCEAgent {
  private taintEngine: TaintEngine
  private commandPatternMatcher: CommandPatternMatcher
  
  async audit(
    jarPath: string,
    entryPoints: AttackEntry[],
    decompiledSources: Map<string, DecompileResult>
  ): Promise<RCEVulnerability[]> {
    const vulnerabilities: RCEVulnerability[] = []
    
    for (const entry of entryPoints) {
      const source = decompiledSources.get(entry.className)
      if (!source) continue
      
      const taintResult = await this.taintEngine.analyze(
        { name: entry.methodName, className: entry.className },
        source.sourceCode,
        { package: source.packageName, imports: source.imports }
      )
      
      for (const flow of taintResult.flows) {
        if (this.isRCESink(flow.sink)) {
          const vuln = await this.analyzeRCE(flow, source)
          if (vuln) vulnerabilities.push(vuln)
        }
      }
    }
    
    return vulnerabilities
  }
  
  private isRCESink(sink: TaintSink): boolean {
    return [
      'COMMAND_EXECUTION',
      'SCRIPT_EXECUTION', 
      'EL_EVALUATION',
      'DESERIALIZATION',
      'REFLECTION'
    ].includes(sink.type)
  }
}

enum RCEType {
  COMMAND_INJECTION = 'COMMAND_INJECTION',
  ARGUMENT_INJECTION = 'ARGUMENT_INJECTION',
  SCRIPT_INJECTION = 'SCRIPT_INJECTION',
  EL_EXPRESSION_INJECTION = 'EL_EXPRESSION_INJECTION',
  DESERIALIZATION_RCE = 'DESERIALIZATION_RCE',
  REFLECTION_RCE = 'REFLECTION_RCE',
  TEMPLATE_INJECTION = 'TEMPLATE_INJECTION',
  GENERIC_RCE = 'GENERIC_RCE'
}

interface RCEVulnerability {
  id: string
  type: 'RCE'
  cwe: 'CWE-78' | 'CWE-94' | 'CWE-502' | 'CWE-917'
  owasp: 'A03:2021 - Injection'
  
  details: {
    rceType: RCEType
    sinkType: string
    severity: 'critical' | 'high' | 'medium'
    confidence: number
    isDirectUserInput: boolean
    hasSanitization: boolean
  }
  
  attackPayloads: {
    type: string
    payload: string
    description: string
  }[]
  
  remediation: {
    description: string
    safeCodeExample: string
    steps: string[]
  }
}

// RCE 危险函数库
const RCE_SINK_PATTERNS = [
  { pattern: 'Runtime.getRuntime().exec', type: 'COMMAND_EXECUTION', severity: 'critical' },
  { pattern: 'ProcessBuilder', type: 'COMMAND_EXECUTION', severity: 'critical' },
  { pattern: 'ScriptEngine.eval', type: 'SCRIPT_EXECUTION', severity: 'critical' },
  { pattern: 'ELProcessor.eval', type: 'EL_EVALUATION', severity: 'critical' },
  { pattern: 'ObjectInputStream.readObject', type: 'DESERIALIZATION', severity: 'critical' },
  { pattern: 'XMLDecoder.readObject', type: 'DESERIALIZATION', severity: 'critical' }
]
```

### 4.7 认证授权 Agent (`agents/auth-analyzer/`)

**设计目标：**
- 检测认证绕过、越权访问、JWT 安全问题
- 识别硬编码凭证、弱密码策略
- 分析权限检查逻辑缺陷

**核心架构：**

```typescript
class AuthAnalyzerAgent {
  private taintEngine: TaintEngine
  private authPatternDetector: AuthPatternDetector
  private jwtAnalyzer: JWTSecurityAnalyzer
  
  async audit(
    jarPath: string,
    entryPoints: AttackEntry[],
    decompiledSources: Map<string, DecompileResult>,
    configFiles: ConfigFile[]
  ): Promise<AuthVulnerability[]> {
    const vulnerabilities: AuthVulnerability[] = []
    
    for (const entry of entryPoints) {
      const source = decompiledSources.get(entry.className)
      if (!source) continue
      
      // 检测认证绕过
      const bypassVulns = await this.detectAuthBypass(entry, source)
      vulnerabilities.push(...bypassVulns)
      
      // 检测越权访问
      const privilegeVulns = await this.detectPrivilegeEscalation(entry, source)
      vulnerabilities.push(...privilegeVulns)
      
      // 分析 JWT 安全
      const jwtVulns = await this.analyzeJWTSecurity(source)
      vulnerabilities.push(...jwtVulns)
    }
    
    // 检测硬编码凭证
    const credentialVulns = await this.detectHardcodedCredentials(configFiles)
    vulnerabilities.push(...credentialVulns)
    
    return vulnerabilities
  }
}

enum AuthVulnerabilityType {
  AUTH_BYPASS = 'AUTH_BYPASS',
  HORIZONTAL_PRIVILEGE_ESCALATION = 'HORIZONTAL_PRIVILEGE_ESCALATION',
  VERTICAL_PRIVILEGE_ESCALATION = 'VERTICAL_PRIVILEGE_ESCALATION',
  JWT_NONE_ALGORITHM = 'JWT_NONE_ALGORITHM',
  JWT_WEAK_SECRET = 'JWT_WEAK_SECRET',
  HARDCODED_CREDENTIALS = 'HARDCODED_CREDENTIALS',
  INSECURE_COOKIE = 'INSECURE_COOKIE'
}

interface AuthVulnerability {
  id: string
  type: AuthVulnerabilityType
  cwe: string
  owasp: string
  
  details: {
    description: string
    severity: 'critical' | 'high' | 'medium' | 'low'
    confidence: number
    entryPoint?: AttackEntry
    missingChecks?: string[]
  }
  
  attackScenario?: {
    description: string
    payload?: string
    impact: string
  }
  
  remediation: {
    description: string
    safeCodeExample?: string
    steps: string[]
  }
}
```

---

## 5. 待细化组件

### 5.1 反编译工具 (`tools/decompiler/`)
✅ **已完成详细设计** - 见 4.2 节

### 5.2 污点追踪引擎 (`tools/taint-engine/`)
✅ **已完成详细设计** - 见 4.3 节

### 5.3 各专项 Agent
- ✅ SQL 注入 Agent 详细设计 - 见 4.4 节
- ✅ SSRF Agent 详细设计 - 见 4.5 节
- ✅ RCE Agent 详细设计 - 见 4.6 节
- ✅ 认证授权 Agent 详细设计 - 见 4.7 节
- ✅ 业务逻辑 Agent 详细设计 - 见 4.8 节

### 5.4 规则引擎 (`rules/`)
- SQL 注入规则（MyBatis/JDBC/JPA）
- SSRF 规则（URL 构造模式）
- RCE 规则（危险函数调用）
- 加密规则（不安全算法识别）

### 5.5 报告生成器 (`hooks/report-generator/`)
- 专业渗透测试报告格式
- 证据链展示
- CWE/OWASP 映射

---

## 6. 开发规范

### 6.1 代码风格
- 使用 bun-types，绝不使用 @types/node
- 严格 TypeScript 模式
- 显式类型标注
- 工厂函数命名：`createXXXTool`、`createXXXAgent`
- 目录/文件：kebab-case

### 6.2 TDD 要求
- 先写测试再写实现
- 测试文件：`*.test.ts` 与源文件同目录
- BDD 注释：`#given`、`#when`、`#then`

### 6.3 项目命令
```bash
bun run typecheck              # 类型检查
bun run build                  # 构建 ESM
bun test                       # 运行所有测试
bun test path/to/file.test.ts  # 运行单个测试
```

---

## 7. 下一步工作计划

1. [ ] 细化反编译工具设计
2. [ ] 设计污点追踪引擎
3. [ ] 设计 SQL 注入 Agent
4. [ ] 设计 SSRF Agent
5. [ ] 设计 RCE Agent
6. [ ] 设计规则引擎架构
7. [ ] 设计报告生成器

---

**备注**: 本文档保存了前期头脑风暴的所有设计成果，后续设计将基于此文档继续完善。
