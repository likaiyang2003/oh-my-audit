# code-security-audit 插件实现计划

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** 基于 oh-my-opencode 架构实现专业的 Java 代码安全审计插件

**Architecture:** 分层审计架构（快速攻击面识别 → 智能反编译 → 深度漏洞审计），多 Agent 协作模式

**Tech Stack:** Bun, TypeScript, @opencode-ai/sdk, CFR/FernFlower (Java 反编译)

**Design Doc:** See `docs/plans/2026-01-31-code-security-audit-design.md`  
**Progress Report:** See `PROGRESS-REPORT.md`

---

## 📊 当前进度 (2026-02-01)

| 任务 | 状态 | 代码行 | 测试 |
|------|------|--------|------|
| Task 1: 项目初始化 | ✅ 完成 | ~90 | - |
| Task 2: 基础类型定义 | ✅ 完成 | 95 | 75 |
| Task 3: JAR 分析工具 | ✅ 完成 | 278 | 57 |
| Task 4: CFR 反编译器 | ✅ 完成 | 432 | 80 |
| Task 5: 污点追踪引擎 | ⏳ 待开始 | - | - |
| ... | ... | ... | ... |

**总体进度**: 4/16 任务完成 (**25%**)

---

## 实施策略

- **Phase 1:** 核心基础设施（JAR 分析器 + 反编译工具）- 预计 2-3 天
- **Phase 2:** 污点追踪引擎 - 预计 3-4 天  
- **Phase 3:** 专项检测 Agent（SQL 注入、SSRF、RCE）- 预计 5-7 天
- **Phase 4:** 认证授权 + 业务逻辑 Agent - 预计 4-5 天
- **Phase 5:** 报告生成器 + 集成测试 - 预计 3-4 天

---

## Phase 1: 核心基础设施

### Task 1: 项目初始化

**Files:**
- Create: `package.json`
- Create: `tsconfig.json`
- Create: `bunfig.toml`
- Create: `AGENTS.md`
- Create: `README.md`

**Step 1: 初始化 Bun 项目**

```bash
bun init -y
```

**Step 2: 配置 package.json**

```json
{
  "name": "code-security-audit",
  "version": "1.0.0",
  "description": "Professional Java code security audit plugin for OpenCode",
  "main": "dist/index.js",
  "types": "dist/index.d.ts",
  "type": "module",
  "scripts": {
    "build": "bun build src/index.ts --outdir dist --target bun --format esm && tsc --emitDeclarationOnly",
    "typecheck": "tsc --noEmit",
    "test": "bun test",
    "clean": "rm -rf dist"
  },
  "dependencies": {
    "@opencode-ai/sdk": "^1.1.19",
    "adm-zip": "^0.5.10",
    "js-yaml": "^4.1.1"
  },
  "devDependencies": {
    "bun-types": "latest",
    "typescript": "^5.7.3",
    "@types/adm-zip": "^0.5.0",
    "@types/js-yaml": "^4.0.9"
  }
}
```

**Step 3: 配置 tsconfig.json**

```json
{
  "compilerOptions": {
    "target": "ESNext",
    "module": "ESNext",
    "moduleResolution": "bundler",
    "declaration": true,
    "declarationDir": "dist",
    "outDir": "dist",
    "rootDir": "src",
    "strict": true,
    "esModuleInterop": true,
    "skipLibCheck": true,
    "lib": ["ESNext"],
    "types": ["bun-types"]
  },
  "include": ["src/**/*"],
  "exclude": ["node_modules", "dist"]
}
```

**Step 4: 配置 bunfig.toml**

```toml
[test]
preload = ["./test-setup.ts"]
```

**Step 5: 安装依赖**

```bash
bun install
```

**Step 6: Commit**

```bash
git add package.json tsconfig.json bunfig.toml README.md
git add bun.lock
git commit -m "feat: initialize project structure"
```

---

### Task 2: 基础类型定义

**Files:**
- Create: `src/types/index.ts`
- Create: `src/types/vulnerability.ts`
- Test: `src/types/index.test.ts`

**Step 1: 编写测试**

```typescript
// src/types/index.test.ts
import { describe, it, expect } from 'bun:test'
import type { JarAnalysisResult, AttackEntry } from './index'

describe('types', () => {
  it('should define JarAnalysisResult interface', () => {
    const result: JarAnalysisResult = {
      manifest: { mainClass: 'com.example.App', version: '1.0.0' },
      framework: { type: 'spring-boot', version: '2.7.0', indicators: [] },
      entryPoints: [],
      dependencies: [],
      configFiles: [],
      riskScore: 0
    }
    expect(result.manifest.mainClass).toBe('com.example.App')
  })
})
```

**Step 2: 运行测试确认失败**

```bash
bun test src/types/index.test.ts
```

**Step 3: 实现类型定义**

```typescript
// src/types/index.ts
export interface JarManifest {
  mainClass?: string
  version?: string
  implementationTitle?: string
}

export interface DetectedFramework {
  type: 'spring-boot' | 'spring-mvc' | 'struts2' | 'servlet' | 'unknown'
  version?: string
  indicators: string[]
}

export interface AttackEntry {
  type: 'servlet' | 'controller' | 'listener' | 'filter' | 'websocket'
  className: string
  methodName: string
  urlPattern?: string
  httpMethods: string[]
  parameters: ParameterInfo[]
  riskLevel: 'critical' | 'high' | 'medium' | 'low'
}

export interface ParameterInfo {
  name: string
  type: string
  annotation?: string
  source: 'query' | 'path' | 'body' | 'header' | 'cookie' | 'form'
}

export interface Dependency {
  groupId: string
  artifactId: string
  version: string
  isVulnerable: boolean
  knownVulnerabilities?: string[]
}

export interface ConfigFile {
  path: string
  type: 'xml' | 'yaml' | 'properties'
  content: string
}

export interface JarAnalysisResult {
  manifest: JarManifest
  framework: DetectedFramework
  entryPoints: AttackEntry[]
  dependencies: Dependency[]
  configFiles: ConfigFile[]
  riskScore: number
}

export * from './vulnerability'
```

**Step 4: 运行测试确认通过**

```bash
bun test src/types/index.test.ts
```

**Step 5: Commit**

```bash
git add src/types/
git commit -m "feat: add core type definitions"
```

---

### Task 3: JAR 分析工具

**Files:**
- Create: `src/tools/jar-analyzer/index.ts`
- Create: `src/tools/jar-analyzer/types.ts`
- Create: `src/tools/jar-analyzer/analyzer.ts`
- Test: `src/tools/jar-analyzer/analyzer.test.ts`

**参考设计文档 4.1 节实现**

核心功能：
1. 解压 JAR 并解析 MANIFEST.MF
2. 检测 Spring Boot / Spring MVC / Struts2 框架
3. 提取 Controller / Servlet 入口点
4. 分析 Maven 依赖并检测已知漏洞
5. 提取配置文件并检测硬编码凭证

**测试要点：**
- 使用真实 Spring Boot JAR 测试
- 验证框架检测准确性
- 验证入口点提取完整性

---

### Task 4: CFR 反编译器集成

**Files:**
- Create: `src/tools/decompiler/index.ts`
- Create: `src/tools/decompiler/types.ts`
- Create: `src/tools/decompiler/cfr.ts`
- Create: `src/tools/decompiler/manager.ts`
- Test: `src/tools/decompiler/manager.test.ts`

**参考设计文档 4.2 节实现**

核心功能：
1. 调用 CFR JAR 反编译单个类
2. 实现反编译结果缓存（MD5 检查）
3. 批量并行反编译（每批 10 个类）
4. 解析反编译后的 Java 源码结构

**依赖准备：**

```bash
mkdir -p lib
curl -L -o lib/cfr-0.152.jar https://github.com/leibnitz27/cfr/releases/download/0.152/cfr-0.152.jar
```

---

### Task 5: 反编译缓存管理

**Files:**
- Create: `src/tools/decompiler/cache.ts`
- Test: `src/tools/decompiler/cache.test.ts`

**实现要点：**

```typescript
class DecompileCacheManager {
  private cacheDir = '.security-audit/cache/decompile'
  
  async loadCache(): Promise<Map<string, CacheEntry>>
  async saveCache(cache: Map<string, CacheEntry>): Promise<void>
  generateCacheKey(jarPath: string, className: string): string
  async cleanup(maxAge: number): Promise<void>
}
```

---

## Phase 2: 污点追踪引擎

### Task 6: 污点追踪基础

**Files:**
- Create: `src/tools/taint-engine/index.ts`
- Create: `src/tools/taint-engine/types.ts`
- Create: `src/tools/taint-engine/engine.ts`
- Test: `src/tools/taint-engine/engine.test.ts`

**参考设计文档 4.3 节实现**

核心组件：
1. `TaintEngine` - 主引擎
2. `TaintSource` / `TaintSink` - 源和汇聚点定义
3. `PropagationRule` - 传播规则
4. `DataFlowGraph` - 数据流图

**实现步骤：**
1. 定义所有 SourceType（HTTP 参数、Header、Body 等）
2. 定义所有 SinkType（SQL_EXECUTION、COMMAND_EXECUTION 等）
3. 实现数据流图构建
4. 实现 DFS 污点追踪算法
5. 实现净化操作识别

---

### Task 7: 数据流图构建器

**Files:**
- Create: `src/tools/taint-engine/graph-builder.ts`
- Create: `src/tools/taint-engine/ast-parser.ts`

**实现要点：**

```typescript
class DataFlowGraphBuilder {
  build(sourceCode: string): DataFlowGraph {
    // 1. 解析 AST
    // 2. 识别变量赋值
    // 3. 识别方法调用参数传递
    // 4. 识别返回值传播
    // 5. 构建节点和边
  }
}
```

---

## Phase 3: 专项检测 Agent

### Task 8: SQL 注入 Agent

**Files:**
- Create: `src/agents/sql-injector/index.ts`
- Create: `src/agents/sql-injector/detector.ts`
- Create: `src/agents/sql-injector/rules.ts`
- Test: `src/agents/sql-injector/detector.test.ts`

**参考设计文档 4.4 节实现**

检测目标：
1. JDBC Statement.executeQuery() 字符串拼接
2. MyBatis ${} 参数注入
3. JPA Query 原生 SQL 注入
4. MyBatis XML 映射文件分析

**修复建议模板：**
- MyBatis: 使用 #{} 替代 ${}
- JDBC: 使用 PreparedStatement
- JPA: 使用参数绑定

---

### Task 9: SSRF Agent

**Files:**
- Create: `src/agents/ssrf-hunter/index.ts`
- Create: `src/agents/ssrf-hunter/detector.ts`
- Test: `src/agents/ssrf-hunter/detector.test.ts`

**参考设计文档 4.5 节实现**

检测目标：
1. URL.openConnection() 用户可控
2. HttpClient.execute() URL 参数注入
3. RestTemplate 请求 URL 拼接
4. 内网 IP 绕过检测
5. 云服务元数据访问

---

### Task 10: RCE Agent

**Files:**
- Create: `src/agents/rce-detector/index.ts`
- Create: `src/agents/rce-detector/detector.ts`
- Create: `src/agents/rce-detector/sinks.ts`
- Test: `src/agents/rce-detector/detector.test.ts`

**参考设计文档 4.6 节实现**

检测目标：
1. Runtime.getRuntime().exec() 命令注入
2. ProcessBuilder 命令链构造
3. ScriptEngine.eval() 脚本注入
4. ObjectInputStream.readObject() 反序列化
5. ELProcessor 表达式注入

---

## Phase 4: 其他 Agent

### Task 11: 认证授权 Agent

**Files:**
- Create: `src/agents/auth-analyzer/index.ts`
- Create: `src/agents/auth-analyzer/detector.ts`
- Test: `src/agents/auth-analyzer/detector.test.ts`

**参考设计文档 4.7 节实现**

检测目标：
1. @PreAuthorize 缺失检测
2. 水平越权（IDOR）检测
3. 垂直越权（管理员绕过）检测
4. JWT None 算法检测
5. JWT 弱密钥检测
6. 配置文件硬编码凭证检测

---

### Task 12: 业务逻辑 Agent

**Files:**
- Create: `src/agents/logic-inspector/index.ts`
- Create: `src/agents/logic-inspector/detector.ts`
- Test: `src/agents/logic-inspector/detector.test.ts`

**参考设计文档 4.8 节实现**

检测目标：
1. 支付价格篡改检测
2. 验证码绕过检测
3. 库存竞争条件检测
4. 优惠券重复使用检测
5. 工作流步骤绕过检测

---

## Phase 5: 集成与报告

### Task 13: Sentry 主控 Agent

**Files:**
- Create: `src/agents/sentry/index.ts`
- Create: `src/agents/sentry/orchestrator.ts`

**功能：**
1. 协调各专项 Agent 执行
2. 并行调度（SQL + SSRF + RCE 同时执行）
3. 去重合并漏洞结果
4. 统一漏洞严重级别评估

---

### Task 14: 报告生成器

**Files:**
- Create: `src/hooks/report-generator/index.ts`
- Create: `src/hooks/report-generator/templates.ts`
- Create: `src/hooks/report-generator/formatters.ts`

**输出格式：**
1. **控制台输出** - 实时扫描进度和漏洞列表
2. **JSON 报告** - 包含完整漏洞详情和证据链
3. **HTML 报告** - 交互式渗透测试报告
4. **Markdown 报告** - 适合提交到 GitHub Issues

**报告内容：**
- 执行摘要（漏洞统计、风险评分）
- 漏洞详情（按严重级别分组）
- 证据链展示（数据流图）
- 修复建议（含代码示例）
- CWE/OWASP 映射

---

### Task 15: 插件入口集成

**Files:**
- Create: `src/index.ts`
- Create: `src/plugin.ts`

**实现 OpenCode 插件接口：**

```typescript
import { createPlugin } from '@opencode-ai/sdk'

export default createPlugin({
  name: 'code-security-audit',
  version: '1.0.0',
  
  async activate(context) {
    // 注册工具
    context.registerTool('audit_jar', auditJarTool)
    context.registerTool('decompile_class', decompileTool)
    
    // 注册 Agent
    context.registerAgent('sentry', createSentryAgent())
    context.registerAgent('sql-injector', createSQLInjectorAgent())
    // ... 其他 Agent
  }
})
```

---

### Task 16: 端到端测试

**Files:**
- Create: `tests/integration/audit-flow.test.ts`
- Create: `tests/fixtures/vulnerable-app/` (测试用漏洞应用)

**测试场景：**
1. 完整审计流程测试（从 JAR 到报告）
2. 各漏洞类型检测准确性测试
3. 误报率测试（使用安全代码样本）
4. 性能测试（大型 JAR 文件处理）

---

## 开发规范

### 代码风格
- 使用 bun-types，绝不使用 @types/node
- 严格 TypeScript 模式
- 显式类型标注
- 工厂函数命名：`createXXXTool`、`createXXXAgent`
- 目录/文件：kebab-case

### TDD 要求
- 先写测试再写实现
- 测试文件：`*.test.ts` 与源文件同目录
- BDD 注释：`#given`、`#when`、`#then`

### Git 提交规范
- 小提交（1-2 个文件）
- 测试与实现分开提交
- 提交信息格式：`feat: ` / `fix: ` / `test: ` / `docs: `

---

**计划完成！**

此实现计划涵盖 16 个主要任务，预计总工期 3-4 周。

**下一步：**

选择执行方式：

1. **立即开始实现** - 我可以按 Task 1 开始编写代码
2. **先细化特定任务** - 如果你需要某个任务的更详细步骤
3. **检查工作树** - 确认当前环境准备就绪

请告诉我你希望如何继续！
