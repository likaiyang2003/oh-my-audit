# code-security-audit

[![Build Status](https://img.shields.io/github/actions/workflow/status/likaiyang2003/oh-my-audit/release.yml?branch=main)](https://github.com/likaiyang2003/oh-my-audit/actions)
[![Version](https://img.shields.io/github/v/release/likaiyang2003/oh-my-audit)](https://github.com/likaiyang2003/oh-my-audit/releases)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Bun](https://img.shields.io/badge/Bun-1.0+-black?logo=bun)](https://bun.sh)

基于 oh-my-opencode 架构的专业 Java 代码安全审计插件。

## 功能特性

- 🔍 **JAR 包反编译与智能分析** - 自动提取和分析 JAR 文件结构
- 🛡️ **OWASP Top 10 漏洞检测** - SQL 注入、SSRF、RCE、XSS 等
- 🔐 **认证授权漏洞检测** - 越权访问、JWT 安全问题、硬编码凭证
- 💰 **业务逻辑漏洞检测** - 支付绕过、竞争条件、工作流绕过
- 📊 **完整的证据链** - 数据流追踪从 Source 到 Sink
- 📝 **多格式报告** - JSON、HTML、Markdown、控制台实时输出
- ⚡ **高性能** - 并行处理与智能缓存
- 🔧 **可扩展** - 插件架构支持自定义检测规则

## 快速开始

### 在 OpenCode 中使用（推荐）

#### 方法 1: 通过 Git URL 安装

```bash
# 在 OpenCode 中安装插件
opencode plugin install https://github.com/likaiyang2003/oh-my-audit.git
```

#### 方法 2: 手动安装到插件目录

```bash
# 1. 克隆仓库到 OpenCode 插件目录
cd ~/.config/opencode/plugins/
git clone https://github.com/likaiyang2003/oh-my-audit.git code-security-audit

# 2. 进入插件目录并安装依赖
cd code-security-audit
bun install

# 3. 构建插件
bun run build
```

#### 方法 3: 在 OpenCode 配置文件中添加

编辑 `~/.config/opencode/config.json`:

```json
{
  "plugins": [
    {
      "name": "code-security-audit",
      "url": "https://github.com/likaiyang2003/oh-my-audit.git"
    }
  ]
}
```

### 使用示例

安装后，在 OpenCode 中可以直接调用以下工具：

```
# 审计 JAR 文件
/audit_jar jarPath=/path/to/app.jar reportFormat=html

# 检测 SQL 注入
/detect_sql_injection sourceCode="String sql = 'SELECT * FROM users WHERE id = ' + userId"

# 检测 SSRF
/detect_ssrf sourceCode="URL url = new URL(request.getParameter('url'))"

# 检测 RCE
/detect_rce sourceCode="Runtime.getRuntime().exec(cmd)"

# 生成报告
/generate_audit_report vulnerabilities=[...] format=markdown
```

### 独立使用（开发/测试）

```bash
# 克隆仓库
git clone https://github.com/likaiyang2003/oh-my-audit.git
cd oh-my-audit

# 安装依赖
bun install
```

### 开发

```bash
# 类型检查
bun run typecheck

# 运行测试
bun test

# 构建
bun run build

# 最终检查（发布前）
bun run final-check
```

### 使用示例

```typescript
import { createSentryAgent } from './src/agents/sentry'
import { createJarAnalyzer } from './src/tools/jar-analyzer'

// 创建 Sentry 主控 Agent
const sentry = createSentryAgent()

// 分析 JAR 文件
const analyzer = createJarAnalyzer()
const result = await analyzer.analyze('./target/app.jar')

// 执行安全审计
const vulnerabilities = await sentry.audit(result)

// 生成报告
console.log(`发现 ${vulnerabilities.length} 个漏洞`)
```

## 架构设计

### 分层审计架构

```
┌─────────────────────────────────────────────────────────────┐
│                    报告生成层 (Reporting)                    │
│         JSON / HTML / Markdown / Console Output             │
└─────────────────────────────────────────────────────────────┘
                              │
┌─────────────────────────────────────────────────────────────┐
│                    Sentry 主控 Agent                         │
│          协调调度 · 结果合并 · 严重级别评估                   │
└─────────────────────────────────────────────────────────────┘
                              │
        ┌──────────┬──────────┼──────────┬──────────┐
        │          │          │          │          │
   ┌────▼────┐ ┌───▼────┐ ┌──▼────┐ ┌──▼────┐ ┌──▼────┐
   │ SQL注入 │ │  SSRF  │ │  RCE  │ │ 认证授权│ │业务逻辑│
   │ Agent   │ │ Agent  │ │ Agent │ │ Agent │ │ Agent  │
   └────┬────┘ └───┬────┘ └──┬────┘ └──┬────┘ └──┬────┘
        │          │         │         │         │
        └──────────┴─────────┴─────────┴─────────┘
                              │
┌─────────────────────────────────────────────────────────────┐
│                   污点追踪引擎 (Taint Engine)                 │
│           Source → Propagation → Sanitization → Sink        │
└─────────────────────────────────────────────────────────────┘
                              │
        ┌─────────────────────┼─────────────────────┐
        │                     │                     │
   ┌────▼────┐          ┌────▼────┐          ┌────▼────┐
   │ JAR分析  │          │ CFR反编译 │          │ AST解析  │
   └─────────┘          └─────────┘          └─────────┘
```

### 核心组件

1. **JAR Analyzer** - 解析 JAR 文件结构，识别框架和攻击面
2. **CFR Decompiler** - Java 字节码反编译，支持缓存
3. **Taint Engine** - 数据流分析引擎，追踪污点传播
4. **Specialized Agents** - 专项漏洞检测 Agent
5. **Sentry** - 主控协调 Agent
6. **Report Generator** - 多格式报告生成

## OpenCode 集成详情

### 可用工具列表

安装后，OpenCode 会自动注册以下 9 个工具：

| 工具名称 | 功能描述 | 使用场景 |
|---------|---------|---------|
| `audit_jar` | 完整的 JAR 安全审计 | 对 Java 应用进行全面安全扫描 |
| `decompile_class` | 反编译 Java 类 | 查看 JAR 内某个类的源码 |
| `analyze_taint` | 污点分析 | 追踪数据从输入到危险函数的流向 |
| `detect_sql_injection` | SQL 注入检测 | 分析代码中的 SQL 拼接问题 |
| `detect_ssrf` | SSRF 检测 | 查找服务器端请求伪造漏洞 |
| `detect_rce` | RCE 检测 | 发现命令执行和反序列化漏洞 |
| `detect_auth_vulnerabilities` | 认证漏洞检测 | 查找 JWT、IDOR、越权等问题 |
| `detect_business_logic` | 业务逻辑检测 | 发现支付绕过、竞争条件等 |
| `generate_audit_report` | 生成审计报告 | 将漏洞结果转换为报告 |

### 工具调用示例

#### 完整 JAR 审计

```
/audit_jar jarPath=/path/to/application.jar severityFilter=["critical","high"] reportFormat=json
```

参数说明：
- `jarPath`: JAR 文件的绝对路径
- `severityFilter`: 可选，过滤严重级别，默认全部
- `reportFormat`: 可选，报告格式 (console/json/html/markdown)，默认 console

#### 代码片段分析

```
/detect_sql_injection sourceCode="public void query(String userId) { String sql = \"SELECT * FROM users WHERE id = '\" + userId + \"'\"; stmt.execute(sql); }" methodName=query
```

#### 批量类反编译

```
/decompile_class jarPath=/path/to/app.jar className=com.example.UserController
```

### 配置文件

在 OpenCode 中使用 `opencode-plugin.json` 配置：

```json
{
  "name": "code-security-audit",
  "version": "1.0.0",
  "permissions": ["file-system-read"],
  "supportedModels": ["claude", "gpt-4", "gemini", "grok", "glm"]
}
```

## 支持的漏洞类型

| 漏洞类型 | CWE | 检测能力 | 修复建议 |
|----------|-----|----------|----------|
| SQL 注入 | CWE-89 | ✅ 完整 | PreparedStatement |
| SSRF | CWE-918 | ✅ 完整 | URL 白名单校验 |
| RCE | CWE-78 | ✅ 完整 | 命令白名单 + 参数化 |
| 反序列化 | CWE-502 | ✅ 完整 | 白名单类加载 |
| IDOR | CWE-639 | ✅ 完整 | 访问控制校验 |
| JWT 漏洞 | CWE-287 | ✅ 完整 | 强密钥 + 算法校验 |
| 硬编码密钥 | CWE-798 | ✅ 完整 | 密钥管理系统 |
| XSS | CWE-79 | 🚧 部分 | HTML 转义 |

## 技术栈

- **运行时**: Bun v1.0+
- **语言**: TypeScript 5.7
- **类型**: bun-types（绝不使用 @types/node）
- **架构**: OpenCode Plugin SDK
- **反编译**: CFR 0.152

## 项目结构

```
oh-my-audit/
├── src/
│   ├── agents/          # 检测 Agent
│   │   ├── sql-injector/
│   │   ├── ssrf-hunter/
│   │   ├── rce-detector/
│   │   ├── auth-analyzer/
│   │   ├── logic-inspector/
│   │   └── sentry/      # 主控 Agent
│   ├── tools/           # 核心工具
│   │   ├── jar-analyzer/
│   │   ├── decompiler/
│   │   └── taint-engine/
│   ├── hooks/           # 生命周期钩子
│   │   └── report-generator/
│   ├── types/           # 类型定义
│   └── index.ts         # 插件入口
├── scripts/             # 脚本工具
│   ├── final-check.ts   # 发布前检查
│   └── bump-version.ts  # 版本升级
├── test/                # 测试文件
├── docs/                # 文档
└── dist/                # 构建输出
```

## 开发规范

- **测试驱动**: TDD 模式，测试文件与源码同目录
- **代码风格**: kebab-case 命名，显式类型标注
- **类型安全**: 严格 TypeScript，禁止使用 `as any`
- **依赖管理**: 仅使用 Bun，绝不使用 npm/yarn
- **Git 提交**: 小提交（1-2 文件），测试与实现分离

## 贡献指南

我们欢迎所有形式的贡献！

### 开发流程

1. Fork 本仓库
2. 创建功能分支: `git checkout -b feat/amazing-feature`
3. 编写测试 → 实现功能 → 确保通过
4. 提交更改: `git commit -m "feat: add amazing feature"`
5. 推送分支: `git push origin feat/amazing-feature`
6. 创建 Pull Request

### 提交信息规范

- `feat:` 新功能
- `fix:` 修复 Bug
- `test:` 添加测试
- `docs:` 更新文档
- `refactor:` 代码重构
- `chore:` 构建/工具更新

### 代码审查

- 所有 PR 必须通过 CI 检查
- 至少 1 个审查者批准
- 测试覆盖率不能下降

## 路线图

### v1.0.0 (当前)
- ✅ 核心基础设施 (JAR 分析、反编译、污点追踪)
- ✅ 6 个专项检测 Agent
- ✅ 报告生成器
- ✅ 端到端集成

### v1.1.0 (计划中)
- 🚧 增加更多 CWE 覆盖
- 🚧 支持 Gradle 项目直接分析
- 🚧 增量扫描支持
- 🚧 IDE 插件 (VS Code)

### v2.0.0 (愿景)
- 📝 SARIF 格式输出
- 📝 CI/CD 集成优化
- 📝 机器学习辅助检测
- 📝 漏洞知识库扩展

## 相关文档

- [架构设计文档](docs/2026-01-31-code-security-audit-design.md)
- [实现计划](docs/2026-01-31-implementation-plan.md)
- [更新日志](CHANGELOG.md)

## 许可证

MIT © [likaiyang2003](https://github.com/likaiyang2003)

---

**Made with ❤️ for the OpenCode community**
