# code-security-audit

基于 oh-my-opencode 架构的专业 Java 代码安全审计插件。

## 功能特性

- 🔍 JAR 包反编译与智能分析
- 🛡️ OWASP Top 10 漏洞检测（SQL 注入、SSRF、RCE、XSS 等）
- 🔐 认证授权漏洞检测（越权访问、JWT 安全问题）
- 💰 业务逻辑漏洞检测（支付绕过、竞争条件）
- 📊 完整的证据链和渗透测试报告

## 快速开始

```bash
# 安装依赖
bun install

# 类型检查
bun run typecheck

# 运行测试
bun test

# 构建
bun run build
```

## 架构设计

参见 `2026-01-31-code-security-audit-design.md`

## 许可证

MIT
