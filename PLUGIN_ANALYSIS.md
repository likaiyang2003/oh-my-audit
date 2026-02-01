# oh-my-audit 插件问题分析报告

## 核心发现

### oh-my-opencode（正常工作）
- ❌ **没有** `opencode-plugin.json` 文件
- ✅ 使用标准 npm 包：`@opencode-ai/plugin` 
- ✅ 通过 `package.json` 注册为 OpenCode 插件
- ✅ 发布到 npm  registry

### oh-my-audit（报错）
- ✅ 有 `opencode-plugin.json`（217行复杂配置）
- ❌ **缺少** `@opencode-ai/plugin` 依赖
- ❌ 使用**错误的**自定义插件格式
- ❌ 未发布到 npm

## 根本原因

**oh-my-audit 使用了不存在的插件格式！**

OpenCode 不支持 `opencode-plugin.json` 这种自定义格式。正确的做法是：

1. 依赖 `@opencode-ai/plugin` 包
2. 使用标准 npm 包格式
3. 通过 `package.json` 注册
4. 使用 `@opencode-ai/sdk` 的 `createTool()` API

## 修复方案

### 方案 A: 改为标准 npm 包（推荐）

修改 `package.json`，添加：
```json
{
  "dependencies": {
    "@opencode-ai/plugin": "^1.1.19",
    "@opencode-ai/sdk": "^1.1.19"
  }
}
```

删除 `opencode-plugin.json`

### 方案 B: 作为技能（Skill）而非插件

如果只需要代码复用，可以将 oh-my-audit 作为 skill 加载：

1. 创建 `.opencode/skills/oh-my-audit/skill.yaml`
2. 定义工具调用方式

### 方案 C: 使用子进程调用

在 oh-my-opencode 中通过 Bun 子进程调用 oh-my-audit：

```typescript
const result = await $`bun run oh-my-audit/audit.ts ${jarPath}`
```

## 推荐方案

**方案 A** - 将 oh-my-audit 改为标准 OpenCode 插件格式：

1. 删除 `opencode-plugin.json`
2. 修改 `package.json` 添加依赖
3. 重写 `src/index.ts` 使用 `createTool()`
4. 发布到 npm 或本地安装

## 关键差异对比

| 特性 | oh-my-opencode | oh-my-audit |
|------|----------------|-------------|
| 插件格式 | 标准 npm 包 | 自定义 JSON |
| 依赖 | @opencode-ai/plugin | 缺失 |
| 入口 | package.json main | opencode-plugin.json |
| 注册方式 | npm install | 不支持 |
| 工具定义 | TypeScript 代码 | JSON 配置 |

## 结论

**oh-my-audit 无法作为 OpenCode 插件使用**，因为它使用了不存在的插件格式。

需要重构为标准的 `@opencode-ai/plugin` 格式才能正常工作。
