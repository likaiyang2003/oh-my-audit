import type { Vulnerability } from '../../types'

export type RCEType =
  | 'command_injection'      // 命令注入（; && | 等）
  | 'argument_injection'     // 参数注入
  | 'script_injection'       // 脚本注入（ScriptEngine）
  | 'el_expression_injection' // EL 表达式注入
  | 'deserialization_rce'    // 反序列化 RCE
  | 'reflection_rce'         // 反射导致的 RCE
  | 'template_injection'     // 模板注入
  | 'generic_rce'           // 通用 RCE

export interface RCEVulnerability extends Vulnerability {
  details: {
    rceType: RCEType
    sinkType: string
    sinkMethod: string
    vulnerableParameter?: string
    commandChain?: string[]
    isDirectUserInput: boolean
    hasSanitization: boolean
    sanitizationType?: string
  }
  
  attackPayloads: {
    type: string
    payload: string
    description: string
    successIndicator?: string
  }[]
}

export interface RCERule {
  name: string
  description: string
  severity: 'critical' | 'high' | 'medium'
  patterns: RegExp[]
  rceType: RCEType
  sinkMethods: string[]
  safeAlternative: string
}

export interface RCEAnalyzerOptions {
  detectCommandChaining?: boolean
  detectDeserialization?: boolean
  strictMode?: boolean
}
