import type { Vulnerability, AttackEntry } from '../../types'

export type BusinessLogicType =
  | 'PRICE_MANIPULATION'        // 价格篡改
  | 'PAYMENT_STATUS_BYPASS'     // 支付状态绕过
  | 'MISSING_CAPTCHA'           // 缺少验证码
  | 'CAPTCHA_BYPASS'            // 验证码绕过
  | 'RACE_CONDITION'            // 竞争条件
  | 'COUPON_REUSE'              // 优惠券重复使用
  | 'WORKFLOW_BYPASS'           // 工作流程绕过
  | 'INSUFFICIENT_VALIDATION'   // 验证不足

export interface BusinessLogicVulnerability extends Vulnerability {
  details: {
    logicType: BusinessLogicType
    businessImpact: string
    financialImpact?: string
    affectedResource?: string
  }
}

export interface BusinessLogicRule {
  name: string
  description: string
  severity: 'critical' | 'high' | 'medium'
  patterns: RegExp[]
  logicType: BusinessLogicType
  businessImpact: string
}

export interface BusinessLogicAnalyzerOptions {
  detectPaymentIssues?: boolean
  detectRaceConditions?: boolean
  detectCaptchaIssues?: boolean
  strictMode?: boolean
}
