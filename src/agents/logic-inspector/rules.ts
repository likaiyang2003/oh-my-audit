// 业务逻辑漏洞检测规则

export const BUSINESS_LOGIC_RULES = [
  // 价格篡改检测
  {
    name: 'Price Manipulation',
    description: '订单价格接受客户端传入，存在被篡改风险',
    severity: 'critical',
    patterns: [
      /setPrice\s*\(\s*request\.getPrice/g,
      /setAmount\s*\(\s*request\.getAmount/g,
      /order\.setPrice\s*\(/g,
      /\.setPrice\s*\(\s*request/g,
    ],
    logicType: 'PRICE_MANIPULATION',
    businessImpact: '攻击者可将订单金额改为 0.01 元或负数，造成财务损失'
  },
  
  // 缺少验证码
  {
    name: 'Missing CAPTCHA',
    description: '登录/注册等敏感操作缺少验证码保护',
    severity: 'high',
    patterns: [
      /@PostMapping.*login/g,
      /login.*password/g,
      /public.*login.*password/g,
    ],
    logicType: 'MISSING_CAPTCHA',
    businessImpact: '可被自动化工具暴力破解账号密码'
  },
  
  // 竞争条件 - 库存扣减
  {
    name: 'Inventory Race Condition',
    description: '库存扣减缺乏并发控制，可能导致超卖',
    severity: 'high',
    patterns: [
      /getInventory.*>=.*quantity/g,
      /inventory.*>=.*quantity/g,
      /setInventory.*-\s*quantity/g,
      /inventory\s*=\s*inventory\s*-/g,
    ],
    logicType: 'RACE_CONDITION',
    businessImpact: '并发请求可能导致库存为负，超卖商品'
  },
  
  // 工作流程绕过
  {
    name: 'Workflow Bypass',
    description: '跳过必要审批步骤直接完成操作',
    severity: 'high',
    patterns: [
      /setStatus\s*\(\s*["']APPROVED["']/g,
      /setState\s*\(\s*["']COMPLETED["']/g,
    ],
    logicType: 'WORKFLOW_BYPASS',
    businessImpact: '绕过业务规则校验，可能导致不合规操作'
  },
  
  // 优惠券重复使用
  {
    name: 'Coupon Reuse',
    description: '优惠券使用缺乏幂等性控制',
    severity: 'medium',
    patterns: [
      /useCoupon.*couponId/g,
      /applyCoupon.*without.*check/g,
    ],
    logicType: 'COUPON_REUSE',
    businessImpact: '一张优惠券可被使用多次'
  }
]

// 检测验证码存在
export function hasCaptchaProtection(sourceCode: string): boolean {
  return /captcha|Captcha|verifyCode|kaptcha|geetest/i.test(sourceCode)
}

// 检测同步机制
export function hasSynchronization(sourceCode: string): boolean {
  return /synchronized|@Synchronized|Lock|Semaphore|version.*optimistic|@Version/i.test(sourceCode)
}

// 检测乐观锁
export function usesOptimisticLocking(sourceCode: string): boolean {
  return /@Version|optimistic.*locking|version.*column/i.test(sourceCode)
}
