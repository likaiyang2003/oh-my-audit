import { describe, it, expect, beforeAll } from 'bun:test'
import { BusinessLogicAgent } from './agent'
import type { AttackEntry } from '../../types'
import type { DecompileResult } from '../../tools/decompiler/types'

describe('BusinessLogicAgent', () => {
  let agent: BusinessLogicAgent
  
  beforeAll(() => {
    agent = new BusinessLogicAgent()
  })
  
  it('#given price from client input #when audit is called #then should detect price manipulation', async () => {
    const sourceCode = `
      @PostMapping("/api/order")
      public Order createOrder(@RequestBody OrderRequest request) {
        Order order = new Order();
        order.setProductId(request.getProductId());
        order.setPrice(request.getPrice()); // 危险：接受客户端价格
        order.setQuantity(request.getQuantity());
        orderRepository.save(order);
        return order;
      }
    `
    
    const entry: AttackEntry = {
      type: 'controller',
      className: 'OrderController',
      methodName: 'createOrder',
      urlPattern: '/api/order',
      httpMethods: ['POST'],
      parameters: [
        { name: 'request', type: 'OrderRequest', source: 'body' }
      ],
      riskLevel: 'critical'
    }
    
    const decompiledSources = new Map<string, DecompileResult>([[
      'OrderController',
      {
        className: 'OrderController',
        sourceCode,
        packageName: 'com.example.controller',
        imports: ['org.springframework.web.bind.annotation.*'],
        methods: [],
        fields: [],
        isSuccess: true,
        decompileTime: 0,
        cacheHit: false
      }
    ]])
    
    const vulnerabilities = await agent.audit(
      'test.jar',
      [entry],
      decompiledSources
    )
    
    expect(vulnerabilities.length).toBeGreaterThan(0)
    expect(vulnerabilities.some((v: any) => v.type === 'PRICE_MANIPULATION')).toBe(true)
  })
  
  it('#given missing captcha protection #when audit is called #then should detect captcha bypass', async () => {
    const sourceCode = `
      @PostMapping("/api/login")
      public ResponseEntity<?> login(@RequestParam String username, 
                                     @RequestParam String password) {
        User user = userService.authenticate(username, password);
        if (user != null) {
          return ResponseEntity.ok(jwtUtil.generateToken(user));
        }
        return ResponseEntity.status(401).build();
      }
    `
    
    const entry: AttackEntry = {
      type: 'controller',
      className: 'LoginController',
      methodName: 'login',
      urlPattern: '/api/login',
      httpMethods: ['POST'],
      parameters: [
        { name: 'username', type: 'String', source: 'body' },
        { name: 'password', type: 'String', source: 'body' }
      ],
      riskLevel: 'high'
    }
    
    const decompiledSources = new Map<string, DecompileResult>([[
      'LoginController',
      {
        className: 'LoginController',
        sourceCode,
        packageName: 'com.example.controller',
        imports: ['org.springframework.web.bind.annotation.*'],
        methods: [],
        fields: [],
        isSuccess: true,
        decompileTime: 0,
        cacheHit: false
      }
    ]])
    
    const vulnerabilities = await agent.audit(
      'test.jar',
      [entry],
      decompiledSources
    )
    
    expect(vulnerabilities.some((v: any) => v.type === 'MISSING_CAPTCHA')).toBe(true)
  })
  
  it('#given inventory deduction without synchronization #when audit is called #then should detect race condition', async () => {
    const sourceCode = `
      @PostMapping("/api/purchase")
      @Transactional
      public void purchase(@RequestParam Long productId, @RequestParam Integer quantity) {
        Product product = productRepository.findById(productId).orElseThrow();
        if (product.getInventory() >= quantity) {
          product.setInventory(product.getInventory() - quantity);
          productRepository.save(product);
        }
      }
    `
    
    const entry: AttackEntry = {
      type: 'controller',
      className: 'PurchaseController',
      methodName: 'purchase',
      urlPattern: '/api/purchase',
      httpMethods: ['POST'],
      parameters: [
        { name: 'productId', type: 'Long', source: 'query' },
        { name: 'quantity', type: 'Integer', source: 'query' }
      ],
      riskLevel: 'high'
    }
    
    const decompiledSources = new Map<string, DecompileResult>([[
      'PurchaseController',
      {
        className: 'PurchaseController',
        sourceCode,
        packageName: 'com.example.controller',
        imports: ['org.springframework.web.bind.annotation.*', 'org.springframework.transaction.annotation.*'],
        methods: [],
        fields: [],
        isSuccess: true,
        decompileTime: 0,
        cacheHit: false
      }
    ]])
    
    const vulnerabilities = await agent.audit(
      'test.jar',
      [entry],
      decompiledSources
    )
    
    expect(vulnerabilities.some((v: any) => v.type === 'RACE_CONDITION')).toBe(true)
  })
  
  it('#given workflow with step bypass #when audit is called #then should detect workflow bypass', async () => {
    const sourceCode = `
      @PostMapping("/api/approve")
      public void approveOrder(@RequestParam Long orderId) {
        Order order = orderRepository.findById(orderId).orElseThrow();
        // 直接跳到最终审批，跳过中间步骤
        order.setStatus("APPROVED");
        orderRepository.save(order);
      }
    `
    
    const entry: AttackEntry = {
      type: 'controller',
      className: 'ApprovalController',
      methodName: 'approveOrder',
      urlPattern: '/api/approve',
      httpMethods: ['POST'],
      parameters: [
        { name: 'orderId', type: 'Long', source: 'query' }
      ],
      riskLevel: 'high'
    }
    
    const decompiledSources = new Map<string, DecompileResult>([[
      'ApprovalController',
      {
        className: 'ApprovalController',
        sourceCode,
        packageName: 'com.example.controller',
        imports: ['org.springframework.web.bind.annotation.*'],
        methods: [],
        fields: [],
        isSuccess: true,
        decompileTime: 0,
        cacheHit: false
      }
    ]])
    
    const vulnerabilities = await agent.audit(
      'test.jar',
      [entry],
      decompiledSources
    )
    
    expect(vulnerabilities.length).toBeGreaterThan(0)
  })
})
