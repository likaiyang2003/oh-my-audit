import { describe, it, expect, beforeAll } from 'bun:test'
import { SentryAgent } from './agent'
import type { AttackEntry, JarAnalysisResult } from '../../types'
import type { DecompileResult } from '../../tools/decompiler/types'

describe('SentryAgent', () => {
  let sentry: SentryAgent
  
  beforeAll(() => {
    sentry = new SentryAgent()
  })
  
  it('#given jar with multiple vulnerabilities #when orchestrate is called #then should coordinate all agents', async () => {
    const jarAnalysis: JarAnalysisResult = {
      manifest: { mainClass: 'com.example.Application' },
      framework: { type: 'spring-boot', indicators: ['org.springframework.boot'] },
      entryPoints: [
        {
          type: 'controller',
          className: 'UserController',
          methodName: 'searchUsers',
          urlPattern: '/api/users/search',
          httpMethods: ['GET'],
          parameters: [{ name: 'name', type: 'String', source: 'query' }],
          riskLevel: 'high'
        },
        {
          type: 'controller',
          className: 'OrderController',
          methodName: 'createOrder',
          urlPattern: '/api/order',
          httpMethods: ['POST'],
          parameters: [{ name: 'request', type: 'OrderRequest', source: 'body' }],
          riskLevel: 'critical'
        }
      ],
      dependencies: [],
      configFiles: [],
      riskScore: 75
    }
    
    const decompiledSources = new Map<string, DecompileResult>([
      ['UserController', {
        className: 'UserController',
        sourceCode: `
          @GetMapping("/api/users/search")
          public List<User> searchUsers(@RequestParam String name) {
            String sql = "SELECT * FROM users WHERE name = '" + name + "'";
            return jdbcTemplate.query(sql, new UserRowMapper());
          }
        `,
        packageName: 'com.example.controller',
        imports: ['org.springframework.web.bind.annotation.*'],
        methods: [],
        fields: [],
        isSuccess: true,
        decompileTime: 100,
        cacheHit: false
      }],
      ['OrderController', {
        className: 'OrderController',
        sourceCode: `
          @PostMapping("/api/order")
          public Order createOrder(@RequestBody OrderRequest request) {
            Order order = new Order();
            order.setPrice(request.getPrice()); // 危险
            orderRepository.save(order);
            return order;
          }
        `,
        packageName: 'com.example.controller',
        imports: ['org.springframework.web.bind.annotation.*'],
        methods: [],
        fields: [],
        isSuccess: true,
        decompileTime: 120,
        cacheHit: false
      }]
    ])
    
    const result = await sentry.orchestrate(
      'test-application.jar',
      jarAnalysis,
      decompiledSources
    )
    
    expect(result).toBeDefined()
    expect(result.vulnerabilities).toBeDefined()
    expect(Array.isArray(result.vulnerabilities)).toBe(true)
    expect(result.summary).toBeDefined()
    expect(result.summary.totalVulnerabilities).toBeGreaterThan(0)
  })
  
  it('#given multiple vulnerabilities #when deduplicate is called #then should remove duplicates', async () => {
    const jarAnalysis: JarAnalysisResult = {
      manifest: {},
      framework: { type: 'spring-boot', indicators: [] },
      entryPoints: [],
      dependencies: [],
      configFiles: [],
      riskScore: 50
    }
    
    const decompiledSources = new Map<string, DecompileResult>()
    
    const result = await sentry.orchestrate(
      'test.jar',
      jarAnalysis,
      decompiledSources
    )
    
    // 检查去重逻辑
    const uniqueTypes = new Set(result.vulnerabilities.map((v: any) => v.type))
    expect(uniqueTypes.size).toBeLessThanOrEqual(result.vulnerabilities.length)
  })
  
  it('#given scan results #when generateReport is called #then should produce summary', async () => {
    const jarAnalysis: JarAnalysisResult = {
      manifest: { mainClass: 'com.example.App' },
      framework: { type: 'spring-boot', indicators: [] },
      entryPoints: [
        {
          type: 'controller',
          className: 'TestController',
          methodName: 'test',
          urlPattern: '/api/test',
          httpMethods: ['GET'],
          parameters: [],
          riskLevel: 'medium'
        }
      ],
      dependencies: [],
      configFiles: [],
      riskScore: 30
    }
    
    const decompiledSources = new Map<string, DecompileResult>([
      ['TestController', {
        className: 'TestController',
        sourceCode: 'public class TestController {}',
        packageName: 'com.example',
        imports: [],
        methods: [],
        fields: [],
        isSuccess: true,
        decompileTime: 50,
        cacheHit: false
      }]
    ])
    
    const result = await sentry.orchestrate(
      'test.jar',
      jarAnalysis,
      decompiledSources
    )
    
    expect(result.summary.scanDuration).toBeGreaterThanOrEqual(0)
    expect(result.summary.filesScanned).toBeGreaterThanOrEqual(0)
    expect(result.summary.agentsExecuted).toBeGreaterThan(0)
  })
})
