import { describe, it, expect, beforeAll } from 'bun:test'
import { AuthAnalyzerAgent } from './agent'
import type { AttackEntry } from '../../types'
import type { Vulnerability } from '../../types'
import { VulnerabilityType } from '../../types'
import type { DecompileResult } from '../../tools/decompiler/types'
import type { ConfigFile } from '../../types'

describe('AuthAnalyzerAgent', () => {
  let agent: AuthAnalyzerAgent
  
  beforeAll(() => {
    agent = new AuthAnalyzerAgent()
  })
  
  it('#given admin endpoint without auth check #when audit is called #then should detect auth bypass', async () => {
    const sourceCode = `
      @RestController
      @RequestMapping("/admin")
      public class AdminController {
        
        @GetMapping("/users")
        public List<User> getAllUsers() {
          return userService.findAll();
        }
      }
    `
    
    const entry: AttackEntry = {
      type: 'controller',
      className: 'AdminController',
      methodName: 'getAllUsers',
      urlPattern: '/admin/users',
      httpMethods: ['GET'],
      parameters: [],
      riskLevel: 'critical'
    }
    
    const decompiledSources = new Map<string, DecompileResult>([[
      'AdminController',
      {
        className: 'AdminController',
        sourceCode,
        packageName: 'com.example.admin',
        imports: ['org.springframework.web.bind.annotation.*'],
        methods: [],
        fields: [],
        isSuccess: true,
        decompileTime: 0,
        cacheHit: false
      }
    ]])
    
    const configFiles: ConfigFile[] = []
    
    const vulnerabilities = await agent.audit(
      'test.jar',
      [entry],
      decompiledSources,
      configFiles
    )
    
    expect(vulnerabilities.length).toBeGreaterThan(0)
    expect(vulnerabilities.some((v: Vulnerability) => v.type === 'AUTH_BYPASS')).toBe(true)
  })
  
  it('#given user data access without ownership check #when audit is called #then should detect IDOR', async () => {
    const sourceCode = `
      @GetMapping("/users/{userId}")
      public User getUser(@PathVariable Long userId) {
        return userService.findById(userId);
      }
    `
    
    const entry: AttackEntry = {
      type: 'controller',
      className: 'UserController',
      methodName: 'getUser',
      urlPattern: '/users/{userId}',
      httpMethods: ['GET'],
      parameters: [
        { name: 'userId', type: 'Long', source: 'path' }
      ],
      riskLevel: 'high'
    }
    
    const decompiledSources = new Map<string, DecompileResult>([[
      'UserController',
      {
        className: 'UserController',
        sourceCode,
        packageName: 'com.example',
        imports: ['org.springframework.web.bind.annotation.*'],
        methods: [],
        fields: [],
        isSuccess: true,
        decompileTime: 0,
        cacheHit: false
      }
    ]])
    
    const configFiles: ConfigFile[] = []
    
    const vulnerabilities = await agent.audit(
      'test.jar',
      [entry],
      decompiledSources,
      configFiles
    )
    
    expect(vulnerabilities.some((v: Vulnerability) => v.type === 'IDOR')).toBe(true)
  })
  
  it('#given JWT with none algorithm #when audit is called #then should detect JWT vulnerability', async () => {
    const sourceCode = `
      public String parseToken(String token) {
        Jwts.parser()
            .setAllowedAlgorithms("none", "HS256")
            .parseClaimsJws(token);
      }
    `
    
    const entry: AttackEntry = {
      type: 'controller',
      className: 'JwtUtil',
      methodName: 'parseToken',
      urlPattern: '/api/parse',
      httpMethods: ['POST'],
      parameters: [
        { name: 'token', type: 'String', source: 'body' }
      ],
      riskLevel: 'critical'
    }
    
    const decompiledSources = new Map<string, DecompileResult>([[
      'JwtUtil',
      {
        className: 'JwtUtil',
        sourceCode,
        packageName: 'com.example.util',
        imports: ['io.jsonwebtoken.*'],
        methods: [],
        fields: [],
        isSuccess: true,
        decompileTime: 0,
        cacheHit: false
      }
    ]])
    
    const configFiles: ConfigFile[] = []
    
    const vulnerabilities = await agent.audit(
      'test.jar',
      [entry],
      decompiledSources,
      configFiles
    )
    
    expect(vulnerabilities.some((v: Vulnerability) => v.type === VulnerabilityType.JWT_NONE_ALGORITHM)).toBe(true)
  })
  
  it('#given config with hardcoded password #when audit is called #then should detect hardcoded credentials', async () => {
    const entry: AttackEntry = {
      type: 'controller',
      className: 'UserController',
      methodName: 'login',
      urlPattern: '/api/login',
      httpMethods: ['POST'],
      parameters: [],
      riskLevel: 'medium'
    }
    
    const decompiledSources = new Map<string, DecompileResult>()
    
    const configFiles: ConfigFile[] = [
      {
        path: 'application.properties',
        type: 'properties',
        content: `
          spring.datasource.username=admin
          spring.datasource.password=SuperSecret123!
          jwt.secret=my-super-secret-key-123456
        `
      }
    ]
    
    const vulnerabilities = await agent.audit(
      'test.jar',
      [entry],
      decompiledSources,
      configFiles
    )
    
    expect(vulnerabilities.length).toBeGreaterThan(0)
  })
})