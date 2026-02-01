import { describe, it, expect, beforeAll } from 'bun:test'
import { SQLInjectionAgent } from './agent'
import type { AttackEntry } from '../../types'
import { VulnerabilityType } from '../../types'
import type { DecompileResult } from '../../tools/decompiler/types'

describe('SQLInjectionAgent', () => {
  let agent: SQLInjectionAgent
  
  beforeAll(() => {
    agent = new SQLInjectionAgent()
  })
  
  it('#given JDBC string concatenation #when audit is called #then should detect SQL injection', async () => {
    const sourceCode = `
      public void searchUsers(String name) {
        String sql = "SELECT * FROM users WHERE name = '" + name + "'";
        Statement stmt = connection.createStatement();
        ResultSet rs = stmt.executeQuery(sql);
      }
    `
    
    const entry: AttackEntry = {
      type: 'controller',
      className: 'UserController',
      methodName: 'searchUsers',
      urlPattern: '/api/users/search',
      httpMethods: ['GET'],
      parameters: [
        { name: 'name', type: 'String', source: 'query' }
      ],
      riskLevel: 'high'
    }
    
    const decompiledSources = new Map<string, DecompileResult>()
    decompiledSources.set('UserController', {
      className: 'UserController',
      sourceCode,
      packageName: 'com.example',
      imports: ['java.sql.*'],
      methods: [],
      fields: [],
      isSuccess: true,
      decompileTime: 0,
      cacheHit: false
    })
    
    const vulnerabilities = await agent.audit(
      'test.jar',
      [entry],
      decompiledSources
    )
    
    expect(vulnerabilities.length).toBeGreaterThan(0)
    expect(vulnerabilities[0].type).toBe(VulnerabilityType.SQL_INJECTION)
    expect(vulnerabilities[0].cwe).toBe('CWE-89')
  })
  
  it('#given MyBatis ${} usage #when audit is called #then should detect SQL injection', async () => {
    const sourceCode = `
      @Select("SELECT * FROM users WHERE name = '\${name}'")
      public User findByName(@Param("name") String name);
    `
    
    const entry: AttackEntry = {
      type: 'controller',
      className: 'UserMapper',
      methodName: 'findByName',
      urlPattern: '/api/users/{name}',
      httpMethods: ['GET'],
      parameters: [
        { name: 'name', type: 'String', source: 'path' }
      ],
      riskLevel: 'high'
    }
    
    const decompiledSources = new Map<string, DecompileResult>([[
      'UserMapper',
      {
        className: 'UserMapper',
        sourceCode,
        packageName: 'com.example.mapper',
        imports: ['org.apache.ibatis.annotations.*'],
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
    expect(vulnerabilities[0].details.injectionType).toBe('mybatis_dollar_placeholder')
  })
  
  it('#given PreparedStatement with parameters #when audit is called #then should not report false positive', async () => {
    const sourceCode = `
      public void safeSearch(String name) {
        String sql = "SELECT * FROM users WHERE name = ?";
        PreparedStatement stmt = connection.prepareStatement(sql);
        stmt.setString(1, name);
        ResultSet rs = stmt.executeQuery();
      }
    `
    
    const entry: AttackEntry = {
      type: 'controller',
      className: 'UserController',
      methodName: 'safeSearch',
      urlPattern: '/api/users/safe',
      httpMethods: ['GET'],
      parameters: [
        { name: 'name', type: 'String', source: 'query' }
      ],
      riskLevel: 'medium'
    }
    
    const decompiledSources = new Map<string, DecompileResult>([[
      'UserController',
      {
        className: 'UserController',
        sourceCode,
        packageName: 'com.example',
        imports: ['java.sql.*'],
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
    
    // 使用 PreparedStatement 不应该报告漏洞
    expect(vulnerabilities.length).toBe(0)
  })
  
  it('#given StringBuilder concatenation #when audit is called #then should detect SQL injection', async () => {
    const sourceCode = `
      public void search(String userInput) {
        // 使用 StringBuilder 构建动态 SQL
        StringBuilder sql = new StringBuilder("SELECT * FROM users WHERE name = '");
        sql.append(userInput).append("'");
        Statement stmt = connection.createStatement();
        ResultSet rs = stmt.executeQuery(sql.toString());
      }
    `
    
    const entry: AttackEntry = {
      type: 'controller',
      className: 'QueryController',
      methodName: 'search',
      urlPattern: '/api/search',
      httpMethods: ['GET'],
      parameters: [
        { name: 'userInput', type: 'String', source: 'query' }
      ],
      riskLevel: 'high'
    }
    
    const decompiledSources = new Map<string, DecompileResult>([[
      'QueryController',
      {
        className: 'QueryController',
        sourceCode,
        packageName: 'com.example',
        imports: ['java.sql.*'],
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
