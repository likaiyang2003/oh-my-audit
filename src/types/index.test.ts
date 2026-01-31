import { describe, it, expect } from 'bun:test'
import type { JarAnalysisResult, AttackEntry, Vulnerability } from './index'
import { VulnerabilityType, Severity } from './index'

describe('types', () => {
  it('#given a valid JarAnalysisResult object #when accessed #then should have correct structure', () => {
    const result: JarAnalysisResult = {
      manifest: {
        mainClass: 'com.example.App',
        version: '1.0.0'
      },
      framework: {
        type: 'spring-boot',
        version: '2.7.0',
        indicators: ['org.springframework.boot']
      },
      entryPoints: [],
      dependencies: [],
      configFiles: [],
      riskScore: 0
    }
    
    expect(result.manifest.mainClass).toBe('com.example.App')
    expect(result.framework.type).toBe('spring-boot')
  })
  
  it('#given an AttackEntry #when created #then should have required fields', () => {
    const entry: AttackEntry = {
      type: 'controller',
      className: 'UserController',
      methodName: 'getUser',
      urlPattern: '/api/user/{id}',
      httpMethods: ['GET'],
      parameters: [
        { name: 'id', type: 'Long', annotation: '@PathVariable', source: 'path' }
      ],
      riskLevel: 'high'
    }
    
    expect(entry.type).toBe('controller')
    expect(entry.riskLevel).toBe('high')
    expect(entry.parameters).toHaveLength(1)
  })
  
  it('#given a Vulnerability #when created #then should have complete structure', () => {
    const vuln: Vulnerability = {
      id: 'vuln-001',
      type: VulnerabilityType.SQL_INJECTION,
      cwe: 'CWE-89',
      owasp: 'A03:2021 - Injection',
      severity: Severity.CRITICAL,
      title: 'SQL Injection in UserController',
      description: 'User input is directly concatenated into SQL query',
      location: {
        className: 'UserController',
        methodName: 'searchUsers',
        lineNumber: 45,
        codeSnippet: "String sql = \"SELECT * FROM users WHERE name = '\" + userInput + \"'\""
      },
      evidence: {
        sourceFlow: ['userInput parameter', 'String concatenation', 'sql variable'],
        sinkFlow: ['statement.executeQuery(sql)']
      },
      remediation: {
        description: 'Use PreparedStatement with parameterized queries',
        codeExample: 'PreparedStatement stmt = conn.prepareStatement("SELECT * FROM users WHERE name = ?");',
        references: ['https://owasp.org/www-community/attacks/SQL_Injection']
      }
    }
    
    expect(vuln.type).toBe(VulnerabilityType.SQL_INJECTION)
    expect(vuln.severity).toBe(Severity.CRITICAL)
    expect(vuln.cwe).toBe('CWE-89')
  })
})
