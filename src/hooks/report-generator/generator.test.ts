import { describe, it, expect } from 'bun:test'
import { ReportGenerator } from './generator'
import type { ScanResult } from '../../agents/sentry/types'
import { Severity, VulnerabilityType } from '../../types'

describe('ReportGenerator', () => {
  const mockScanResult: ScanResult = {
    vulnerabilities: [
      {
        id: 'vuln-001',
        type: VulnerabilityType.SQL_INJECTION,
        cwe: 'CWE-89',
        owasp: 'A03:2021 - Injection',
        severity: Severity.CRITICAL,
        title: 'SQL Injection in UserController',
        description: 'User input directly concatenated into SQL query',
        location: {
          className: 'UserController',
          methodName: 'searchUsers',
          lineNumber: 45,
          codeSnippet: 'String sql = "SELECT * FROM users WHERE name = \'" + name + "\'"'
        },
        evidence: {
          sourceFlow: ['name parameter'],
          sinkFlow: ['jdbcTemplate.query(sql)']
        },
        remediation: {
          description: 'Use PreparedStatement',
          codeExample: 'PreparedStatement stmt = conn.prepareStatement("SELECT * FROM users WHERE name = ?")',
          references: ['https://owasp.org/sql-injection']
        }
      },
      {
        id: 'vuln-002',
        type: VulnerabilityType.SSRF,
        cwe: 'CWE-918',
        owasp: 'A10:2021 - SSRF',
        severity: Severity.HIGH,
        title: 'SSRF in FetchController',
        description: 'User-controlled URL used in HTTP request',
        location: {
          className: 'FetchController',
          methodName: 'fetchData',
          lineNumber: 23,
          codeSnippet: 'URL u = new URL(url);'
        },
        evidence: {
          sourceFlow: ['url parameter'],
          sinkFlow: ['u.openConnection()']
        },
        remediation: {
          description: 'Validate URL',
          references: ['https://cheatsheetseries.owasp.org/SSRF']
        }
      }
    ],
    summary: {
      totalVulnerabilities: 2,
      criticalCount: 1,
      highCount: 1,
      mediumCount: 0,
      lowCount: 0,
      scanDuration: 1500,
      filesScanned: 5,
      agentsExecuted: 5
    },
    metadata: {
      jarPath: '/path/to/app.jar',
      scanStartTime: new Date('2026-02-01T10:00:00Z'),
      scanEndTime: new Date('2026-02-01T10:01:30Z'),
      framework: 'spring-boot',
      entryPointsCount: 3
    }
  }

  it('#given scan result #when generateConsoleReport is called #then should produce readable output', async () => {
    const generator = new ReportGenerator()
    const report = await generator.generateConsoleReport(mockScanResult)
    
    expect(report).toBeDefined()
    expect(typeof report).toBe('string')
    expect(report).toContain('SQL Injection')
    expect(report).toContain('CRITICAL')
    expect(report).toContain('📊 Total: 2')
  })

  it('#given scan result #when generateJSONReport is called #then should produce valid JSON', async () => {
    const generator = new ReportGenerator()
    const report = await generator.generateJSONReport(mockScanResult)
    
    expect(report).toBeDefined()
    expect(typeof report).toBe('string')
    
    const parsed = JSON.parse(report)
    expect(parsed.vulnerabilities).toHaveLength(2)
    expect(parsed.summary.totalVulnerabilities).toBe(2)
    expect(parsed.metadata.framework).toBe('spring-boot')
  })

  it('#given scan result #when generateHTMLReport is called #then should produce HTML document', async () => {
    const generator = new ReportGenerator()
    const report = await generator.generateHTMLReport(mockScanResult)
    
    expect(report).toBeDefined()
    expect(typeof report).toBe('string')
    expect(report).toContain('<!DOCTYPE html>')
    expect(report).toContain('<html lang="en">')
    expect(report).toContain('SQL Injection')
    expect(report).toContain('critical')
  })

  it('#given scan result #when generateMarkdownReport is called #then should produce markdown', async () => {
    const generator = new ReportGenerator()
    const report = await generator.generateMarkdownReport(mockScanResult)
    
    expect(report).toBeDefined()
    expect(typeof report).toBe('string')
    expect(report).toContain('# Security Audit Report')
    expect(report).toContain('## Summary')
    expect(report).toContain('### 🔴 SQL Injection in UserController')
    expect(report).toContain('**Severity:** `CRITICAL`')
  })

  it('#given empty scan result #when generateReport is called #then should handle gracefully', async () => {
    const emptyResult: ScanResult = {
      vulnerabilities: [],
      summary: {
        totalVulnerabilities: 0,
        criticalCount: 0,
        highCount: 0,
        mediumCount: 0,
        lowCount: 0,
        scanDuration: 500,
        filesScanned: 3,
        agentsExecuted: 5
      },
      metadata: {
        jarPath: '/path/to/app.jar',
        scanStartTime: new Date(),
        scanEndTime: new Date(),
        framework: 'spring-boot',
        entryPointsCount: 2
      }
    }
    
    const generator = new ReportGenerator()
    const report = await generator.generateConsoleReport(emptyResult)
    
    expect(report).toContain('📊 Total: 0')
    expect(report).toContain('✅ No vulnerabilities found')
  })
})
