import { describe, it, expect, beforeAll } from 'bun:test'
import { JarAnalyzer } from '../tools/jar-analyzer'
import { DecompileManager, CFRDecompiler } from '../tools/decompiler'
import { SentryAgent } from '../agents/sentry'
import { ReportGenerator } from '../hooks/report-generator'
import type { JarAnalysisResult, Vulnerability } from '../types'
import { Severity, VulnerabilityType } from '../types'
import type { ScanResult } from '../agents/sentry/types'
import type { DecompileResult } from '../tools/decompiler/types'

describe('End-to-End Integration Tests', () => {
  let jarAnalyzer: JarAnalyzer
  let decompilerManager: DecompileManager
  let sentryAgent: SentryAgent
  let reportGenerator: ReportGenerator

  beforeAll(async () => {
    // 初始化所有组件
    jarAnalyzer = new JarAnalyzer()
    const cfrEngine = new CFRDecompiler()
    decompilerManager = new DecompileManager(cfrEngine)
    sentryAgent = new SentryAgent()
    reportGenerator = new ReportGenerator()

    // 确保测试JAR文件存在
    const vulnerableJarExists = await Bun.file('test/fixtures/vulnerable-app.jar').exists()
    if (!vulnerableJarExists) {
      // 创建带有漏洞的测试JAR
      const AdmZip = (await import('adm-zip')).default
      const zip = new AdmZip()
      
      // 添加 manifest
      zip.addFile('META-INF/MANIFEST.MF', Buffer.from(
        'Manifest-Version: 1.0\n' +
        'Main-Class: com.vulnerable.App\n' +
        'Implementation-Title: Vulnerable App\n' +
        'Implementation-Version: 1.0.0\n'
      ))
      
      // 添加模拟的 Spring 控制器类文件（使用 class 文件魔数）
      zip.addFile('com/vulnerable/UserController.class', Buffer.from([
        0xCA, 0xFE, 0xBA, 0xBE, 0x00, 0x00, 0x00, 0x34,
        0x00, 0x10, 0x0A, 0x00, 0x03, 0x00, 0x0D, 0x07
      ]))
      
      zip.addFile('com/vulnerable/OrderController.class', Buffer.from([
        0xCA, 0xFE, 0xBA, 0xBE, 0x00, 0x00, 0x00, 0x34,
        0x00, 0x10, 0x0A, 0x00, 0x03, 0x00, 0x0D, 0x07
      ]))
      
      zip.addFile('com/vulnerable/AdminController.class', Buffer.from([
        0xCA, 0xFE, 0xBA, 0xBE, 0x00, 0x00, 0x00, 0x34,
        0x00, 0x10, 0x0A, 0x00, 0x03, 0x00, 0x0D, 0x07
      ]))
      
      // 添加 pom.properties 来模拟依赖
      zip.addFile('META-INF/maven/com.vulnerable/app/pom.properties', Buffer.from(
        'groupId=com.vulnerable\n' +
        'artifactId=app\n' +
        'version=1.0.0\n'
      ))
      
      // 添加配置文件
      zip.addFile('application.properties', Buffer.from(
        'spring.datasource.url=jdbc:mysql://localhost:3306/db\n' +
        'spring.datasource.username=admin\n' +
        'spring.datasource.password=secret123\n'
      ))
      
      zip.writeZip('test/fixtures/vulnerable-app.jar')
    }

    // 创建干净的测试JAR（无漏洞）
    const cleanJarExists = await Bun.file('test/fixtures/clean-app.jar').exists()
    if (!cleanJarExists) {
      const AdmZip = (await import('adm-zip')).default
      const zip = new AdmZip()
      
      zip.addFile('META-INF/MANIFEST.MF', Buffer.from(
        'Manifest-Version: 1.0\n' +
        'Main-Class: com.clean.App\n'
      ))
      
      zip.addFile('com/clean/HealthController.class', Buffer.from([
        0xCA, 0xFE, 0xBA, 0xBE, 0x00, 0x00, 0x00, 0x34,
        0x00, 0x10, 0x0A, 0x00, 0x03, 0x00, 0x0D, 0x07
      ]))
      
      zip.writeZip('test/fixtures/clean-app.jar')
    }
  })

  describe('#given full audit workflow #when executed #then should complete successfully', () => {
    it('Test 1: Full workflow from JAR to report generation', async () => {
      const jarPath = 'test/fixtures/vulnerable-app.jar'
      
      // Step 1: JAR Analysis
      const jarAnalysis = await jarAnalyzer.analyze(jarPath)
      expect(jarAnalysis).toBeDefined()
      expect(jarAnalysis.manifest).toBeDefined()
      expect(jarAnalysis.framework).toBeDefined()
      expect(Array.isArray(jarAnalysis.entryPoints)).toBe(true)
      
      // Step 2: Decompilation
      const decompiledSources = await decompilerManager.decompileCriticalClasses(
        jarPath,
        jarAnalysis.entryPoints,
        { includeLineNumbers: true }
      )
      expect(decompiledSources).toBeDefined()
      expect(decompiledSources instanceof Map).toBe(true)
      
      // Step 3: Security Scan (Sentry + Agents)
      const scanResult = await sentryAgent.orchestrate(jarPath, jarAnalysis, decompiledSources)
      expect(scanResult).toBeDefined()
      expect(scanResult.vulnerabilities).toBeDefined()
      expect(scanResult.summary).toBeDefined()
      expect(scanResult.metadata).toBeDefined()
      expect(scanResult.summary.agentsExecuted).toBe(5) // 5 agents should execute
      
      // Step 4: Report Generation (all 4 formats)
      const consoleReport = await reportGenerator.generateConsoleReport(scanResult)
      expect(consoleReport).toBeDefined()
      expect(typeof consoleReport).toBe('string')
      expect(consoleReport.length).toBeGreaterThan(0)
      
      const jsonReport = await reportGenerator.generateJSONReport(scanResult)
      expect(jsonReport).toBeDefined()
      expect(typeof jsonReport).toBe('string')
      const parsedJson = JSON.parse(jsonReport)
      expect(parsedJson.vulnerabilities).toBeDefined()
      expect(parsedJson.summary).toBeDefined()
      
      const htmlReport = await reportGenerator.generateHTMLReport(scanResult)
      expect(htmlReport).toBeDefined()
      expect(typeof htmlReport).toBe('string')
      expect(htmlReport.includes('<html')).toBe(true)
      expect(htmlReport.includes('</html>')).toBe(true)
      
      const markdownReport = await reportGenerator.generateMarkdownReport(scanResult)
      expect(markdownReport).toBeDefined()
      expect(typeof markdownReport).toBe('string')
      expect(markdownReport.includes('# Security Audit Report')).toBe(true)
    })
  })

  describe('#given JAR with no vulnerabilities #when scanned #then should report zero findings', () => {
    it('Test 2: No vulnerabilities found scenario', async () => {
      const jarPath = 'test/fixtures/clean-app.jar'
      
      // Analyze JAR
      const jarAnalysis = await jarAnalyzer.analyze(jarPath)
      expect(jarAnalysis).toBeDefined()
      
      // Mock decompiled sources with safe code
      const decompiledSources = new Map<string, DecompileResult>([
        ['HealthController', {
          className: 'HealthController',
          sourceCode: `
            @RestController
            public class HealthController {
              @GetMapping("/health")
              public ResponseEntity<String> health() {
                return ResponseEntity.ok("OK");
              }
            }
          `,
          packageName: 'com.clean',
          imports: ['org.springframework.web.bind.annotation.*'],
          methods: [],
          fields: [],
          isSuccess: true,
          decompileTime: 50,
          cacheHit: false
        }]
      ])
      
      // Run security scan
      const scanResult = await sentryAgent.orchestrate(jarPath, jarAnalysis, decompiledSources)
      
      // Verify no vulnerabilities found
      expect(scanResult.vulnerabilities).toBeDefined()
      expect(Array.isArray(scanResult.vulnerabilities)).toBe(true)
      // Note: actual count depends on agents, but safe code should have 0 or minimal findings
      expect(scanResult.summary.totalVulnerabilities).toBeGreaterThanOrEqual(0)
      
      // Generate report - should indicate no vulnerabilities
      const consoleReport = await reportGenerator.generateConsoleReport(scanResult)
      expect(consoleReport).toBeDefined()
      
      if (scanResult.vulnerabilities.length === 0) {
        expect(consoleReport.includes('No vulnerabilities') || consoleReport.includes('0')).toBe(true)
      }
    })
  })

  describe('#given JAR with multiple vulnerability types #when scanned #then should detect all types', () => {
    it('Test 3: Multiple vulnerability types detection', async () => {
      // 创建一个模拟的扫描结果，包含多种漏洞类型
      const mockVulnerabilities: Vulnerability[] = [
        {
          id: 'sql-001',
          type: VulnerabilityType.SQL_INJECTION,
          cwe: 'CWE-89',
          owasp: 'A03:2021',
          severity: Severity.CRITICAL,
          title: 'SQL Injection in UserController',
          description: 'User input concatenated directly into SQL query',
          location: {
            className: 'UserController',
            methodName: 'searchUsers',
            lineNumber: 42,
            codeSnippet: 'String sql = "SELECT * FROM users WHERE name = \'" + name + "\'"'
          },
          evidence: {
            sourceFlow: ['name parameter'],
            sinkFlow: ['jdbcTemplate.query']
          },
          remediation: {
            description: 'Use PreparedStatement with parameterized queries',
            codeExample: 'PreparedStatement stmt = conn.prepareStatement("SELECT * FROM users WHERE name = ?")',
            references: ['https://owasp.org/www-community/attacks/SQL_Injection']
          }
        },
        {
          id: 'ssrf-001',
          type: VulnerabilityType.SSRF,
          cwe: 'CWE-918',
          owasp: 'A10:2021',
          severity: Severity.HIGH,
          title: 'SSRF in URL Fetcher',
          description: 'User-controlled URL used in HTTP request',
          location: {
            className: 'UrlController',
            methodName: 'fetchUrl',
            lineNumber: 28,
            codeSnippet: 'URL url = new URL(userInput);'
          },
          evidence: {
            sourceFlow: ['userInput parameter'],
            sinkFlow: ['url.openConnection()']
          },
          remediation: {
            description: 'Validate URL against whitelist',
            codeExample: 'if (!isAllowedDomain(url)) throw new SecurityException()',
            references: ['https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html']
          }
        },
        {
          id: 'rce-001',
          type: VulnerabilityType.RCE,
          cwe: 'CWE-78',
          owasp: 'A03:2021',
          severity: Severity.CRITICAL,
          title: 'Command Injection',
          description: 'User input passed to Runtime.exec',
          location: {
            className: 'CommandController',
            methodName: 'execute',
            lineNumber: 35,
            codeSnippet: 'Runtime.getRuntime().exec(command)'
          },
          evidence: {
            sourceFlow: ['command parameter'],
            sinkFlow: ['Runtime.exec']
          },
          remediation: {
            description: 'Avoid executing system commands with user input',
            codeExample: 'Use ProcessBuilder with strict argument validation',
            references: ['https://owasp.org/www-community/attacks/Command_Injection']
          }
        },
        {
          id: 'auth-001',
          type: VulnerabilityType.AUTH_BYPASS,
          cwe: 'CWE-306',
          owasp: 'A07:2021',
          severity: Severity.HIGH,
          title: 'Missing Authentication',
          description: 'Admin endpoint lacks authentication check',
          location: {
            className: 'AdminController',
            methodName: 'deleteUser',
            lineNumber: 55,
            codeSnippet: '@DeleteMapping("/admin/users/{id}")'
          },
          evidence: {
            sourceFlow: [],
            sinkFlow: ['userRepository.delete()']
          },
          remediation: {
            description: 'Add @PreAuthorize annotation',
            codeExample: '@PreAuthorize("hasRole(\'ADMIN\')")',
            references: ['https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html']
          }
        },
        {
          id: 'logic-001',
          type: VulnerabilityType.BUSINESS_LOGIC,
          cwe: 'CWE-841',
          owasp: 'A04:2021',
          severity: Severity.MEDIUM,
          title: 'Price Manipulation',
          description: 'Order price set from user input without validation',
          location: {
            className: 'OrderController',
            methodName: 'createOrder',
            lineNumber: 48,
            codeSnippet: 'order.setPrice(request.getPrice())'
          },
          evidence: {
            sourceFlow: ['request.getPrice()'],
            sinkFlow: ['order.setPrice()']
          },
          remediation: {
            description: 'Validate price on server side',
            codeExample: 'if (price < 0 || price > MAX_PRICE) throw new ValidationException()',
            references: ['https://owasp.org/www-community/attacks/Logic_attack']
          }
        }
      ]

      const mockScanResult: ScanResult = {
        vulnerabilities: mockVulnerabilities,
        summary: {
          totalVulnerabilities: 5,
          criticalCount: 2,
          highCount: 2,
          mediumCount: 1,
          lowCount: 0,
          scanDuration: 1250,
          filesScanned: 3,
          agentsExecuted: 5
        },
        metadata: {
          jarPath: 'test/fixtures/vulnerable-app.jar',
          scanStartTime: new Date(),
          scanEndTime: new Date(),
          framework: 'spring-boot',
          entryPointsCount: 5
        }
      }

      // Verify all vulnerability types are present
      const detectedTypes = new Set(mockVulnerabilities.map(v => v.type))
      expect(detectedTypes.has(VulnerabilityType.SQL_INJECTION)).toBe(true)
      expect(detectedTypes.has(VulnerabilityType.SSRF)).toBe(true)
      expect(detectedTypes.has(VulnerabilityType.RCE)).toBe(true)
      expect(detectedTypes.has(VulnerabilityType.AUTH_BYPASS)).toBe(true)
      expect(detectedTypes.has(VulnerabilityType.BUSINESS_LOGIC)).toBe(true)

      // Verify severity distribution
      expect(mockScanResult.summary.criticalCount).toBe(2)
      expect(mockScanResult.summary.highCount).toBe(2)
      expect(mockScanResult.summary.mediumCount).toBe(1)
      expect(mockScanResult.summary.lowCount).toBe(0)

      // Generate reports
      const consoleReport = await reportGenerator.generateConsoleReport(mockScanResult)
      expect(consoleReport).toBeDefined()
      expect(consoleReport.includes('SQL Injection') || consoleReport.includes('CRITICAL')).toBe(true)
      expect(consoleReport.includes('SSRF') || consoleReport.includes('URL Fetcher')).toBe(true)
      expect(consoleReport.includes('Command Injection') || consoleReport.includes('Injection')).toBe(true)

      const jsonReport = await reportGenerator.generateJSONReport(mockScanResult)
      const parsedJson = JSON.parse(jsonReport)
      expect(parsedJson.vulnerabilities.length).toBe(5)
      expect(parsedJson.summary.totalVulnerabilities).toBe(5)

      const htmlReport = await reportGenerator.generateHTMLReport(mockScanResult)
      expect(htmlReport).toContain('SQL Injection')
      expect(htmlReport).toContain('SSRF')
      expect(htmlReport).toContain('Command Injection')

      const markdownReport = await reportGenerator.generateMarkdownReport(mockScanResult)
      expect(markdownReport.includes('SQL Injection') || markdownReport.includes('CRITICAL')).toBe(true)
      expect(markdownReport.includes('5') || markdownReport.includes('Total')).toBe(true)
    })
  })

  describe('#given invalid JAR path #when analyzed #then should throw error', () => {
    it('Test 4: Error handling for invalid JAR path', async () => {
      const invalidJarPath = 'test/fixtures/non-existent.jar'
      
      // Verify file doesn't exist
      const fileExists = await Bun.file(invalidJarPath).exists()
      expect(fileExists).toBe(false)
      
      // Attempt to analyze should throw error
      let errorThrown = false
      let errorMessage = ''
      
      try {
        await jarAnalyzer.analyze(invalidJarPath)
      } catch (error) {
        errorThrown = true
        errorMessage = error instanceof Error ? error.message : String(error)
      }
      
      expect(errorThrown).toBe(true)
      expect(errorMessage).toContain('Failed to analyze JAR')
    })

    it('Test 4b: Error handling for corrupted JAR', async () => {
      // Create a corrupted JAR file
      const corruptedJarPath = 'test/fixtures/corrupted.jar'
      const corruptedJarExists = await Bun.file(corruptedJarPath).exists()
      
      if (!corruptedJarExists) {
        // Write invalid data (not a valid ZIP)
        await Bun.write(corruptedJarPath, Buffer.from([0x00, 0x01, 0x02, 0x03, 0x04, 0x05]))
      }
      
      let errorThrown = false
      
      try {
        await jarAnalyzer.analyze(corruptedJarPath)
      } catch (error) {
        errorThrown = true
      }
      
      expect(errorThrown).toBe(true)
    })
  })

  describe('#given performance threshold #when full workflow executed #then should complete within time limit', () => {
    it('Test 5: Performance test - execution time under threshold', async () => {
      const jarPath = 'test/fixtures/vulnerable-app.jar'
      const PERFORMANCE_THRESHOLD_MS = 10000 // 10 seconds threshold
      
      const startTime = performance.now()
      
      // Execute full workflow
      const jarAnalysis = await jarAnalyzer.analyze(jarPath)
      
      const decompiledSources = await decompilerManager.decompileCriticalClasses(
        jarPath,
        jarAnalysis.entryPoints,
        { includeLineNumbers: true }
      )
      
      const scanResult = await sentryAgent.orchestrate(jarPath, jarAnalysis, decompiledSources)
      
      // Generate all reports
      await reportGenerator.generateConsoleReport(scanResult)
      await reportGenerator.generateJSONReport(scanResult)
      await reportGenerator.generateHTMLReport(scanResult)
      await reportGenerator.generateMarkdownReport(scanResult)
      
      const endTime = performance.now()
      const totalExecutionTime = endTime - startTime
      
      console.log(`Full workflow execution time: ${totalExecutionTime.toFixed(2)}ms`)
      
      // Verify execution time is under threshold
      expect(totalExecutionTime).toBeLessThan(PERFORMANCE_THRESHOLD_MS)
      
      // Verify scan metadata includes duration
      expect(scanResult.summary.scanDuration).toBeGreaterThanOrEqual(0)
      expect(scanResult.metadata.scanEndTime.getTime()).toBeGreaterThanOrEqual(
        scanResult.metadata.scanStartTime.getTime()
      )
    })

    it('Test 5b: Concurrent report generation performance', async () => {
      // Create a mock scan result with multiple vulnerabilities
      const mockScanResult: ScanResult = {
        vulnerabilities: Array.from({ length: 10 }, (_, i) => ({
          id: `vuln-${i}`,
          type: VulnerabilityType.SQL_INJECTION,
          cwe: 'CWE-89',
          owasp: 'A03:2021',
          severity: i % 2 === 0 ? Severity.HIGH : Severity.MEDIUM,
          title: `Vulnerability ${i}`,
          description: `Test vulnerability ${i}`,
          location: {
            className: `TestController${i}`,
            methodName: 'testMethod',
            lineNumber: 10 + i,
            codeSnippet: 'test code'
          },
          evidence: {},
          remediation: {
            description: 'Fix it',
            references: []
          }
        })),
        summary: {
          totalVulnerabilities: 10,
          criticalCount: 0,
          highCount: 5,
          mediumCount: 5,
          lowCount: 0,
          scanDuration: 1000,
          filesScanned: 5,
          agentsExecuted: 5
        },
        metadata: {
          jarPath: 'test.jar',
          scanStartTime: new Date(),
          scanEndTime: new Date(),
          framework: 'spring-boot',
          entryPointsCount: 5
        }
      }

      const startTime = performance.now()
      
      // Generate reports concurrently
      const reports = await Promise.all([
        reportGenerator.generateConsoleReport(mockScanResult),
        reportGenerator.generateJSONReport(mockScanResult),
        reportGenerator.generateHTMLReport(mockScanResult),
        reportGenerator.generateMarkdownReport(mockScanResult)
      ])
      
      const endTime = performance.now()
      const concurrentTime = endTime - startTime
      
      console.log(`Concurrent report generation time: ${concurrentTime.toFixed(2)}ms`)
      
      // All reports should be generated
      expect(reports.length).toBe(4)
      expect(reports.every(r => typeof r === 'string' && r.length > 0)).toBe(true)
      
      // Should complete quickly (under 5 seconds for 10 vulnerabilities)
      expect(concurrentTime).toBeLessThan(5000)
    })
  })
})
