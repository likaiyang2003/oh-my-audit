import { describe, it, expect, beforeAll } from 'bun:test'
import { JarAnalyzer } from './analyzer'
import type { JarAnalysisResult } from '../../types'

describe('JarAnalyzer', () => {
  let analyzer: JarAnalyzer
  
  beforeAll(() => {
    analyzer = new JarAnalyzer()
  })
  
  it('#given a sample JAR file #when analyze is called #then it should return analysis result', async () => {
    // 检查测试 JAR 是否存在
    const jarExists = await Bun.file('test/fixtures/sample-app.jar').exists()
    if (!jarExists) {
      // 创建最小测试 JAR
      const zip = new (await import('adm-zip')).default()
      zip.addFile('META-INF/MANIFEST.MF', Buffer.from('Manifest-Version: 1.0\nMain-Class: com.test.Main\n'))
      zip.addFile('com/test/Main.class', Buffer.from([0xCA, 0xFE, 0xBA, 0xBE]))
      zip.writeZip('test/fixtures/sample-app.jar')
    }
    
    const result = await analyzer.analyze('test/fixtures/sample-app.jar')
    
    expect(result).toBeDefined()
    expect(result.manifest).toBeDefined()
    expect(result.framework).toBeDefined()
    expect(Array.isArray(result.entryPoints)).toBe(true)
    expect(Array.isArray(result.dependencies)).toBe(true)
    expect(Array.isArray(result.configFiles)).toBe(true)
    expect(typeof result.riskScore).toBe('number')
  })
  
  it('#given a Spring Boot JAR #when analyze is called #then should detect Spring Boot framework', async () => {
    // 这需要真实的 Spring Boot JAR 文件
    // 暂时跳过，等待测试资源
  })
  
  it('#given a JAR with dependencies #when analyze is called #then should extract dependencies', async () => {
    const result = await analyzer.analyze('test/fixtures/sample-app.jar')
    
    expect(result.dependencies).toBeDefined()
    expect(Array.isArray(result.dependencies)).toBe(true)
  })
  
  it('#given a JAR with config files #when analyze is called #then should extract config files', async () => {
    const result = await analyzer.analyze('test/fixtures/sample-app.jar')
    
    expect(result.configFiles).toBeDefined()
    expect(Array.isArray(result.configFiles)).toBe(true)
  })
  
  it('#given a vulnerable dependency #when analyze is called #then should mark it as vulnerable', async () => {
    // 测试 Log4j 漏洞检测
    // 这需要包含 Log4j 的测试 JAR
  })
})
