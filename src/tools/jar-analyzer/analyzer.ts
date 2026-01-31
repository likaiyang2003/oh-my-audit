import AdmZip from 'adm-zip'
import type { JarAnalysisResult, JarManifest, DetectedFramework, AttackEntry, Dependency, ConfigFile } from '../../types'
import type { AnalyzerOptions } from './types'

export class JarAnalyzer {
  private options: AnalyzerOptions
  
  constructor(options: AnalyzerOptions = {}) {
    this.options = {
      includeInnerClasses: true,
      maxEntryPoints: 100,
      riskThreshold: 0,
      ...options
    }
  }
  
  async analyze(jarPath: string): Promise<JarAnalysisResult> {
    try {
      const zip = new AdmZip(jarPath)
      const entries = zip.getEntries()
      
      // 1. 解析 Manifest
      const manifest = this.parseManifest(entries)
      
      // 2. 检测框架
      const framework = this.detectFramework(entries)
      
      // 3. 提取入口点
      const entryPoints = this.extractEntryPoints(entries, framework)
      
      // 4. 分析依赖
      const dependencies = this.analyzeDependencies(entries)
      
      // 5. 提取配置文件
      const configFiles = this.extractConfigFiles(entries)
      
      // 6. 计算风险评分
      const riskScore = this.calculateRiskScore(dependencies, configFiles)
      
      return {
        manifest,
        framework,
        entryPoints,
        dependencies,
        configFiles,
        riskScore
      }
    } catch (error) {
      throw new Error(`Failed to analyze JAR: ${error instanceof Error ? error.message : String(error)}`)
    }
  }
  
  private parseManifest(entries: AdmZip.IZipEntry[]): JarManifest {
    const manifestEntry = entries.find(e => e.entryName === 'META-INF/MANIFEST.MF')
    if (!manifestEntry) return {}
    
    const content = manifestEntry.getData().toString('utf-8')
    const lines = content.split('\n')
    
    const manifest: JarManifest = {}
    
    for (const line of lines) {
      const trimmed = line.trim()
      if (trimmed.startsWith('Main-Class:')) {
        manifest.mainClass = trimmed.split(':')[1].trim()
      } else if (trimmed.startsWith('Implementation-Version:')) {
        manifest.version = trimmed.split(':')[1].trim()
      } else if (trimmed.startsWith('Implementation-Title:')) {
        manifest.implementationTitle = trimmed.split(':')[1].trim()
      }
    }
    
    return manifest
  }
  
  private detectFramework(entries: AdmZip.IZipEntry[]): DetectedFramework {
    const classFiles = entries.filter(e => e.entryName.endsWith('.class'))
    const classNames = classFiles.map(e => 
      e.entryName.replace(/\//g, '.').replace('.class', '')
    )
    
    const indicators: string[] = []
    
    // 检测 Spring Boot
    if (classNames.some(c => c.includes('org.springframework.boot'))) {
      indicators.push('org.springframework.boot')
    }
    
    // 检测 Spring MVC
    if (classNames.some(c => c.includes('org.springframework.web'))) {
      indicators.push('org.springframework.web')
    }
    
    // 检测 Struts2
    if (classNames.some(c => c.includes('org.apache.struts2'))) {
      indicators.push('org.apache.struts2')
    }
    
    let type: DetectedFramework['type'] = 'unknown'
    if (indicators.includes('org.springframework.boot')) {
      type = 'spring-boot'
    } else if (indicators.includes('org.springframework.web')) {
      type = 'spring-mvc'
    } else if (indicators.includes('org.apache.struts2')) {
      type = 'struts2'
    }
    
    // 检查 web.xml
    const webXml = entries.find(e => e.entryName === 'WEB-INF/web.xml')
    if (webXml && type === 'unknown') {
      type = 'servlet'
      indicators.push('javax.servlet')
    }
    
    return { type, indicators }
  }
  
  private extractEntryPoints(entries: AdmZip.IZipEntry[], framework: DetectedFramework): AttackEntry[] {
    const entryPoints: AttackEntry[] = []
    const classFiles = entries.filter(e => e.entryName.endsWith('.class'))
    
    for (const entry of classFiles) {
      const className = entry.entryName.replace(/\//g, '.').replace('.class', '')
      
      // 检测 Controller 类（基于类名模式）
      if (framework.type === 'spring-boot' || framework.type === 'spring-mvc') {
        if (className.includes('Controller')) {
          entryPoints.push({
            type: 'controller',
            className,
            methodName: 'unknown',
            urlPattern: '/api/unknown',
            httpMethods: ['GET', 'POST'],
            parameters: [],
            riskLevel: 'medium'
          })
        }
      }
      
      // 检测 Servlet 类
      if (className.includes('Servlet')) {
        entryPoints.push({
          type: 'servlet',
          className,
          methodName: 'doGet',
          urlPattern: '/unknown',
          httpMethods: ['GET', 'POST'],
          parameters: [],
          riskLevel: 'medium'
        })
      }
    }
    
    return entryPoints.slice(0, this.options.maxEntryPoints)
  }
  
  private analyzeDependencies(entries: AdmZip.IZipEntry[]): Dependency[] {
    const dependencies: Dependency[] = []
    
    // 查找 pom.properties 文件
    const pomFiles = entries.filter(e => 
      e.entryName.includes('META-INF/maven/') && 
      e.entryName.endsWith('pom.properties')
    )
    
    for (const pomEntry of pomFiles) {
      try {
        const content = pomEntry.getData().toString('utf-8')
        const lines = content.split('\n')
        
        let groupId = '', artifactId = '', version = ''
        
        for (const line of lines) {
          const trimmed = line.trim()
          if (trimmed.startsWith('groupId=')) {
            groupId = trimmed.split('=')[1].trim()
          } else if (trimmed.startsWith('artifactId=')) {
            artifactId = trimmed.split('=')[1].trim()
          } else if (trimmed.startsWith('version=')) {
            version = trimmed.split('=')[1].trim()
          }
        }
        
        if (groupId && artifactId) {
          dependencies.push({
            groupId,
            artifactId,
            version,
            isVulnerable: this.checkVulnerability(groupId, artifactId, version)
          })
        }
      } catch (error) {
        // 忽略解析错误的文件
        console.warn(`Failed to parse pom.properties: ${pomEntry.entryName}`)
      }
    }
    
    return dependencies
  }
  
  private checkVulnerability(groupId: string, artifactId: string, version: string): boolean {
    // 简化的漏洞检测逻辑
    const vulnerableLibs: Record<string, string[]> = {
      'log4j:log4j': ['2.0', '2.14.1'],
      'org.apache.logging.log4j:log4j-core': ['2.0', '2.14.1'],
      'org.apache.logging.log4j:log4j-api': ['2.0', '2.14.1']
    }
    
    const key = `${groupId}:${artifactId}`
    const vulnerableVersions = vulnerableLibs[key]
    
    if (vulnerableVersions) {
      return vulnerableVersions.some(v => version.startsWith(v))
    }
    
    return false
  }
  
  private extractConfigFiles(entries: AdmZip.IZipEntry[]): ConfigFile[] {
    const configFiles: ConfigFile[] = []
    const configPatterns = [
      /application.*\.ya?ml$/,
      /application.*\.properties$/,
      /web\.xml$/,
      /spring.*\.xml$/
    ]
    
    for (const entry of entries) {
      if (configPatterns.some(p => p.test(entry.entryName))) {
        let type: ConfigFile['type'] = 'xml'
        if (entry.entryName.endsWith('.yml') || entry.entryName.endsWith('.yaml')) {
          type = 'yaml'
        } else if (entry.entryName.endsWith('.properties')) {
          type = 'properties'
        }
        
        try {
          configFiles.push({
            path: entry.entryName,
            type,
            content: entry.getData().toString('utf-8')
          })
        } catch (error) {
          console.warn(`Failed to read config file: ${entry.entryName}`)
        }
      }
    }
    
    return configFiles
  }
  
  private calculateRiskScore(dependencies: Dependency[], configFiles: ConfigFile[]): number {
    let score = 0
    
    // 漏洞依赖加分
    const vulnerableDeps = dependencies.filter(d => d.isVulnerable)
    score += vulnerableDeps.length * 20
    
    // 配置文件中的敏感信息
    for (const config of configFiles) {
      if (config.content.match(/password\s*=\s*[^\s]+/i)) {
        score += 15
      }
      if (config.content.match(/secret\s*=\s*[^\s]+/i)) {
        score += 15
      }
    }
    
    return Math.min(score, 100)
  }
}
