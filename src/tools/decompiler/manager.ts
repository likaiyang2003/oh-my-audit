import AdmZip from 'adm-zip'
import type { DecompilerEngine, DecompileOptions, DecompileResult } from './types'

export class DecompileManager {
  private engine: DecompilerEngine
  private cache: Map<string, DecompileResult>
  private cacheDir: string
  
  constructor(engine: DecompilerEngine, cacheDir = '.security-audit/cache/decompile') {
    this.engine = engine
    this.cache = new Map()
    this.cacheDir = cacheDir
  }
  
  /**
   * 从 JAR 中提取并反编译单个类
   */
  async decompileClass(
    jarPath: string, 
    className: string, 
    options?: DecompileOptions
  ): Promise<DecompileResult> {
    // 生成缓存 key
    const cacheKey = this.generateCacheKey(jarPath, className)
    
    // 检查内存缓存
    if (this.cache.has(cacheKey)) {
      const cached = this.cache.get(cacheKey)!
      return { ...cached, cacheHit: true }
    }
    
    // 检查磁盘缓存
    const diskCached = await this.loadFromDisk(cacheKey)
    if (diskCached) {
      this.cache.set(cacheKey, diskCached)
      return { ...diskCached, cacheHit: true }
    }
    
    try {
      // 从 JAR 中提取 class 文件
      const zip = new AdmZip(jarPath)
      const classEntry = zip.getEntry(`${className.replace(/\./g, '/')}.class`)
      
      if (!classEntry) {
        return {
          className,
          sourceCode: '',
          packageName: '',
          imports: [],
          methods: [],
          fields: [],
          isSuccess: false,
          error: `Class not found in JAR: ${className}`,
          decompileTime: 0,
          cacheHit: false
        }
      }
      
      const classFile = classEntry.getData()
      
      // 反编译
      const result = await this.engine.decompile(classFile, className, options)
      
      // 缓存结果
      if (result.isSuccess) {
        this.cache.set(cacheKey, result)
        await this.saveToDisk(cacheKey, result)
      }
      
      return result
    } catch (error) {
      return {
        className,
        sourceCode: '',
        packageName: '',
        imports: [],
        methods: [],
        fields: [],
        isSuccess: false,
        error: error instanceof Error ? error.message : String(error),
        decompileTime: 0,
        cacheHit: false
      }
    }
  }
  
  /**
   * 批量反编译多个类
   */
  async decompileBatch(
    jarPath: string,
    classNames: string[],
    options?: DecompileOptions,
    batchSize = 10
  ): Promise<DecompileResult[]> {
    const results: DecompileResult[] = []
    
    // 分批处理
    for (let i = 0; i < classNames.length; i += batchSize) {
      const batch = classNames.slice(i, i + batchSize)
      
      // 并行反编译
      const batchResults = await Promise.all(
        batch.map(name => this.decompileClass(jarPath, name, options))
      )
      
      results.push(...batchResults)
    }
    
    return results
  }
  
  /**
   * 智能反编译 - 只反编译关键类
   */
  async decompileCriticalClasses(
    jarPath: string,
    entryPoints: Array<{ className: string; riskLevel: string }>,
    options?: DecompileOptions
  ): Promise<Map<string, DecompileResult>> {
    // 按风险级别排序
    const sorted = entryPoints.sort((a, b) => {
      const riskOrder = { critical: 0, high: 1, medium: 2, low: 3 }
      return riskOrder[a.riskLevel as keyof typeof riskOrder] - 
             riskOrder[b.riskLevel as keyof typeof riskOrder]
    })
    
    // 只取前 maxEntryPoints 个
    const critical = sorted.slice(0, 50)
    
    const results = new Map<string, DecompileResult>()
    
    for (const entry of critical) {
      const result = await this.decompileClass(jarPath, entry.className, options)
      results.set(entry.className, result)
    }
    
    return results
  }
  
  /**
   * 生成缓存 key
   */
  private generateCacheKey(jarPath: string, className: string): string {
    // 简化版：使用 JAR 路径 + 类名
    // 实际应该使用 JAR 文件的 MD5
    const jarName = jarPath.split('/').pop() || jarPath
    return `${jarName}:${className}`
  }
  
  /**
   * 从磁盘加载缓存
   */
  private async loadFromDisk(cacheKey: string): Promise<DecompileResult | null> {
    try {
      const cacheFile = `${this.cacheDir}/${cacheKey.replace(/[/:]/g, '_')}.json`
      const content = await Bun.file(cacheFile).text()
      return JSON.parse(content)
    } catch {
      return null
    }
  }
  
  /**
   * 保存到磁盘缓存
   */
  private async saveToDisk(cacheKey: string, result: DecompileResult): Promise<void> {
    try {
      await Bun.write(
        `${this.cacheDir}/${cacheKey.replace(/[/:]/g, '_')}.json`,
        JSON.stringify(result)
      )
    } catch (error) {
      console.warn(`Failed to save cache: ${error}`)
    }
  }
  
  /**
   * 清理缓存
   */
  async clearCache(): Promise<void> {
    this.cache.clear()
    // 实际应该清理磁盘缓存
  }
  
  /**
   * 获取缓存统计
   */
  getCacheStats(): { memorySize: number; diskSize?: number } {
    return {
      memorySize: this.cache.size
    }
  }
}
