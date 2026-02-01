import { CacheManager } from './cache-manager'
import { ParallelExecutor } from './parallel-executor'
import type {
  OptimizerOptions,
  PerformanceMetrics,
  PhaseMetrics,
  MemoryStatus,
  CacheStats
} from './types'

export class PerformanceOptimizer {
  private cache: CacheManager<unknown>
  private executor: ParallelExecutor
  private phases: Map<string, PhaseMetrics>
  private cacheHits: number
  private cacheMisses: number
  private memoryThreshold: number

  constructor(options: OptimizerOptions = {}) {
    this.cache = new CacheManager({
      maxSize: options.cacheSize ?? 100,
      ttlMs: options.cacheTtlMs ?? 3600000 // 1 hour default
    })

    this.executor = new ParallelExecutor({
      maxConcurrency: options.maxConcurrency ?? 5
    })

    this.phases = new Map()
    this.cacheHits = 0
    this.cacheMisses = 0
    this.memoryThreshold = options.memoryThreshold ?? 1024 * 1024 * 100 // 100MB default
  }

  startPhase(name: string): void {
    this.phases.set(name, {
      startTime: Date.now()
    })
  }

  endPhase(name: string): void {
    const phase = this.phases.get(name)
    if (phase) {
      phase.endTime = Date.now()
      phase.duration = phase.endTime - phase.startTime
    }
  }

  getFromCache<T>(key: string): T | undefined {
    const result = this.cache.get(key)
    if (result === undefined) {
      this.cacheMisses++
    } else {
      this.cacheHits++
    }
    return result as T
  }

  setCache<T>(key: string, value: T): void {
    this.cache.set(key, value)
  }

  async executeParallel<T>(tasks: (() => Promise<T>)[], progressCallback?: (progress: number) => void): Promise<T[]> {
    return this.executor.executeAll(tasks, progressCallback)
  }

  getMetrics(): PerformanceMetrics {
    const total = this.cacheHits + this.cacheMisses
    const phaseRecord: Record<string, PhaseMetrics> = {}

    this.phases.forEach((value, key) => {
      phaseRecord[key] = value
    })

    return {
      phases: phaseRecord,
      memory: this.getMemoryUsage(),
      cacheHits: this.cacheHits,
      cacheMisses: this.cacheMisses,
      cacheHitRate: total > 0 ? this.cacheHits / total : 0
    }
  }

  getMemoryUsage(): { used: number; total: number } {
    // In Bun/Node environment, use process.memoryUsage
    if (typeof process !== 'undefined' && process.memoryUsage) {
      const usage = process.memoryUsage()
      return {
        used: usage.heapUsed,
        total: usage.heapTotal
      }
    }

    // Fallback for environments without process.memoryUsage
    return {
      used: 0,
      total: 0
    }
  }

  checkMemoryUsage(): MemoryStatus {
    const memory = this.getMemoryUsage()

    return {
      used: memory.used,
      total: memory.total,
      threshold: this.memoryThreshold,
      underThreshold: memory.used < this.memoryThreshold
    }
  }

  clearCache(): void {
    this.cache.clear()
    this.cacheHits = 0
    this.cacheMisses = 0
  }

  getCacheStats(): CacheStats {
    return this.cache.getStats()
  }

  reset(): void {
    this.clearCache()
    this.phases.clear()
  }
}
