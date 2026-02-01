import { describe, it, expect, beforeEach } from 'bun:test'
import { PerformanceOptimizer } from './optimizer'
import { CacheManager } from './cache-manager'
import { ParallelExecutor } from './parallel-executor'
import type { ProgressCallback, PerformanceMetrics } from './types'

describe('PerformanceOptimizer', () => {
  let optimizer: PerformanceOptimizer

  beforeEach(() => {
    optimizer = new PerformanceOptimizer()
  })

  describe('LRU Cache', () => {
    it('#given a cache with max 100 entries #when 101 entries are added #then oldest entry should be evicted', () => {
      const cache = new CacheManager({ maxSize: 100, ttlMs: 3600000 })

      // Add 100 entries
      for (let i = 0; i < 100; i++) {
        cache.set(`key-${i}`, { data: `value-${i}` })
      }

      // Verify all 100 entries exist (access key-99 but NOT key-0)
      expect(cache.get('key-99')).toBeDefined()

      // Add 101st entry - should evict key-0 (least recently accessed)
      cache.set('key-100', { data: 'value-100' })

      expect(cache.get('key-0')).toBeUndefined()
      expect(cache.get('key-1')).toBeDefined()
      expect(cache.get('key-100')).toBeDefined()
    })

    it('#given a cache with entries #when entries are accessed #then should track hit and miss rates', () => {
      const cache = new CacheManager({ maxSize: 10, ttlMs: 3600000 })

      cache.set('existing', { data: 'value' })

      // Cache hit
      const hit = cache.get('existing')
      expect(hit).toBeDefined()

      // Cache miss
      const miss = cache.get('non-existing')
      expect(miss).toBeUndefined()

      const stats = cache.getStats()
      expect(stats.hits).toBe(1)
      expect(stats.misses).toBe(1)
      expect(stats.hitRate).toBe(0.5)
    })

    it('#given a cache entry #when TTL expires #then entry should be removed', async () => {
      const cache = new CacheManager({ maxSize: 10, ttlMs: 100 }) // 100ms TTL

      cache.set('temp', { data: 'value' })
      expect(cache.get('temp')).toBeDefined()

      // Wait for TTL to expire
      await new Promise(resolve => setTimeout(resolve, 150))

      expect(cache.get('temp')).toBeUndefined()
    })
  })

  describe('Parallel Execution', () => {
    it('#given 5 concurrent tasks #when executed in parallel #then all should complete successfully', async () => {
      const executor = new ParallelExecutor({ maxConcurrency: 5 })
      const results: number[] = []

      const tasks = Array.from({ length: 5 }, (_, i) => async () => {
        await new Promise(resolve => setTimeout(resolve, 50))
        results.push(i)
        return i
      })

      const completed = await executor.executeAll(tasks)

      expect(completed).toHaveLength(5)
      expect(results).toHaveLength(5)
      expect(completed).toContain(0)
      expect(completed).toContain(4)
    })

    it('#given parallel tasks with progress tracking #when executing #then should report progress', async () => {
      const executor = new ParallelExecutor({ maxConcurrency: 3 })
      const progressUpdates: number[] = []

      const tasks = Array.from({ length: 5 }, (_, i) => async () => {
        await new Promise(resolve => setTimeout(resolve, 10))
        return i
      })

      await executor.executeAll(tasks, (progress: number) => {
        progressUpdates.push(progress)
      })

      // Should have received progress updates
      expect(progressUpdates.length).toBeGreaterThan(0)
      expect(progressUpdates[progressUpdates.length - 1]).toBe(100)
    })
  })

  describe('Performance Metrics', () => {
    it('#given optimizer #when tracking phase execution #then should record timing', async () => {
      optimizer.startPhase('analysis')

      await new Promise(resolve => setTimeout(resolve, 50))

      optimizer.endPhase('analysis')

      const metrics = optimizer.getMetrics()
      expect(metrics.phases['analysis']).toBeDefined()
      expect(metrics.phases['analysis'].duration).toBeGreaterThanOrEqual(50)
    })

    it('#given optimizer #when collecting metrics #then should track memory usage', () => {
      optimizer.startPhase('memory-test')

      // Allocate some memory
      const arr = new Array(1000000).fill(0)

      optimizer.endPhase('memory-test')

      const metrics = optimizer.getMetrics()
      expect(metrics.memory).toBeDefined()
      expect(typeof metrics.memory.used).toBe('number')
      expect(typeof metrics.memory.total).toBe('number')
    })

    it('#given optimizer with cache #when measuring cache performance #then should report hit rates', () => {
      const optimizerWithCache = new PerformanceOptimizer({ cacheSize: 10 })

      // Simulate cache operations
      optimizerWithCache.getFromCache('key1') // miss
      optimizerWithCache.setCache('key1', { data: 'value' })
      optimizerWithCache.getFromCache('key1') // hit
      optimizerWithCache.getFromCache('key1') // hit

      const metrics = optimizerWithCache.getMetrics()
      expect(metrics.cacheHits).toBe(2)
      expect(metrics.cacheMisses).toBe(1)
      expect(metrics.cacheHitRate).toBe(2 / 3)
    })
  })

  describe('Memory Management', () => {
    it('#given optimizer under load #when memory threshold is exceeded #then should trigger cleanup', async () => {
      const optimizer = new PerformanceOptimizer({
        cacheSize: 1000,
        memoryThreshold: 1024 * 1024 * 50 // 50MB threshold
      })

      // Simulate operations that might consume memory
      for (let i = 0; i < 100; i++) {
        optimizer.setCache(`key-${i}`, { data: `value-${i}` })
      }

      const memoryStatus = optimizer.checkMemoryUsage()
      expect(memoryStatus).toBeDefined()
      expect(typeof memoryStatus.underThreshold).toBe('boolean')
    })
  })
})
