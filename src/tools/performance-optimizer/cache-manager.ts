import type { CacheEntry, CacheStats, CacheOptions } from './types'

export class CacheManager<T = unknown> {
  private cache: Map<string, CacheEntry<T>>
  private hits: number
  private misses: number
  private readonly maxSize: number
  private readonly ttlMs: number

  constructor(options: CacheOptions) {
    this.cache = new Map()
    this.hits = 0
    this.misses = 0
    this.maxSize = options.maxSize
    this.ttlMs = options.ttlMs
  }

  get(key: string): T | undefined {
    const entry = this.cache.get(key)

    if (!entry) {
      this.misses++
      return undefined
    }

    // Check if entry has expired
    if (Date.now() - entry.timestamp > this.ttlMs) {
      this.cache.delete(key)
      this.misses++
      return undefined
    }

    // Move to end (most recently used) - LRU strategy
    this.cache.delete(key)
    this.cache.set(key, entry)

    this.hits++
    return entry.value
  }

  set(key: string, value: T): void {
    // If key exists, delete it first (will be re-added at end)
    if (this.cache.has(key)) {
      this.cache.delete(key)
    }

    // If at capacity, remove oldest entry (first item in Map)
    if (this.cache.size >= this.maxSize) {
      const firstKey = this.cache.keys().next().value
      if (firstKey !== undefined) {
        this.cache.delete(firstKey)
      }
    }

    this.cache.set(key, {
      value,
      timestamp: Date.now()
    })
  }

  has(key: string): boolean {
    const entry = this.cache.get(key)
    if (!entry) return false

    // Check if entry has expired
    if (Date.now() - entry.timestamp > this.ttlMs) {
      this.cache.delete(key)
      return false
    }

    return true
  }

  delete(key: string): boolean {
    return this.cache.delete(key)
  }

  clear(): void {
    this.cache.clear()
    this.hits = 0
    this.misses = 0
  }

  getStats(): CacheStats {
    const total = this.hits + this.misses
    return {
      hits: this.hits,
      misses: this.misses,
      hitRate: total > 0 ? this.hits / total : 0,
      size: this.cache.size,
      maxSize: this.maxSize
    }
  }

  size(): number {
    return this.cache.size
  }
}
