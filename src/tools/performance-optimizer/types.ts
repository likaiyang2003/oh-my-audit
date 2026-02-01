// Types for performance optimizer

export interface CacheEntry<T> {
  value: T
  timestamp: number
}

export interface CacheStats {
  hits: number
  misses: number
  hitRate: number
  size: number
  maxSize: number
}

export interface CacheOptions {
  maxSize: number
  ttlMs: number
}

export interface ParallelExecutorOptions {
  maxConcurrency: number
}

export interface ExecutionProgress {
  completed: number
  total: number
  percentage: number
}

export type ProgressCallback = (progress: number) => void

export interface PhaseMetrics {
  startTime: number
  endTime?: number
  duration?: number
}

export interface PerformanceMetrics {
  phases: Record<string, PhaseMetrics>
  memory: {
    used: number
    total: number
  }
  cacheHits: number
  cacheMisses: number
  cacheHitRate: number
}

export interface OptimizerOptions {
  cacheSize?: number
  cacheTtlMs?: number
  maxConcurrency?: number
  memoryThreshold?: number
}

export interface MemoryStatus {
  used: number
  total: number
  threshold: number
  underThreshold: boolean
}

export type TaskFunction<T> = () => Promise<T>
