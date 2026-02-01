import type { ParallelExecutorOptions, TaskFunction, ProgressCallback } from './types'

export class ParallelExecutor {
  private maxConcurrency: number

  constructor(options: ParallelExecutorOptions) {
    this.maxConcurrency = options.maxConcurrency
  }

  async executeAll<T>(tasks: TaskFunction<T>[], progressCallback?: ProgressCallback): Promise<T[]> {
    const results: T[] = new Array(tasks.length)
    let completed = 0

    // Create a wrapper for each task that tracks progress
    const wrappedTasks = tasks.map((task, index) => async () => {
      const result = await task()
      results[index] = result
      completed++

      if (progressCallback) {
        const progress = Math.round((completed / tasks.length) * 100)
        progressCallback(progress)
      }

      return result
    })

    // Execute tasks with limited concurrency
    await this.runWithConcurrency(wrappedTasks)

    return results
  }

  private async runWithConcurrency<T>(tasks: TaskFunction<T>[]): Promise<void> {
    let index = 0

    const runNext = async (): Promise<void> => {
      if (index >= tasks.length) return

      const currentIndex = index++
      await tasks[currentIndex]()

      // Continue with next task
      if (index < tasks.length) {
        await runNext()
      }
    }

    // Start initial batch of concurrent tasks
    const initialBatch = Math.min(this.maxConcurrency, tasks.length)
    const promises: Promise<void>[] = []

    for (let i = 0; i < initialBatch; i++) {
      promises.push(runNext())
    }

    await Promise.all(promises)
  }

  async executeInBatches<T>(tasks: TaskFunction<T>[], batchSize: number): Promise<T[]> {
    const results: T[] = []

    for (let i = 0; i < tasks.length; i += batchSize) {
      const batch = tasks.slice(i, i + batchSize)
      const batchResults = await Promise.all(batch.map(task => task()))
      results.push(...batchResults)
    }

    return results
  }
}
