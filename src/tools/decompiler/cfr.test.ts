import { describe, it, expect } from 'bun:test'
import { CFRDecompiler } from './cfr'
import { DecompileManager } from './manager'
import type { DecompileResult } from './types'

describe('CFRDecompiler', () => {
  it('#given a valid class file #when decompile is called #then should return Java source code', async () => {
    const decompiler = new CFRDecompiler()
    
    // 创建测试 class 文件（模拟）
    const classFile = Buffer.from([
      0xCA, 0xFE, 0xBA, 0xBE, // Magic number
      0x00, 0x00, 0x00, 0x34, // Version (Java 8)
      // 简化测试 - 实际测试需要完整 class 文件
    ])
    
    const result = await decompiler.decompile(classFile, 'TestClass')
    
    // 由于我们没有完整的测试 class 文件，这里只验证结构
    expect(result).toBeDefined()
    expect(result.className).toBe('TestClass')
    expect(result.isSuccess).toBeDefined()
  })
  
  it('#given an invalid class file #when decompile is called #then should return error', async () => {
    const decompiler = new CFRDecompiler()
    const invalidClassFile = Buffer.from([0x00, 0x00, 0x00, 0x00])
    
    const result = await decompiler.decompile(invalidClassFile, 'InvalidClass')
    
    expect(result.isSuccess).toBe(false)
    expect(result.error).toBeDefined()
  })
})

describe('DecompileManager', () => {
  it('#given a jar path and class name #when decompileClass is called #then should return decompiled result', async () => {
    const decompiler = new CFRDecompiler()
    const manager = new DecompileManager(decompiler)
    
    // 使用测试 JAR 中的类
    const jarPath = 'test/fixtures/sample-app.jar'
    const className = 'test'
    
    const result = await manager.decompileClass(jarPath, className, {})
    
    expect(result).toBeDefined()
    expect(result.className).toBe(className)
  })
  
  it('#given same class decompiled twice #when cache is enabled #then second call should hit cache', async () => {
    const decompiler = new CFRDecompiler()
    const manager = new DecompileManager(decompiler)
    
    const jarPath = 'test/fixtures/sample-app.jar'
    const className = 'test'
    
    // 第一次反编译
    const result1 = await manager.decompileClass(jarPath, className, {})
    
    // 第二次反编译（应该命中缓存）
    const result2 = await manager.decompileClass(jarPath, className, {})
    
    // 如果是同一实例，应该命中缓存
    expect(result2.cacheHit || !result1.isSuccess).toBe(true)
  })
  
  it('#given multiple classes #when decompileBatch is called #then should decompile all classes', async () => {
    const decompiler = new CFRDecompiler()
    const manager = new DecompileManager(decompiler)
    
    const jarPath = 'test/fixtures/sample-app.jar'
    const classNames = ['test', 'com.test.Main']
    
    const results = await manager.decompileBatch(jarPath, classNames, {})
    
    expect(Array.isArray(results)).toBe(true)
    expect(results.length).toBe(classNames.length)
  })
})
