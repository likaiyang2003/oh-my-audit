import { spawn } from 'bun'
import type { DecompilerEngine, DecompileOptions, DecompileResult, MethodInfo, FieldInfo } from './types'

export class CFRDecompiler implements DecompilerEngine {
  private cfrJarPath: string
  private javaPath: string
  private timeout: number
  
  constructor(cfrJarPath = 'lib/cfr-0.152.jar', javaPath = 'java', timeout = 30000) {
    this.cfrJarPath = cfrJarPath
    this.javaPath = javaPath
    this.timeout = timeout
  }
  
  async decompile(classFile: Buffer, className: string, options?: DecompileOptions): Promise<DecompileResult> {
    const startTime = Date.now()
    const timeout = options?.timeout || this.timeout
    
    // 验证 class 文件魔数
    if (classFile.length < 4 || 
        classFile[0] !== 0xCA || classFile[1] !== 0xFE || 
        classFile[2] !== 0xBA || classFile[3] !== 0xBE) {
      return {
        className,
        sourceCode: '',
        packageName: '',
        imports: [],
        methods: [],
        fields: [],
        isSuccess: false,
        error: 'Invalid class file (wrong magic number)',
        decompileTime: Date.now() - startTime,
        cacheHit: false
      }
    }
    
    try {
      // 创建临时目录
      const tempDir = `${process.env.TEMP || '/tmp'}/decompile-${Date.now()}`
      await Bun.write(`${tempDir}/.keep`, '')
      
      const classFilePath = `${tempDir}/${className.replace(/\./g, '/')}.class`
      
      // 写入 class 文件
      await Bun.write(classFilePath, classFile)
      
      // 调用 CFR
      const proc = spawn({
        cmd: [this.javaPath, '-jar', this.cfrJarPath, classFilePath, '--outputdir', tempDir],
        stdout: 'pipe',
        stderr: 'pipe',
        timeout
      })
      
      const exitCode = await proc.exited
      
      if (exitCode !== 0) {
        const stderr = await new Response(proc.stderr).text()
        return {
          className,
          sourceCode: '',
          packageName: '',
          imports: [],
          methods: [],
          fields: [],
          isSuccess: false,
          error: `CFR exit code ${exitCode}: ${stderr.substring(0, 500)}`,
          decompileTime: Date.now() - startTime,
          cacheHit: false
        }
      }
      
      // 读取反编译后的 Java 文件
      const javaFile = `${tempDir}/${className.replace(/\./g, '/')}.java`
      const sourceCode = await Bun.file(javaFile).text()
      
      // 解析源码提取信息
      const { packageName, imports, methods, fields } = this.parseSourceCode(sourceCode)
      
      return {
        className,
        sourceCode,
        packageName,
        imports,
        methods,
        fields,
        isSuccess: true,
        decompileTime: Date.now() - startTime,
        cacheHit: false
      }
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
        decompileTime: Date.now() - startTime,
        cacheHit: false
      }
    }
  }
  
  private parseSourceCode(sourceCode: string): {
    packageName: string
    imports: string[]
    methods: MethodInfo[]
    fields: FieldInfo[]
  } {
    const lines = sourceCode.split('\n')
    
    let packageName = ''
    const imports: string[] = []
    const methods: MethodInfo[] = []
    const fields: FieldInfo[] = []
    
    let inClass = false
    let braceCount = 0
    
    for (const line of lines) {
      const trimmed = line.trim()
      
      // 解析 package
      if (trimmed.startsWith('package ')) {
        packageName = trimmed.replace('package ', '').replace(';', '').trim()
      }
      
      // 解析 import
      else if (trimmed.startsWith('import ')) {
        imports.push(trimmed.replace('import ', '').replace(';', '').trim())
      }
      
      // 检测类定义
      else if (trimmed.match(/^(public\s+)?(class|interface|enum)\s+\w+/)) {
        inClass = true
      }
      
      // 解析字段（简化版）
      else if (inClass && trimmed.match(/^(private|public|protected)\s+\w+\s+\w+\s*;/)) {
        const parts = trimmed.replace(';', '').split(/\s+/)
        if (parts.length >= 3) {
          fields.push({
            name: parts[parts.length - 1],
            type: parts[parts.length - 2],
            isPublic: parts.includes('public'),
            annotations: []
          })
        }
      }
      
      // 解析方法（简化版）
      else if (inClass && trimmed.match(/^(private|public|protected)\s+.*\(.*\)\s*\{/)) {
        const methodMatch = trimmed.match(/(\w+)\s*\(/)
        if (methodMatch) {
          methods.push({
            name: methodMatch[1],
            signature: trimmed.replace('{', '').trim(),
            parameters: [],
            returnType: 'void',
            isPublic: trimmed.includes('public'),
            annotations: [],
            body: '',
            linesOfCode: 0
          })
        }
      }
      
      // 计算大括号
      if (inClass) {
        braceCount += (trimmed.match(/{/g) || []).length
        braceCount -= (trimmed.match(/}/g) || []).length
        if (braceCount === 0 && trimmed === '}') {
          inClass = false
        }
      }
    }
    
    return { packageName, imports, methods, fields }
  }
}
