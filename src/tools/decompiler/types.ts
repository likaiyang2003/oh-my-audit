export interface DecompileOptions {
  includeLineNumbers?: boolean
  includeImports?: boolean
  timeout?: number
}

export interface DecompileResult {
  className: string
  sourceCode: string
  packageName: string
  imports: string[]
  methods: MethodInfo[]
  fields: FieldInfo[]
  isSuccess: boolean
  error?: string
  decompileTime: number
  cacheHit: boolean
}

export interface MethodInfo {
  name: string
  signature: string
  parameters: ParameterInfo[]
  returnType: string
  isPublic: boolean
  annotations: string[]
  body: string
  linesOfCode: number
}

export interface FieldInfo {
  name: string
  type: string
  isPublic: boolean
  annotations: string[]
}

export interface ParameterInfo {
  name: string
  type: string
}

export interface DecompilerEngine {
  decompile(classFile: Buffer, className: string, options?: DecompileOptions): Promise<DecompileResult>
}
