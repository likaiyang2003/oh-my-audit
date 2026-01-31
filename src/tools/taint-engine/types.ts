// 污点源类型（用户可控输入）
export type SourceType = 
  | 'HTTP_PARAMETER'    // request.getParameter()
  | 'HTTP_HEADER'       // request.getHeader() 
  | 'HTTP_BODY'         // request.getInputStream()
  | 'PATH_VARIABLE'     // @PathVariable
  | 'QUERY_STRING'      // request.getQueryString()
  | 'COOKIE'            // request.getCookies()
  | 'FILE_UPLOAD'       // MultipartFile
  | 'EXTERNAL_API'      // 第三方 API 返回值
  | 'DATABASE'          // 数据库查询结果
  | 'USER_INPUT'        // 通用用户输入

// 污点汇聚点类型（危险操作）
export type SinkType =
  | 'SQL_EXECUTION'        // jdbc.execute()
  | 'COMMAND_EXECUTION'    // Runtime.exec()
  | 'URL_CONNECTION'       // URL.openConnection()
  | 'FILE_OPERATION'       // FileInputStream
  | 'RESPONSE_WRITE'       // response.getWriter()
  | 'XML_PARSE'            // DocumentBuilder.parse()
  | 'DESERIALIZATION'      // ObjectInputStream
  | 'REFLECTION'           // Class.forName()
  | 'SCRIPT_EXECUTION'     // ScriptEngine.eval()
  | 'EL_EVALUATION'        // ELProcessor.eval()

// 污点源
export interface TaintSource {
  type: SourceType
  variable: string
  location: SourceLocation
  method: string
  context?: string
}

// 污点汇聚点
export interface TaintSink {
  type: SinkType
  method: string
  location: SourceLocation
  arguments: string[]
  vulnerabilityType: string
  severity: 'critical' | 'high' | 'medium' | 'low'
}

// 代码位置
export interface SourceLocation {
  file?: string
  line: number
  column: number
  snippet: string
}

// 数据流节点
export interface DataFlowNode {
  id: string
  variable: string
  type: 'source' | 'intermediate' | 'sink' | 'sanitizer'
  location: SourceLocation
  value?: string
}

// 数据流边
export interface DataFlowEdge {
  from: string
  to: string
  type: 'assignment' | 'method_call' | 'return' | 'argument_passing'
  propagationRule?: PropagationRule
}

// 数据流图
export interface DataFlowGraph {
  nodes: DataFlowNode[]
  edges: DataFlowEdge[]
}

// 传播规则
export interface PropagationRule {
  from: string
  to: string
  through: string
  isSanitizer: boolean
  confidence: number
}

// 污点追踪步骤
export interface TaintStep {
  node: DataFlowNode
  type: 'source' | 'propagation' | 'transformation' | 'sanitization' | 'sink'
  from?: DataFlowNode
  to?: DataFlowNode
  code: string
  line: number
  confidence: number
}

// 污水流
export interface TaintFlow {
  id: string
  source: TaintSource
  sink?: TaintSink
  path: TaintStep[]
  reachesSink: boolean
  isSanitized: boolean
  vulnerabilityType?: string
  severity?: 'critical' | 'high' | 'medium' | 'low'
}

// 污点追踪结果
export interface TaintAnalysisResult {
  flows: TaintFlow[]
  summary: {
    totalSources: number
    totalSinks: number
    vulnerableFlows: number
    sanitizedFlows: number
  }
  graph: DataFlowGraph
}

// 污点追踪引擎接口
export interface ITaintEngine {
  analyze(context: AnalysisContext): Promise<TaintAnalysisResult>
  identifySources(sourceCode: string, methodName: string): TaintSource[]
  identifySinks(sourceCode: string): TaintSink[]
  buildDataFlowGraph(sourceCode: string): DataFlowGraph
}

// 分析方法参数
export interface AnalysisContext {
  methodName: string
  className: string
  sourceCode: string
  parameters: Array<{
    name: string
    type: string
  }>
  imports?: string[]
}
