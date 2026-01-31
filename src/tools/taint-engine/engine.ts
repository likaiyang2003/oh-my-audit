import type {
  ITaintEngine,
  TaintSource,
  TaintSink,
  TaintFlow,
  TaintStep,
  TaintAnalysisResult,
  DataFlowGraph,
  DataFlowNode,
  DataFlowEdge,
  PropagationRule,
  SourceLocation,
  AnalysisContext
} from './types'

// 默认传播规则
const DEFAULT_PROPAGATION_RULES: PropagationRule[] = [
  // String 操作 - 传播污点
  { from: '$a', to: '$result', through: 'String.concat', isSanitizer: false, confidence: 1.0 },
  { from: '$a', to: '$result', through: 'StringBuilder.append', isSanitizer: false, confidence: 1.0 },
  { from: '$a', to: '$result', through: 'String.format', isSanitizer: false, confidence: 1.0 },
  { from: '$a', to: '$result', through: 'String.replace', isSanitizer: false, confidence: 1.0 },
  
  // 净化操作
  { from: '$a', to: '$result', through: 'ESAPI.encoder.encodeForSQL', isSanitizer: true, confidence: 0.95 },
  { from: '$a', to: '$result', through: 'PreparedStatement.setString', isSanitizer: true, confidence: 0.90 },
  { from: '$a', to: '$result', through: 'HtmlUtils.htmlEscape', isSanitizer: true, confidence: 0.85 },
  
  // 集合操作
  { from: '$list', to: '$element', through: 'List.get', isSanitizer: false, confidence: 1.0 },
  { from: '$element', to: '$list', through: 'List.add', isSanitizer: false, confidence: 1.0 },
  
  // Map 操作
  { from: '$map', to: '$value', through: 'Map.get', isSanitizer: false, confidence: 1.0 },
]

// 污点源识别模式
const SOURCE_PATTERNS: Array<{ type: string; pattern: RegExp; extractor: (match: RegExpMatchArray) => Partial<TaintSource> }> = [
  {
    type: 'HTTP_PARAMETER',
    pattern: /request\.getParameter\s*\(\s*["']([^"']+)["']\s*\)/g,
    extractor: (match) => ({ type: 'HTTP_PARAMETER', context: match[1] })
  },
  {
    type: 'HTTP_HEADER',
    pattern: /request\.getHeader\s*\(\s*["']([^"']+)["']\s*\)/g,
    extractor: (match) => ({ type: 'HTTP_HEADER', context: match[1] })
  },
  {
    type: 'PATH_VARIABLE',
    pattern: /@PathVariable\s*\(?\s*["']?([^"']*)["']?\s*\)?\s*(\w+)\s+(\w+)/g,
    extractor: (match) => ({ type: 'PATH_VARIABLE', variable: match[3], context: match[1] || match[3] })
  },
  {
    type: 'REQUEST_BODY',
    pattern: /@RequestBody\s*(\w+)\s+(\w+)/g,
    extractor: (match) => ({ type: 'HTTP_BODY', variable: match[2] })
  }
]

// Sink 识别模式
const SINK_PATTERNS: Array<{ type: string; vulnerabilityType: string; severity: 'critical' | 'high' | 'medium' | 'low'; pattern: RegExp }> = [
  {
    type: 'SQL_EXECUTION',
    vulnerabilityType: 'SQL_INJECTION',
    severity: 'critical',
    pattern: /(statement|preparedStatement|jdbcTemplate)\.(executeQuery|execute|query|update)\s*\(/g
  },
  {
    type: 'COMMAND_EXECUTION',
    vulnerabilityType: 'RCE',
    severity: 'critical',
    pattern: /Runtime\.getRuntime\(\)\.exec\s*\(/g
  },
  {
    type: 'URL_CONNECTION',
    vulnerabilityType: 'SSRF',
    severity: 'high',
    pattern: /(new\s+URL\s*\(|openConnection\s*\(|httpClient\.execute)/g
  },
  {
    type: 'XML_PARSE',
    vulnerabilityType: 'XXE',
    severity: 'high',
    pattern: /(DocumentBuilder|SAXParser|XMLReader)\.parse\s*\(/g
  },
  {
    type: 'DESERIALIZATION',
    vulnerabilityType: 'RCE',
    severity: 'critical',
    pattern: /ObjectInputStream.*\.readObject\s*\(/g
  }
]

export class TaintEngine implements ITaintEngine {
  private propagationRules: PropagationRule[]
  private maxDepth: number
  
  constructor(rules: PropagationRule[] = DEFAULT_PROPAGATION_RULES, maxDepth = 50) {
    this.propagationRules = rules
    this.maxDepth = maxDepth
  }
  
  async analyze(context: AnalysisContext): Promise<TaintAnalysisResult> {
    const { methodName, className, sourceCode, parameters } = context
    
    // 1. 构建数据流图
    const graph = this.buildDataFlowGraph(sourceCode)
    
    // 2. 识别所有污点源
    const sources = this.identifySources(sourceCode, methodName)
    
    // 3. 识别所有汇聚点
    const sinks = this.identifySinks(sourceCode)
    
    // 4. 追踪每个源的污点流向
    const flows: TaintFlow[] = []
    
    for (const source of sources) {
      const flow = this.trackTaint(source, graph, sinks)
      if (flow.path.length > 0) {
        flows.push(flow)
      }
    }
    
    return {
      flows,
      summary: {
        totalSources: sources.length,
        totalSinks: sinks.length,
        vulnerableFlows: flows.filter(f => f.reachesSink && !f.isSanitized).length,
        sanitizedFlows: flows.filter(f => f.isSanitized).length
      },
      graph
    }
  }
  
  identifySources(sourceCode: string, methodName: string): TaintSource[] {
    const sources: TaintSource[] = []
    const lines = sourceCode.split('\n')
    
    for (let i = 0; i < lines.length; i++) {
      const line = lines[i]
      
      for (const { type, pattern, extractor } of SOURCE_PATTERNS) {
        const matches = Array.from(line.matchAll(pattern))
        
        for (const match of matches) {
          const extracted = extractor(match)
          const variable = this.extractVariableName(line, match.index || 0)
          
          sources.push({
            type: type as any,
            variable: extracted.variable || variable || 'unknown',
            location: {
              line: i + 1,
              column: (match.index || 0) + 1,
              snippet: line.trim()
            },
            method: methodName,
            context: extracted.context
          })
        }
      }
    }
    
    return sources
  }
  
  identifySinks(sourceCode: string): TaintSink[] {
    const sinks: TaintSink[] = []
    const lines = sourceCode.split('\n')
    
    for (let i = 0; i < lines.length; i++) {
      const line = lines[i]
      
      for (const { type, vulnerabilityType, severity, pattern } of SINK_PATTERNS) {
        const matches = Array.from(line.matchAll(pattern))
        
        for (const match of matches) {
          const arguments_ = this.extractArguments(line, match.index || 0)
          
          sinks.push({
            type: type as any,
            method: this.extractMethodCall(line, match.index || 0),
            location: {
              line: i + 1,
              column: (match.index || 0) + 1,
              snippet: line.trim()
            },
            arguments: arguments_,
            vulnerabilityType,
            severity
          })
        }
      }
    }
    
    return sinks
  }
  
  buildDataFlowGraph(sourceCode: string): DataFlowGraph {
    const nodes: DataFlowNode[] = []
    const edges: DataFlowEdge[] = []
    const lines = sourceCode.split('\n')
    
    let nodeId = 0
    const variableMap = new Map<string, string>()
    
    for (let i = 0; i < lines.length; i++) {
      const line = lines[i].trim()
      
      // 检测变量赋值
      const assignmentMatch = line.match(/(\w+)\s*=\s*(.+);?$/)
      if (assignmentMatch) {
        const targetVar = assignmentMatch[1]
        const expression = assignmentMatch[2]
        
        const nodeId_str = `node_${nodeId++}`
        nodes.push({
          id: nodeId_str,
          variable: targetVar,
          type: 'intermediate',
          location: { line: i + 1, column: 1, snippet: line }
        })
        
        variableMap.set(targetVar, nodeId_str)
        
        // 检测表达式中的源变量
        const sourceVars = this.extractVariables(expression)
        for (const sourceVar of sourceVars) {
          const sourceNodeId = variableMap.get(sourceVar)
          if (sourceNodeId) {
            edges.push({
              from: sourceNodeId,
              to: nodeId_str,
              type: 'assignment'
            })
          }
        }
      }
      
      // 检测方法调用
      const methodCallMatch = line.match(/(\w+)\.(\w+)\s*\(([^)]*)\)/)
      if (methodCallMatch) {
        const objectVar = methodCallMatch[1]
        const methodName = methodCallMatch[2]
        const args = methodCallMatch[3]
        
        // 添加方法调用边
        const argVars = this.extractVariables(args)
        for (const argVar of argVars) {
          const argNodeId = variableMap.get(argVar)
          if (argNodeId) {
            edges.push({
              from: argNodeId,
              to: `method_${methodName}`,
              type: 'argument_passing'
            })
          }
        }
      }
    }
    
    return { nodes, edges }
  }
  
  private trackTaint(source: TaintSource, graph: DataFlowGraph, sinks: TaintSink[]): TaintFlow {
    const visited = new Set<string>()
    const path: TaintStep[] = []
    let reachesSink = false
    let isSanitized = false
    let sink: TaintSink | undefined
    
    // 找到源节点
    const sourceNode = graph.nodes.find(n => n.variable === source.variable)
    if (!sourceNode) {
      return {
        id: `flow_${Date.now()}`,
        source,
        path: [],
        reachesSink: false,
        isSanitized: false
      }
    }
    
    // DFS 追踪
    const dfs = (node: DataFlowNode, depth: number = 0): boolean => {
      if (depth > this.maxDepth) return false
      if (visited.has(node.id)) return false
      visited.add(node.id)
      
      // 记录步骤
      path.push({
        node,
        type: depth === 0 ? 'source' : 'propagation',
        code: node.location.snippet,
        line: node.location.line,
        confidence: 1.0
      })
      
      // 检查是否是汇聚点
      const matchedSink = sinks.find(s => 
        s.location.line === node.location.line
      )
      
      if (matchedSink) {
        reachesSink = true
        sink = matchedSink
        path[path.length - 1].type = 'sink'
        return true
      }
      
      // 检查是否经过净化
      const sanitizerRule = this.propagationRules.find(r => 
        r.isSanitizer && node.location.snippet.includes(r.through)
      )
      
      if (sanitizerRule) {
        isSanitized = true
        path[path.length - 1].type = 'sanitization'
      }
      
      // 继续追踪
      const outgoingEdges = graph.edges.filter(e => e.from === node.id)
      for (const edge of outgoingEdges) {
        const nextNode = graph.nodes.find(n => n.id === edge.to)
        if (nextNode && dfs(nextNode, depth + 1)) {
          return true
        }
      }
      
      // 回溯
      path.pop()
      visited.delete(node.id)
      return false
    }
    
    dfs(sourceNode)
    
    return {
      id: `flow_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`,
      source,
      sink,
      path,
      reachesSink,
      isSanitized,
      vulnerabilityType: sink?.vulnerabilityType,
      severity: sink?.severity
    }
  }
  
  private extractVariableName(line: string, position: number): string | null {
    // 提取赋值左侧的变量名
    const beforeMatch = line.substring(0, position)
    const varMatch = beforeMatch.match(/(\w+)\s*=\s*$/)
    return varMatch ? varMatch[1] : null
  }
  
  private extractArguments(line: string, position: number): string[] {
    // 从方法调用中提取参数
    const afterMatch = line.substring(position)
    const argsMatch = afterMatch.match(/\(([^)]*)\)/)
    if (argsMatch) {
      return argsMatch[1].split(',').map(a => a.trim()).filter(a => a)
    }
    return []
  }
  
  private extractMethodCall(line: string, position: number): string {
    // 提取方法调用字符串
    const afterMatch = line.substring(position)
    const methodMatch = afterMatch.match(/(\w+(?:\.\w+)*)\s*\(/)
    return methodMatch ? methodMatch[1] : 'unknown'
  }
  
  private extractVariables(expression: string): string[] {
    // 从表达式中提取变量名（简化版）
    const varPattern = /\b([a-zA-Z_]\w*)\b/g
    const matches = Array.from(expression.matchAll(varPattern))
    return matches.map(m => m[1]).filter(v => 
      !['String', 'int', 'boolean', 'new', 'return', 'if', 'for', 'while'].includes(v)
    )
  }
}
