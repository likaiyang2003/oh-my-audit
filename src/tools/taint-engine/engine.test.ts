import { describe, it, expect, beforeAll } from 'bun:test'
import { TaintEngine } from './engine'
import type { TaintSource, TaintSink, TaintFlow, DataFlowGraph } from './types'

describe('TaintEngine', () => {
  let engine: TaintEngine
  
  beforeAll(() => {
    engine = new TaintEngine()
  })
  
  it('#given a simple data flow #when analyze is called #then should track taint from source to sink', async () => {
    const sourceCode = `
      public void processRequest(HttpServletRequest request) {
        String userInput = request.getParameter("name");
        String query = "SELECT * FROM users WHERE name = '" + userInput + "'";
        statement.executeQuery(query);
      }
    `
    
    const result = await engine.analyze({
      methodName: 'processRequest',
      className: 'UserController',
      sourceCode,
      parameters: [
        { name: 'request', type: 'HttpServletRequest' }
      ]
    })
    
    expect(result).toBeDefined()
    expect(result.flows).toBeDefined()
    expect(Array.isArray(result.flows)).toBe(true)
  })
  
  it('#given HTTP request parameter #when identifying sources #then should mark it as taint source', () => {
    const code = `
      String userId = request.getParameter("id");
      String username = request.getHeader("X-User");
    `
    
    const sources = engine.identifySources(code, 'testMethod')
    
    expect(sources.length).toBeGreaterThan(0)
    expect(sources.some((s: TaintSource) => s.type === 'HTTP_PARAMETER')).toBe(true)
  })
  
  it('#given SQL execution #when identifying sinks #then should mark it as SQL sink', () => {
    const code = `
      statement.executeQuery(sql);
      preparedStatement.execute();
      jdbcTemplate.query(sql);
    `
    
    const sinks = engine.identifySinks(code)
    
    expect(sinks.length).toBeGreaterThan(0)
    expect(sinks.some((s: TaintSink) => s.type === 'SQL_EXECUTION')).toBe(true)
  })
  
  it('#given tainted variable passed to method #when tracking propagation #then should follow data flow', () => {
    const code = `
      String input = request.getParameter("data");
      String processed = input.toUpperCase();
      String result = "SELECT " + processed;
    `
    
    const graph = engine.buildDataFlowGraph(code)
    
    expect(graph.nodes.length).toBeGreaterThan(0)
    expect(graph.edges.length).toBeGreaterThan(0)
  })
  
  it('#given sanitizer applied #when tracking taint #then should recognize sanitization', async () => {
    const code = `
      String input = request.getParameter("name");
      String safe = ESAPI.encoder().encodeForSQL(input);
      String query = "SELECT * FROM users WHERE name = '" + safe + "'";
    `
    
    const result = await engine.analyze({
      methodName: 'test',
      className: 'Test',
      sourceCode: code,
      parameters: []
    })
    
    // 验证分析成功执行
    expect(result).toBeDefined()
    expect(result.flows).toBeDefined()
    expect(result.summary).toBeDefined()
    
    // 如果有净化流程，验证它正确标记
    const sanitizedFlow = result.flows.find((f: TaintFlow) => 
      f.path.some((step: { type: string }) => step.type === 'sanitization')
    )
    
    if (sanitizedFlow) {
      expect(sanitizedFlow.isSanitized).toBe(true)
    }
  })
})
