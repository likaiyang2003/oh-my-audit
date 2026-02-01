import { describe, it, expect, beforeAll } from 'bun:test'
import { RCEAgent } from './agent'
import type { AttackEntry } from '../../types'
import { VulnerabilityType } from '../../types'
import type { DecompileResult } from '../../tools/decompiler/types'

describe('RCEAgent', () => {
  let agent: RCEAgent
  
  beforeAll(() => {
    agent = new RCEAgent()
  })
  
  it('#given Runtime.exec with user input #when audit is called #then should detect RCE', async () => {
    const sourceCode = `
      public void executeCommand(String userCmd) {
        Process process = Runtime.getRuntime().exec(userCmd);
        process.waitFor();
      }
    `
    
    const entry: AttackEntry = {
      type: 'controller',
      className: 'CommandController',
      methodName: 'executeCommand',
      urlPattern: '/api/execute',
      httpMethods: ['POST'],
      parameters: [
        { name: 'userCmd', type: 'String', source: 'body' }
      ],
      riskLevel: 'critical'
    }
    
    const decompiledSources = new Map<string, DecompileResult>([[
      'CommandController',
      {
        className: 'CommandController',
        sourceCode,
        packageName: 'com.example',
        imports: ['java.io.*'],
        methods: [],
        fields: [],
        isSuccess: true,
        decompileTime: 0,
        cacheHit: false
      }
    ]])
    
    const vulnerabilities = await agent.audit(
      'test.jar',
      [entry],
      decompiledSources
    )
    
    expect(vulnerabilities.length).toBeGreaterThan(0)
    expect(vulnerabilities[0].type).toBe(VulnerabilityType.RCE)
    expect(vulnerabilities[0].cwe).toBe('CWE-78')
  })
  
  it('#given ProcessBuilder with user controlled args #when audit is called #then should detect RCE', async () => {
    const sourceCode = `
      public void runProcess(String cmd, String arg) {
        ProcessBuilder pb = new ProcessBuilder(cmd, arg);
        Process process = pb.start();
        process.waitFor();
      }
    `
    
    const entry: AttackEntry = {
      type: 'controller',
      className: 'ProcessController',
      methodName: 'runProcess',
      urlPattern: '/api/run',
      httpMethods: ['POST'],
      parameters: [
        { name: 'cmd', type: 'String', source: 'body' },
        { name: 'arg', type: 'String', source: 'body' }
      ],
      riskLevel: 'critical'
    }
    
    const decompiledSources = new Map<string, DecompileResult>([[
      'ProcessController',
      {
        className: 'ProcessController',
        sourceCode,
        packageName: 'com.example',
        imports: ['java.lang.*'],
        methods: [],
        fields: [],
        isSuccess: true,
        decompileTime: 0,
        cacheHit: false
      }
    ]])
    
    const vulnerabilities = await agent.audit(
      'test.jar',
      [entry],
      decompiledSources
    )
    
    expect(vulnerabilities.length).toBeGreaterThan(0)
    expect(vulnerabilities[0].details.rceType).toBe('command_injection')
  })
  
  it('#given ScriptEngine.eval with user input #when audit is called #then should detect script injection', async () => {
    const sourceCode = `
      public void evalScript(String script) {
        ScriptEngineManager manager = new ScriptEngineManager();
        ScriptEngine engine = manager.getEngineByName("JavaScript");
        engine.eval(script);
      }
    `
    
    const entry: AttackEntry = {
      type: 'controller',
      className: 'ScriptController',
      methodName: 'evalScript',
      urlPattern: '/api/eval',
      httpMethods: ['POST'],
      parameters: [
        { name: 'script', type: 'String', source: 'body' }
      ],
      riskLevel: 'critical'
    }
    
    const decompiledSources = new Map<string, DecompileResult>([[
      'ScriptController',
      {
        className: 'ScriptController',
        sourceCode,
        packageName: 'com.example',
        imports: ['javax.script.*'],
        methods: [],
        fields: [],
        isSuccess: true,
        decompileTime: 0,
        cacheHit: false
      }
    ]])
    
    const vulnerabilities = await agent.audit(
      'test.jar',
      [entry],
      decompiledSources
    )
    
    expect(vulnerabilities.length).toBeGreaterThan(0)
    expect(vulnerabilities[0].details.rceType).toBe('script_injection')
  })
  
  it('#given ObjectInputStream.readObject with user controlled data #when audit is called #then should detect deserialization RCE', async () => {
    const sourceCode = `
      public void deserialize(byte[] data) {
        ByteArrayInputStream bis = new ByteArrayInputStream(data);
        ObjectInputStream ois = new ObjectInputStream(bis);
        Object obj = ois.readObject();
        ois.close();
      }
    `
    
    const entry: AttackEntry = {
      type: 'controller',
      className: 'DeserializationController',
      methodName: 'deserialize',
      urlPattern: '/api/deserialize',
      httpMethods: ['POST'],
      parameters: [
        { name: 'data', type: 'byte[]', source: 'body' }
      ],
      riskLevel: 'critical'
    }
    
    const decompiledSources = new Map<string, DecompileResult>([[
      'DeserializationController',
      {
        className: 'DeserializationController',
        sourceCode,
        packageName: 'com.example',
        imports: ['java.io.*'],
        methods: [],
        fields: [],
        isSuccess: true,
        decompileTime: 0,
        cacheHit: false
      }
    ]])
    
    const vulnerabilities = await agent.audit(
      'test.jar',
      [entry],
      decompiledSources
    )
    
    expect(vulnerabilities.length).toBeGreaterThan(0)
    expect(vulnerabilities[0].details.rceType).toBe('deserialization_rce')
  })
})
