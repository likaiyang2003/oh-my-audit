import { describe, it, expect, beforeAll } from 'bun:test'
import { SSRFAgent } from './agent'
import type { AttackEntry } from '../../types'
import { VulnerabilityType } from '../../types'
import type { DecompileResult } from '../../tools/decompiler/types'

describe('SSRFAgent', () => {
  let agent: SSRFAgent
  
  beforeAll(() => {
    agent = new SSRFAgent()
  })
  
  it('#given URL.openConnection with user input #when audit is called #then should detect SSRF', async () => {
    const sourceCode = `
      public void fetchData(String url) {
        URL u = new URL(url);
        HttpURLConnection conn = (HttpURLConnection) u.openConnection();
        conn.setRequestMethod("GET");
        int responseCode = conn.getResponseCode();
      }
    `
    
    const entry: AttackEntry = {
      type: 'controller',
      className: 'FetchController',
      methodName: 'fetchData',
      urlPattern: '/api/fetch',
      httpMethods: ['POST'],
      parameters: [
        { name: 'url', type: 'String', source: 'body' }
      ],
      riskLevel: 'high'
    }
    
    const decompiledSources = new Map<string, DecompileResult>([[
      'FetchController',
      {
        className: 'FetchController',
        sourceCode,
        packageName: 'com.example',
        imports: ['java.net.*'],
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
    expect(vulnerabilities[0].type).toBe(VulnerabilityType.SSRF)
    expect(vulnerabilities[0].cwe).toBe('CWE-918')
  })
  
  it('#given HttpClient.execute with user controlled URL #when audit is called #then should detect SSRF', async () => {
    const sourceCode = `
      public void httpRequest(String targetUrl) {
        HttpClient client = HttpClient.newHttpClient();
        HttpRequest request = HttpRequest.newBuilder()
          .uri(URI.create(targetUrl))
          .build();
        HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());
      }
    `
    
    const entry: AttackEntry = {
      type: 'controller',
      className: 'HttpController',
      methodName: 'httpRequest',
      urlPattern: '/api/http-request',
      httpMethods: ['POST'],
      parameters: [
        { name: 'targetUrl', type: 'String', source: 'body' }
      ],
      riskLevel: 'high'
    }
    
    const decompiledSources = new Map<string, DecompileResult>([[
      'HttpController',
      {
        className: 'HttpController',
        sourceCode,
        packageName: 'com.example',
        imports: ['java.net.http.*'],
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
    expect(vulnerabilities[0].details.ssrfType).toBe('http_client')
  })
  
  it('#given RestTemplate with user input #when audit is called #then should detect SSRF', async () => {
    const sourceCode = `
      public void restCall(String apiEndpoint) {
        RestTemplate restTemplate = new RestTemplate();
        ResponseEntity<String> response = restTemplate.getForEntity(apiEndpoint, String.class);
        return response.getBody();
      }
    `
    
    const entry: AttackEntry = {
      type: 'controller',
      className: 'RestController',
      methodName: 'restCall',
      urlPattern: '/api/rest-call',
      httpMethods: ['GET'],
      parameters: [
        { name: 'apiEndpoint', type: 'String', source: 'query' }
      ],
      riskLevel: 'high'
    }
    
    const decompiledSources = new Map<string, DecompileResult>([[
      'RestController',
      {
        className: 'RestController',
        sourceCode,
        packageName: 'com.example',
        imports: ['org.springframework.web.client.*'],
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
  })
  
  it('#given URL with whitelist validation #when audit is called #then should not report false positive', async () => {
    const sourceCode = `
      public void safeFetch(String url) {
        // 验证 URL 在白名单中
        if (!url.startsWith("https://api.example.com/")) {
          throw new IllegalArgumentException("Invalid URL");
        }
        URL u = new URL(url);
        HttpURLConnection conn = (HttpURLConnection) u.openConnection();
        return conn.getResponseCode();
      }
    `
    
    const entry: AttackEntry = {
      type: 'controller',
      className: 'SafeController',
      methodName: 'safeFetch',
      urlPattern: '/api/safe-fetch',
      httpMethods: ['POST'],
      parameters: [
        { name: 'url', type: 'String', source: 'body' }
      ],
      riskLevel: 'medium'
    }
    
    const decompiledSources = new Map<string, DecompileResult>([[
      'SafeController',
      {
        className: 'SafeController',
        sourceCode,
        packageName: 'com.example',
        imports: ['java.net.*'],
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
    
    // 有白名单验证，不应该报告漏洞
    expect(vulnerabilities.length).toBe(0)
  })
})
