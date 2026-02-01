import type { Vulnerability } from '../../types'

export type SSRFType = 
  | 'url_connection'        // URL.openConnection()
  | 'http_client'           // HttpClient.execute()
  | 'rest_template'         // RestTemplate
  | 'apache_http_client'    // Apache HttpClient
  | 'okhttp'                // OkHttp
  | 'web_client'            // WebClient (Spring WebFlux)

type HTTPClientType = 'HttpURLConnection' | 'HttpClient' | 'RestTemplate' | 'ApacheHttpClient' | 'OkHttp' | 'WebClient' | 'Unknown'

export interface SSRFVulnerability extends Vulnerability {
  details: {
    ssrfType: SSRFType
    httpClient: HTTPClientType
    sinkMethod: string
    vulnerableParameter?: string
    urlConstruction?: string
    hasValidation: boolean
    validationType?: string
  }
  
  attackScenarios: {
    name: string
    description: string
    payload: string
    impact: string
  }[]
}

export interface SSRFRule {
  name: string
  description: string
  severity: 'critical' | 'high' | 'medium'
  patterns: RegExp[]
  ssrfType: SSRFType
  httpClient: HTTPClientType
  sinkMethods: string[]
  safeAlternative: string
}

export interface SSRFAnalyzerOptions {
  detectInternalIPs?: boolean
  detectMetadataEndpoints?: boolean
  detectFileProtocol?: boolean
  strictMode?: boolean
}
