export interface JarManifest {
  mainClass?: string
  version?: string
  implementationTitle?: string
  implementationVersion?: string
}

export interface DetectedFramework {
  type: 'spring-boot' | 'spring-mvc' | 'struts2' | 'servlet' | 'unknown'
  version?: string
  indicators: string[]
}

export interface AttackEntry {
  type: 'servlet' | 'controller' | 'listener' | 'filter' | 'websocket'
  className: string
  methodName: string
  urlPattern?: string
  httpMethods: string[]
  parameters: ParameterInfo[]
  riskLevel: 'critical' | 'high' | 'medium' | 'low'
}

export interface ParameterInfo {
  name: string
  type: string
  annotation?: string
  source: 'query' | 'path' | 'body' | 'header' | 'cookie' | 'form'
}

export interface Dependency {
  groupId: string
  artifactId: string
  version: string
  isVulnerable: boolean
  knownVulnerabilities?: string[]
}

export interface ConfigFile {
  path: string
  type: 'xml' | 'yaml' | 'properties'
  content: string
}

export interface JarAnalysisResult {
  manifest: JarManifest
  framework: DetectedFramework
  entryPoints: AttackEntry[]
  dependencies: Dependency[]
  configFiles: ConfigFile[]
  riskScore: number
}

export enum Severity {
  CRITICAL = 'critical',
  HIGH = 'high',
  MEDIUM = 'medium',
  LOW = 'low'
}

export enum VulnerabilityType {
  SQL_INJECTION = 'SQL_INJECTION',
  SSRF = 'SSRF',
  RCE = 'RCE',
  XSS = 'XSS',
  XXE = 'XXE',
  AUTH_BYPASS = 'AUTH_BYPASS',
  IDOR = 'IDOR',
  HARDCODED_CREDENTIALS = 'HARDCODED_CREDENTIALS',
  BUSINESS_LOGIC = 'BUSINESS_LOGIC',
  JWT_NONE_ALGORITHM = 'JWT_NONE_ALGORITHM',
  JWT_WEAK_SECRET = 'JWT_WEAK_SECRET'
}

export interface Vulnerability {
  id: string
  type: VulnerabilityType
  cwe: string
  owasp: string
  severity: Severity
  title: string
  description: string
  location: {
    className: string
    methodName: string
    lineNumber: number
    codeSnippet: string
  }
  evidence: {
    sourceFlow?: string[]
    sinkFlow?: string[]
  }
  remediation: {
    description: string
    codeExample?: string
    references: string[]
  }
}
