// 手动测试演示
import { JarAnalyzer } from './src/tools/jar-analyzer/index'
import { SQLInjectionAgent } from './src/agents/sql-injector/index'
import type { AttackEntry } from './src/types/index'
import type { DecompileResult } from './src/tools/decompiler/types'

async function testScan() {
  console.log('=== 代码安全审计测试 ===\n')
  
  // 1. 模拟 JAR 分析结果
  const mockEntry: AttackEntry = {
    type: 'controller',
    className: 'UserController',
    methodName: 'searchUsers',
    urlPattern: '/api/users/search',
    httpMethods: ['GET'],
    parameters: [
      { name: 'name', type: 'String', source: 'query' }
    ],
    riskLevel: 'high'
  }
  
  // 2. 模拟反编译源码（包含 SQL 注入漏洞）
  const vulnerableCode = `
    @RestController
    public class UserController {
      @Autowired
      private JdbcTemplate jdbcTemplate;
      
      @GetMapping("/api/users/search")
      public List<User> searchUsers(@RequestParam String name) {
        // 危险代码：字符串拼接 SQL
        String sql = "SELECT * FROM users WHERE name = '" + name + "'";
        return jdbcTemplate.query(sql, new UserRowMapper());
      }
    }
  `
  
  const decompiledSources = new Map<string, DecompileResult>([[
    'UserController',
    {
      className: 'UserController',
      sourceCode: vulnerableCode,
      packageName: 'com.example.controller',
      imports: ['org.springframework.web.bind.annotation.*', 'org.springframework.jdbc.core.*'],
      methods: [],
      fields: [],
      isSuccess: true,
      decompileTime: 0,
      cacheHit: false
    }
  ]])
  
  // 3. 运行 SQL 注入检测
  console.log('🔍 正在检测 SQL 注入漏洞...')
  const sqlAgent = new SQLInjectionAgent()
  const sqlVulns = await sqlAgent.audit(
    'test-application.jar',
    [mockEntry],
    decompiledSources
  )
  
  if (sqlVulns.length > 0) {
    console.log(`\n⚠️  发现 ${sqlVulns.length} 个 SQL 注入漏洞！\n`)
    
    for (const vuln of sqlVulns) {
      console.log(`漏洞 ID: ${vuln.id}`)
      console.log(`标题: ${vuln.title}`)
      console.log(`严重级别: ${vuln.severity}`)
      console.log(`位置: ${vuln.location.className}:${vuln.location.lineNumber}`)
      console.log(`代码片段: ${vuln.location.codeSnippet}`)
      console.log(`\n修复建议:`)
      console.log(vuln.remediation.description)
      console.log(`\n安全代码示例:`)
      console.log(vuln.remediation.codeExample)
      console.log('\n---\n')
    }
  } else {
    console.log('✅ 未发现 SQL 注入漏洞')
  }
}

// 运行测试
testScan().catch(console.error)
