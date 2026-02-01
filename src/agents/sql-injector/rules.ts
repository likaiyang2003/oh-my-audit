import type { SQLInjectionRule } from './types'

export const SQL_INJECTION_RULES: SQLInjectionRule[] = [
  // JDBC Statement 字符串拼接
  {
    name: 'JDBC Statement String Concatenation',
    description: '使用字符串拼接构建 SQL 查询，存在 SQL 注入风险',
    severity: 'critical',
    patterns: [
      /String\s+\w+\s*=\s*["'][^"']*["']\s*\+\s*\w+.*\+\s*["'][^"']*["']/g,
      /["']SELECT\s+.*FROM\s+\w+.*WHERE.*["']\s*\+\s*\w+/gi,
      /["']INSERT\s+INTO\s+\w+.*["']\s*\+\s*\w+/gi,
      /["']UPDATE\s+\w+.*SET.*["']\s*\+\s*\w+/gi,
      /["']DELETE\s+FROM\s+\w+.*["']\s*\+\s*\w+/gi,
    ],
    ormFramework: 'jdbc',
    injectionType: 'string_concatenation',
    safeAlternative: '使用 PreparedStatement 和参数绑定: stmt.setString(1, value)'
  },
  
  // StringBuilder 拼接 SQL
  {
    name: 'StringBuilder SQL Concatenation',
    description: '使用 StringBuilder 动态构建 SQL 查询',
    severity: 'critical',
    patterns: [
      /StringBuilder.*\.append\s*\(\s*["'][^"']*(?:SELECT|INSERT|UPDATE|DELETE)/gi,
      /new\s+StringBuilder\s*\(\s*["'][^"']*(?:SELECT|INSERT|UPDATE|DELETE)/gi,
      /\.append\s*\(\s*\w+\s*\).*executeQuery/g,
      /\.append\s*\(\s*\w+\s*\).*execute\s*\(/g,
    ],
    ormFramework: 'jdbc',
    injectionType: 'dynamic_query',
    safeAlternative: '使用 PreparedStatement 替代动态 SQL 构建'
  },
  
  // MyBatis ${} 占位符
  {
    name: 'MyBatis Dollar Placeholder',
    description: '使用 ${} 占位符直接拼接参数到 SQL 中',
    severity: 'critical',
    patterns: [
      /\$\{\s*\w+\s*\}/g,
      /@Select\s*\(\s*["'][^"']*\$\{/g,
      /@Insert\s*\(\s*["'][^"']*\$\{/g,
      /@Update\s*\(\s*["'][^"']*\$\{/g,
      /@Delete\s*\(\s*["'][^"']*\$\{/g,
    ],
    ormFramework: 'mybatis',
    injectionType: 'mybatis_dollar_placeholder',
    safeAlternative: '使用 #{} 占位符进行参数绑定: #{parameterName}'
  },
  
  // JPA Query 字符串拼接
  {
    name: 'JPA Query String Concatenation',
    description: '在 @Query 注解或 createQuery 中拼接字符串',
    severity: 'high',
    patterns: [
      /entityManager\.createQuery\s*\(\s*["'][^"']*["']\s*\+/gi,
      /@Query\s*\(\s*["'][^"']*["']\s*\+/g,
    ],
    ormFramework: 'jpa',
    injectionType: 'string_concatenation',
    safeAlternative: '使用具名参数: @Query("SELECT u FROM User u WHERE u.name = :name")'
  },
  
  // ORDER BY 注入（特殊场景）
  {
    name: 'ORDER BY Injection',
    description: '动态 ORDER BY 子章可能导致的注入',
    severity: 'medium',
    patterns: [
      /["']ORDER\s+BY\s+["']\s*\+\s*\w+/gi,
      /["']\s+ORDER\s+BY\s+\$\{/gi,
    ],
    ormFramework: 'unknown',
    injectionType: 'order_by_injection',
    safeAlternative: '使用白名单验证排序字段，或改用枚举类型'
  },
]

// SQL 执行方法签名
export const SQL_EXECUTION_SINKS = [
  'Statement.executeQuery',
  'Statement.execute',
  'Statement.executeUpdate',
  'PreparedStatement.executeQuery',
  'PreparedStatement.execute',
  'PreparedStatement.executeUpdate',
  'JdbcTemplate.query',
  'JdbcTemplate.execute',
  'JdbcTemplate.update',
  'entityManager.createQuery',
  'entityManager.createNativeQuery',
]

// 安全的数据库操作方法
export const SAFE_SQL_METHODS = [
  'PreparedStatement.setString',
  'PreparedStatement.setInt',
  'PreparedStatement.setLong',
  'PreparedStatement.setObject',
  'JdbcTemplate.query(String, Object[])',
  'NamedParameterJdbcTemplate',
]

// 检测是否使用了 PreparedStatement（安全）
export function usesPreparedStatement(sourceCode: string): boolean {
  // 检查是否使用了 ? 占位符
  const hasPlaceholder = /["'][^"']*\?[^"']*["']/.test(sourceCode)
  
  // 检查是否调用了 setString/setInt 等方法
  const hasSetMethods = /\.(setString|setInt|setLong|setObject)\s*\(/.test(sourceCode)
  
  // 检查是否使用了 NamedParameterJdbcTemplate
  const hasNamedParams = sourceCode.includes('NamedParameterJdbcTemplate')
  
  return hasPlaceholder && hasSetMethods || hasNamedParams
}
