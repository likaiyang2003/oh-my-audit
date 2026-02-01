#!/usr/bin/env bun
/**
 * Final Check Script
 * Automated verification before release
 */

import { $ } from 'bun'
import { readdir, readFile, stat } from 'node:fs/promises'
import { join, resolve } from 'node:path'

const CHECKS = {
  passed: 0,
  failed: 0,
  warnings: 0,
}

function log(message: string): void {
  console.log(message)
}

function success(message: string): void {
  console.log(`  ✅ ${message}`)
  CHECKS.passed++
}

function fail(message: string): void {
  console.log(`  ❌ ${message}`)
  CHECKS.failed++
}

function warn(message: string): void {
  console.log(`  ⚠️  ${message}`)
  CHECKS.warnings++
}

async function runCheck(name: string, checkFn: () => Promise<void>): Promise<void> {
  log(`\n${name}`)
  try {
    await checkFn()
  } catch (error) {
    fail(`Check failed: ${error instanceof Error ? error.message : String(error)}`)
  }
}

// Check 1: All tests pass
async function checkTests(): Promise<void> {
  try {
    const result = await $`bun test`.quiet()
    if (result.exitCode === 0) {
      success('All tests pass')
    } else {
      fail('Some tests failed')
    }
  } catch {
    fail('Test command failed')
  }
}

// Check 2: TypeScript compiles
async function checkTypeScript(): Promise<void> {
  try {
    const result = await $`bun run typecheck`.quiet()
    if (result.exitCode === 0) {
      success('TypeScript compiles without errors')
    } else {
      fail('TypeScript compilation failed')
    }
  } catch {
    fail('Typecheck command failed')
  }
}

// Check 3: No @types/node dependencies
async function checkNoNodeTypes(): Promise<void> {
  const packageJson = await readFile('package.json', 'utf-8')
  const pkg = JSON.parse(packageJson)
  
  const allDeps = {
    ...pkg.dependencies,
    ...pkg.devDependencies
  }
  
  const hasNodeTypes = Object.keys(allDeps).some(dep => 
    dep.includes('@types/node')
  )
  
  if (hasNodeTypes) {
    fail('Found @types/node in dependencies - should use bun-types only')
  } else {
    success('No @types/node dependencies found')
  }
}

// Check 4: All barrel exports exist
async function checkBarrelExports(): Promise<void> {
  const expectedBarrels = [
    'src/types/index.ts',
    'src/tools/jar-analyzer/index.ts',
    'src/tools/decompiler/index.ts',
    'src/tools/taint-engine/index.ts',
    'src/agents/sql-injector/index.ts',
    'src/agents/ssrf-hunter/index.ts',
    'src/agents/sentry/index.ts',
    'src/hooks/report-generator/index.ts'
  ]
  
  let allExist = true
  for (const barrel of expectedBarrels) {
    try {
      await stat(barrel)
    } catch {
      fail(`Missing barrel export: ${barrel}`)
      allExist = false
    }
  }
  
  if (allExist) {
    success('All expected barrel exports exist')
  }
}

// Check 5: No TODO/FIXME comments in code
async function checkNoTodos(): Promise<void> {
  try {
    const result = await $`grep -r "TODO\|FIXME" src/ --include="*.ts"`.quiet()
    if (result.exitCode === 0 && result.stdout.toString().trim()) {
      const todos = result.stdout.toString().trim().split('\n').length
      warn(`Found ${todos} TODO/FIXME comments in source code`)
    } else {
      success('No TODO/FIXME comments found in source code')
    }
  } catch {
    success('No TODO/FIXME comments found in source code')
  }
}

// Check 6: Calculate test coverage (approximate)
async function checkTestCoverage(): Promise<void> {
  const srcFiles: string[] = []
  const testFiles: string[] = []
  
  async function scanDir(dir: string): Promise<void> {
    const entries = await readdir(dir, { withFileTypes: true })
    for (const entry of entries) {
      const path = join(dir, entry.name)
      if (entry.isDirectory()) {
        await scanDir(path)
      } else if (entry.name.endsWith('.ts')) {
        if (entry.name.endsWith('.test.ts')) {
          testFiles.push(path)
        } else if (!entry.name.endsWith('.d.ts')) {
          srcFiles.push(path)
        }
      }
    }
  }
  
  await scanDir('src')
  
  const coverage = srcFiles.length > 0 
    ? Math.round((testFiles.length / srcFiles.length) * 100)
    : 0
  
  if (coverage >= 70) {
    success(`Test coverage: ${coverage}% (${testFiles.length}/${srcFiles.length} files have tests)`)
  } else if (coverage >= 50) {
    warn(`Test coverage: ${coverage}% - consider adding more tests`)
  } else {
    fail(`Test coverage: ${coverage}% - need more tests`)
  }
}

// Check 7: File naming conventions
async function checkNamingConventions(): Promise<void> {
  const issues: string[] = []
  
  async function scanDir(dir: string): Promise<void> {
    const entries = await readdir(dir, { withFileTypes: true })
    for (const entry of entries) {
      const path = join(dir, entry.name)
      if (entry.isDirectory()) {
        // Check directory: kebab-case
        if (!/^[a-z0-9]+(-[a-z0-9]+)*$/.test(entry.name)) {
          issues.push(`Directory not kebab-case: ${path}`)
        }
        await scanDir(path)
      } else if (entry.name.endsWith('.ts') && !entry.name.endsWith('.d.ts')) {
        // Check file: kebab-case
        if (!/^[a-z0-9]+(-[a-z0-9]+)*\.ts$/.test(entry.name)) {
          issues.push(`File not kebab-case: ${path}`)
        }
      }
    }
  }
  
  await scanDir('src')
  
  if (issues.length === 0) {
    success('All files follow kebab-case naming convention')
  } else {
    for (const issue of issues) {
      fail(issue)
    }
  }
}

// Check 8: Verify documentation exists
async function checkDocumentation(): Promise<void> {
  const requiredDocs = [
    'README.md',
    'CHANGELOG.md',
    'LICENSE',
    'docs/ARCHITECTURE.md'
  ]
  
  let allExist = true
  for (const doc of requiredDocs) {
    try {
      await stat(doc)
    } catch {
      warn(`Missing documentation: ${doc}`)
      allExist = false
    }
  }
  
  if (allExist) {
    success('All required documentation exists')
  }
}

// Check 9: Verify package.json metadata
async function checkPackageMetadata(): Promise<void> {
  const packageJson = await readFile('package.json', 'utf-8')
  const pkg = JSON.parse(packageJson)
  
  const required = ['name', 'version', 'description', 'main', 'types', 'license']
  const optional = ['repository', 'bugs', 'keywords', 'author']
  
  let allRequired = true
  for (const field of required) {
    if (!pkg[field]) {
      fail(`Missing required field in package.json: ${field}`)
      allRequired = false
    }
  }
  
  for (const field of optional) {
    if (!pkg[field]) {
      warn(`Missing optional field in package.json: ${field}`)
    }
  }
  
  if (allRequired) {
    success('Package.json has all required metadata')
  }
}

// Check 10: Verify build succeeds
async function checkBuild(): Promise<void> {
  try {
    const result = await $`bun run build`.quiet()
    if (result.exitCode === 0) {
      success('Build succeeds')
    } else {
      fail('Build failed')
    }
  } catch {
    fail('Build command failed')
  }
}

// Main
async function main(): Promise<void> {
  log('🔍 Running Final Release Checks\n')
  log('=' .repeat(50))
  
  await runCheck('1. Test Suite', checkTests)
  await runCheck('2. TypeScript Compilation', checkTypeScript)
  await runCheck('3. Dependencies (@types/node check)', checkNoNodeTypes)
  await runCheck('4. Barrel Exports', checkBarrelExports)
  await runCheck('5. TODO/FIXME Comments', checkNoTodos)
  await runCheck('6. Test Coverage', checkTestCoverage)
  await runCheck('7. Naming Conventions', checkNamingConventions)
  await runCheck('8. Documentation', checkDocumentation)
  await runCheck('9. Package Metadata', checkPackageMetadata)
  await runCheck('10. Build Verification', checkBuild)
  
  log('\n' + '='.repeat(50))
  log('\n📊 Summary:')
  log(`  ✅ Passed: ${CHECKS.passed}`)
  log(`  ❌ Failed: ${CHECKS.failed}`)
  log(`  ⚠️  Warnings: ${CHECKS.warnings}`)
  
  if (CHECKS.failed === 0) {
    log('\n🎉 All critical checks passed! Ready for release.')
    process.exit(0)
  } else {
    log(`\n❌ ${CHECKS.failed} check(s) failed. Fix before release.`)
    process.exit(1)
  }
}

main().catch(console.error)
