#!/usr/bin/env bun
/**
 * Version Bump Script
 * Bumps version and creates git tag
 * 
 * Usage: bun run scripts/bump-version.ts [patch|minor|major]
 */

import { $ } from 'bun'
import { readFile, writeFile } from 'node:fs/promises'

type BumpType = 'patch' | 'minor' | 'major'

function bumpVersion(version: string, type: BumpType): string {
  const parts = version.split('.').map(Number)
  
  switch (type) {
    case 'major':
      return `${parts[0] + 1}.0.0`
    case 'minor':
      return `${parts[0]}.${parts[1] + 1}.0`
    case 'patch':
      return `${parts[0]}.${parts[1]}.${parts[2] + 1}`
    default:
      throw new Error(`Unknown bump type: ${type}`)
  }
}

async function main(): Promise<void> {
  const bumpType = (process.argv[2] || 'patch') as BumpType
  
  if (!['patch', 'minor', 'major'].includes(bumpType)) {
    console.error('Usage: bun run scripts/bump-version.ts [patch|minor|major]')
    process.exit(1)
  }
  
  // Read current version
  const packageJsonContent = await readFile('package.json', 'utf-8')
  const packageJson = JSON.parse(packageJsonContent)
  const currentVersion = packageJson.version
  
  console.log(`Current version: ${currentVersion}`)
  console.log(`Bump type: ${bumpType}`)
  
  // Calculate new version
  const newVersion = bumpVersion(currentVersion, bumpType)
  console.log(`New version: ${newVersion}`)
  
  // Update package.json
  packageJson.version = newVersion
  await writeFile('package.json', JSON.stringify(packageJson, null, 2) + '\n')
  console.log('✅ Updated package.json')
  
  // Update package-lock.json if exists
  try {
    const lockContent = await readFile('bun.lock', 'utf-8')
    // bun.lock format is binary, skip
  } catch {
    // No lock file, skip
  }
  
  // Stage changes
  await $`git add package.json`
  
  // Commit
  await $`git commit -m "chore(release): bump version to ${newVersion}"`
  console.log('✅ Created commit')
  
  // Create tag
  await $`git tag -a v${newVersion} -m "Release v${newVersion}"`
  console.log(`✅ Created tag v${newVersion}`)
  
  console.log('\n🎉 Version bumped successfully!')
  console.log(`To push: git push && git push origin v${newVersion}`)
}

main().catch((error) => {
  console.error('Error:', error)
  process.exit(1)
})
