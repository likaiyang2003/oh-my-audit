// Test setup file
// This file is loaded before each test file

import { beforeAll, afterAll } from 'bun:test'

beforeAll(() => {
  // Global test setup
  console.log('Starting tests...')
})

afterAll(() => {
  // Global test teardown
  console.log('Tests completed.')
})
