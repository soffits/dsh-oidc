import { defineConfig } from 'vitest/config'

export default defineConfig({
  test: {
    include: ['tests/gateway.acceptance.ts'],
    testTimeout: 90_000,
    hookTimeout: 150_000,
    teardownTimeout: 30_000,
    fileParallelism: false,
  },
})
