/**
 * Vitest Configuration
 * 
 * Configuration for running tests with TypeScript support.
 */

import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    globals: true,
    environment: 'node',
    include: ['tests/**/*.test.ts'],
    exclude: ['node_modules', 'dist'],
    testTimeout: 10000,
    hookTimeout: 10000,
    teardownTimeout: 5000,
    // Mock process.env for testing
    setupFiles: ['./tests/setup.ts'],
  },
  esbuild: {
    target: 'node18',
  },
});