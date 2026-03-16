/**
 * Test Setup
 * 
 * Global test configuration and mocks.
 */

import { beforeAll, beforeEach, vi } from 'vitest';

// Set up environment variables for testing
beforeAll(() => {
  process.env.SESSION_SECRET = 'test-session-secret-for-testing-minimum-32-characters';
  process.env.NODE_ENV = 'test';
  process.env.DB_HOST = 'localhost';
  process.env.DB_PORT = '3306';
  process.env.DB_USER = 'test';
  process.env.DB_PASSWORD = 'test';
  process.env.DB_NAME = 'spacechild_auth_test';
});

// Clean up mocks before each test
beforeEach(() => {
  vi.clearAllMocks();
});