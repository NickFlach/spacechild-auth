/**
 * Database Connection
 * 
 * MySQL connection pool for Dolt database.
 * Dolt is MySQL-compatible, so we use mysql2 driver.
 * 
 * IMPORTANT: Dolt requires @@dolt_transaction_commit = 1 per connection,
 * otherwise writes go to the working set but never get committed to the branch.
 */

import mysql from 'mysql2/promise';
import type { Pool, PoolConnection } from 'mysql2/promise';

const DB_HOST = process.env.DB_HOST || '127.0.0.1';
const DB_PORT = parseInt(process.env.DB_PORT || '3306');
const DB_USER = process.env.DB_USER || 'root';
const DB_PASSWORD = process.env.DB_PASSWORD || '';
const DB_NAME = process.env.DB_NAME || 'spacechild_auth';

// Create connection pool
const rawPool = mysql.createPool({
  host: DB_HOST,
  port: DB_PORT,
  user: DB_USER,
  password: DB_PASSWORD,
  database: DB_NAME,
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0,
  // Enable multiple statements for schema migrations
  multipleStatements: true,
  // Ensure proper timezone handling
  timezone: 'Z',
  dateStrings: false,
  typeCast: (field, next) => {
    // Convert TINYINT(1) to boolean
    if (field.type === 'TINY' && field.length === 1) {
      return field.string() === '1';
    }
    return next();
  }
});

// Wrap pool.execute to ensure Dolt transaction commit is enabled
// This is critical: without it, Dolt accepts writes but never persists them
const originalExecute = rawPool.execute.bind(rawPool);
const originalQuery = rawPool.query.bind(rawPool);

const doltInitSql = 'SET @@autocommit = 1, @@dolt_transaction_commit = 1';
const initializedConnections = new WeakSet<PoolConnection>();

async function getInitializedConnection(): Promise<PoolConnection> {
  const conn = await rawPool.getConnection();
  if (!initializedConnections.has(conn)) {
    await conn.query(doltInitSql);
    initializedConnections.add(conn);
  }
  return conn;
}

// Override execute to use initialized connections
rawPool.execute = (async function (sql: any, values?: any) {
  const conn = await getInitializedConnection();
  try {
    return await conn.execute(sql, values);
  } finally {
    conn.release();
  }
}) as any;

// Override query too (used by migrations)
const origPoolQuery = rawPool.query.bind(rawPool);
rawPool.query = (async function (sql: any, values?: any) {
  // For migration multi-statements, use raw query (no dolt commit needed for DDL)
  if (typeof sql === 'string' && (sql.includes('CREATE TABLE') || sql.includes('ALTER TABLE'))) {
    return origPoolQuery(sql, values);
  }
  const conn = await getInitializedConnection();
  try {
    return await conn.query(sql, values);
  } finally {
    conn.release();
  }
}) as any;

export const pool = rawPool;

/**
 * Test database connection
 */
export async function testConnection(): Promise<void> {
  try {
    const connection = await rawPool.getConnection();
    await connection.query(doltInitSql);
    initializedConnections.add(connection);
    await connection.ping();
    console.log(`✅ Database connected: ${DB_HOST}:${DB_PORT}/${DB_NAME}`);
    connection.release();
  } catch (error) {
    console.error('❌ Database connection failed:', error);
    throw error;
  }
}

/**
 * Close all database connections
 */
export async function closeConnections(): Promise<void> {
  try {
    await rawPool.end();
    console.log('✅ Database connections closed');
  } catch (error) {
    console.error('❌ Error closing database connections:', error);
    throw error;
  }
}
