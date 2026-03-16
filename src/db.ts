/**
 * Database Connection
 * 
 * MySQL connection pool for Dolt database.
 * Dolt is MySQL-compatible, so we use mysql2 driver.
 */

import mysql from 'mysql2/promise';

const DB_HOST = process.env.DB_HOST || '127.0.0.1';
const DB_PORT = parseInt(process.env.DB_PORT || '3306');
const DB_USER = process.env.DB_USER || 'root';
const DB_PASSWORD = process.env.DB_PASSWORD || '';
const DB_NAME = process.env.DB_NAME || 'spacechild_auth';

// Create connection pool
export const pool = mysql.createPool({
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

/**
 * Test database connection
 */
export async function testConnection(): Promise<void> {
  try {
    const connection = await pool.getConnection();
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
    await pool.end();
    console.log('✅ Database connections closed');
  } catch (error) {
    console.error('❌ Error closing database connections:', error);
    throw error;
  }
}