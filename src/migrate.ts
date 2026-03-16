/**
 * Database Migration Runner
 * 
 * Reads and executes the schema.sql file to create/update database tables.
 * Uses idempotent CREATE TABLE IF NOT EXISTS statements.
 */

import fs from 'fs/promises';
import path from 'path';
import type { Pool } from 'mysql2/promise';

/**
 * Run database migrations
 */
export async function runMigrations(pool: Pool): Promise<void> {
  try {
    console.log('🔄 Running database migrations...');

    // Read schema.sql file
    const schemaPath = path.join(__dirname, 'schema.sql');
    const schemaContent = await fs.readFile(schemaPath, 'utf-8');

    // Strip comments, then split into individual statements
    const cleaned = schemaContent
      .replace(/\/\*[\s\S]*?\*\//g, '')  // Remove /* ... */ block comments
      .replace(/--.*$/gm, '');            // Remove -- line comments
    
    const statements = cleaned
      .split(';')
      .map(stmt => stmt.trim())
      .filter(stmt => stmt.length > 5);

    console.log(`📋 Found ${statements.length} migration statements`);

    // Execute each statement
    const connection = await pool.getConnection();
    
    try {
      for (let i = 0; i < statements.length; i++) {
        const statement = statements[i] + ';'; // Add semicolon back
        
        if (statement.trim().length < 3) continue; // Skip empty/tiny statements
        
        try {
          await connection.execute(statement);
          console.log(`✅ Migration ${i + 1}/${statements.length} executed`);
        } catch (error: any) {
          // Log but continue if it's a duplicate key or table exists error
          if (error.code === 'ER_TABLE_EXISTS_ERROR' || 
              error.code === 'ER_DUP_KEYNAME' ||
              error.message?.includes('already exists')) {
            console.log(`⚠️  Migration ${i + 1}/${statements.length} skipped (already exists)`);
          } else {
            console.error(`❌ Migration ${i + 1}/${statements.length} failed:`, error.message);
            console.error(`Statement: ${statement.substring(0, 100)}...`);
            throw error;
          }
        }
      }

      console.log('✅ Database migrations completed successfully');
    } finally {
      connection.release();
    }
  } catch (error) {
    console.error('❌ Migration failed:', error);
    throw error;
  }
}

/**
 * Create migration from SQL string (for tests)
 */
export async function runMigrationFromSQL(pool: Pool, sql: string): Promise<void> {
  const connection = await pool.getConnection();
  
  try {
    const statements = sql
      .split(';')
      .map(stmt => stmt.trim())
      .filter(stmt => stmt.length > 0 && !stmt.startsWith('--'));

    for (const statement of statements) {
      if (statement.trim().length < 3) continue;
      await connection.execute(statement + ';');
    }
  } finally {
    connection.release();
  }
}