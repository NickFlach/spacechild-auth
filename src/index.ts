/**
 * SpaceChild Auth - Main Entry Point
 * 
 * Initializes the database, runs migrations, and starts the server.
 * Handles graceful shutdown and database connections.
 */

import * as dotenv from "dotenv";
dotenv.config();

import { testConnection, closeConnections, pool } from "./db";
import { runMigrations } from "./migrate";
import { startServer } from "./server";

/**
 * Initialize and start the application
 */
async function main() {
  console.log("🔄 Starting SpaceChild Auth service...");
  
  try {
    // Test database connection
    console.log("🔌 Testing database connection...");
    await testConnection();
    
    // Run database migrations
    console.log("🔄 Running database migrations...");
    await runMigrations(pool);
    
    // Start the HTTP server
    console.log("🚀 Starting HTTP server...");
    startServer();
    
    console.log("✅ SpaceChild Auth service started successfully!");
    
  } catch (error) {
    console.error("❌ Failed to start SpaceChild Auth service:", error);
    
    // Clean up and exit
    try {
      await closeConnections();
    } catch (closeError) {
      console.error("❌ Error closing database connections:", closeError);
    }
    
    process.exit(1);
  }
}

/**
 * Enhanced graceful shutdown that also closes database connections
 */
async function gracefulShutdown(signal: string) {
  console.log(`\n${signal} received. Starting graceful shutdown...`);
  
  try {
    // Close database connections
    console.log("🔄 Closing database connections...");
    await closeConnections();
    
    console.log("✅ Graceful shutdown completed");
    process.exit(0);
  } catch (error) {
    console.error("❌ Error during graceful shutdown:", error);
    process.exit(1);
  }
}

// Handle shutdown signals
process.on("SIGTERM", () => gracefulShutdown("SIGTERM"));
process.on("SIGINT", () => gracefulShutdown("SIGINT"));

// Handle uncaught exceptions and rejections
process.on("uncaughtException", (error) => {
  console.error("❌ Uncaught Exception:", error);
  gracefulShutdown("UNCAUGHT_EXCEPTION");
});

process.on("unhandledRejection", (reason, promise) => {
  console.error("❌ Unhandled Rejection at:", promise, "reason:", reason);
  gracefulShutdown("UNHANDLED_REJECTION");
});

// Start the application
if (require.main === module) {
  main();
}