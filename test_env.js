#!/usr/bin/env node

/**
 * FlareGuard Security Audit Test Script
 * 
 * This script runs a security audit on a Cloudflare zone using environment variables
 * for credentials to avoid hardcoding sensitive information.
 * 
 * SECURITY NOTE: This script reads credentials from .env file which should NEVER be committed
 * to version control. Make sure .env is in your .gitignore file.
 */

import { auditZone } from './src/index.js';
import dotenv from 'dotenv';
import fs from 'fs';

// Load environment variables from .env file
dotenv.config();

// Get credentials from environment variables
const zoneId = process.env.CF_ZONE_ID;
const apiToken = process.env.CF_API_TOKEN;

// Validate environment variables
if (!zoneId || zoneId === 'your_zone_id_here') {
  console.error('\x1b[31mError: Please set CF_ZONE_ID in your .env file\x1b[0m');
  process.exit(1);
}

if (!apiToken || apiToken === 'your_api_token_here') {
  console.error('\x1b[31mError: Please set CF_API_TOKEN in your .env file\x1b[0m');
  process.exit(1);
}

// Only show a portion of the Zone ID for security (first 6 and last 4 chars)
console.log('\x1b[36m%s\x1b[0m', 'FlareGuard Security Audit');
console.log('\x1b[36m%s\x1b[0m', `Zone ID: ${zoneId.substring(0, 6)}...${zoneId.substring(zoneId.length - 4)}`);
console.log('Running audit...');

// Run the audit
auditZone(zoneId, apiToken)
  .then(results => {
    console.log('\x1b[32m%s\x1b[0m', '✓ Audit completed successfully!');
    
    // Display summary
    console.log('\n' + '='.repeat(50));
    console.log('\x1b[1m%s\x1b[0m', 'SECURITY AUDIT SUMMARY');
    console.log('='.repeat(50));
    
    const score = results.summary.score;
    let scoreColor = '\x1b[31m'; // Red
    if (score >= 90) {
      scoreColor = '\x1b[32m'; // Green
    } else if (score >= 70) {
      scoreColor = '\x1b[33m'; // Yellow
    }
    
    console.log(`\x1b[1mSecurity Score:\x1b[0m ${scoreColor}${score}%\x1b[0m`);
    console.log(`\x1b[1mTotal Checks:\x1b[0m ${results.summary.total_checks}`);
    console.log(`\x1b[1mPassed:\x1b[0m \x1b[32m${results.summary.passed}\x1b[0m`);
    console.log(`\x1b[1mFailed:\x1b[0m \x1b[31m${results.summary.failed}\x1b[0m`);
    console.log(`\x1b[1mWarning:\x1b[0m \x1b[33m${results.summary.warning || 0}\x1b[0m`);
    
    // Save results to a file for inspection
    // SECURITY NOTE: Ensure audit_results.json is in .gitignore to prevent committing sensitive data
    const sanitizedResults = sanitizeResults(results);
    fs.writeFileSync('audit_results.json', JSON.stringify(sanitizedResults, null, 2));
    console.log('\x1b[32m%s\x1b[0m', '✓ Results saved to audit_results.json');
    
    // Display results by status
    displayResultsByStatus(results.details);
  })
  .catch(error => {
    console.error('\x1b[31m%s\x1b[0m', `✗ Error running audit: ${error.message}`);
    process.exit(1);
  });

/**
 * Sanitize results to remove any potentially sensitive information
 * @param {Object} results - The audit results
 * @returns {Object} Sanitized results
 */
function sanitizeResults(results) {
  // Create a deep copy of the results
  const sanitized = JSON.parse(JSON.stringify(results));
  
  // Remove or mask any potentially sensitive information
  if (sanitized.zone_id) {
    sanitized.zone_id = `${sanitized.zone_id.substring(0, 6)}...${sanitized.zone_id.substring(sanitized.zone_id.length - 4)}`;
  }
  
  // Add more sanitization as needed
  
  return sanitized;
}

/**
 * Helper function to display results grouped by status
 * @param {Array} details - The audit details
 */
function displayResultsByStatus(details) {
  // Group by status
  const passed = details.filter(check => check.status === 'PASS');
  const failed = details.filter(check => check.status === 'FAIL');
  const warnings = details.filter(check => check.status === 'WARNING');
  
  // Display failed checks first
  if (failed.length > 0) {
    console.log('\n' + '='.repeat(50));
    console.log('\x1b[31m\x1b[1m%s\x1b[0m', 'FAILED CHECKS');
    console.log('='.repeat(50));
    
    failed.forEach(check => {
      console.log(`\n\x1b[1m${check.id}: ${check.name}\x1b[0m`);
      console.log(`Category: ${check.category}`);
      console.log(`Severity: ${check.severity}`);
      console.log(`\x1b[33mRemediation: ${check.remediation}\x1b[0m`);
    });
  }
  
  // Display warnings
  if (warnings.length > 0) {
    console.log('\n' + '='.repeat(50));
    console.log('\x1b[33m\x1b[1m%s\x1b[0m', 'WARNINGS');
    console.log('='.repeat(50));
    
    warnings.forEach(check => {
      console.log(`\n\x1b[1m${check.id}: ${check.name}\x1b[0m`);
      console.log(`Category: ${check.category}`);
      console.log(`Severity: ${check.severity}`);
      console.log(`\x1b[33mRemediation: ${check.remediation}\x1b[0m`);
    });
  }
  
  // Display passed checks
  if (passed.length > 0) {
    console.log('\n' + '='.repeat(50));
    console.log('\x1b[32m\x1b[1m%s\x1b[0m', 'PASSED CHECKS');
    console.log('='.repeat(50));
    
    passed.forEach(check => {
      console.log(`\n\x1b[1m${check.id}: ${check.name}\x1b[0m`);
      console.log(`Category: ${check.category}`);
      console.log(`\x1b[32m${check.remediation}\x1b[0m`);
    });
  }
} 