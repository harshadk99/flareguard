#!/usr/bin/env node

/**
 * FlareGuard Environment Setup Script
 * 
 * This script securely prompts for Cloudflare credentials and saves them to a .env file.
 * 
 * SECURITY NOTE: The .env file should NEVER be committed to version control.
 * Make sure .env is in your .gitignore file.
 */

import fs from 'fs';
import readline from 'readline';
import path from 'path';

// Create a secure readline interface
const rl = readline.createInterface({
  input: process.stdin,
  output: process.stdout
});

/**
 * Function to securely prompt for credentials
 * @returns {Promise<Object>} Object containing zoneId and apiToken
 */
function promptCredentials() {
  return new Promise((resolve) => {
    console.log('\x1b[36m%s\x1b[0m', 'FlareGuard Environment Setup');
    console.log('This script will update your .env file with your Cloudflare credentials.');
    console.log('\x1b[33mWarning: These credentials will be stored in your .env file.\x1b[0m');
    console.log('Make sure your .env file is in .gitignore to prevent accidental commits.\n');
    
    // Verify .env is in .gitignore before proceeding
    verifyGitIgnore();
    
    rl.question('Enter your Cloudflare Zone ID: ', (zoneId) => {
      if (!zoneId) {
        console.log('\x1b[31mZone ID cannot be empty. Exiting.\x1b[0m');
        rl.close();
        process.exit(1);
      }
      
      // Use a masked input for the API token if possible
      rl.question('Enter your Cloudflare API Token: ', (apiToken) => {
        if (!apiToken) {
          console.log('\x1b[31mAPI Token cannot be empty. Exiting.\x1b[0m');
          rl.close();
          process.exit(1);
        }
        
        rl.close();
        resolve({ zoneId, apiToken });
      });
    });
  });
}

/**
 * Verify that .env is in .gitignore to prevent accidental commits
 */
function verifyGitIgnore() {
  try {
    // Check if .gitignore exists
    if (!fs.existsSync('.gitignore')) {
      console.log('\x1b[31mWarning: .gitignore file not found!\x1b[0m');
      console.log('\x1b[31mCreating .gitignore file with .env entry...\x1b[0m');
      fs.writeFileSync('.gitignore', '\n# Environment variables\n.env\n', { flag: 'a' });
      return;
    }
    
    // Check if .env is in .gitignore
    const gitignore = fs.readFileSync('.gitignore', 'utf8');
    if (!gitignore.includes('.env')) {
      console.log('\x1b[31mWarning: .env is not in .gitignore!\x1b[0m');
      console.log('\x1b[31mAdding .env to .gitignore...\x1b[0m');
      fs.writeFileSync('.gitignore', '\n# Environment variables\n.env\n', { flag: 'a' });
    }
  } catch (error) {
    console.error('\x1b[31mError checking .gitignore:', error.message, '\x1b[0m');
    console.log('\x1b[31mPlease manually ensure .env is added to .gitignore\x1b[0m');
  }
}

/**
 * Securely write credentials to .env file
 * @param {string} zoneId - Cloudflare Zone ID
 * @param {string} apiToken - Cloudflare API Token
 */
function writeEnvFile(zoneId, apiToken) {
  try {
    const envContent = `# Cloudflare credentials
CF_ZONE_ID=${zoneId}
CF_API_TOKEN=${apiToken}

# Never commit this file to version control!`;

    // Set restrictive file permissions (readable/writable only by owner)
    fs.writeFileSync('.env', envContent, { mode: 0o600 });
    console.log('\x1b[32m%s\x1b[0m', '✓ .env file updated successfully!');
    console.log('\x1b[32m%s\x1b[0m', '✓ File permissions set to 600 (owner read/write only)');
    console.log('You can now run: npm run test:env');
  } catch (error) {
    console.error('\x1b[31mError writing .env file:', error.message, '\x1b[0m');
    process.exit(1);
  }
}

// Check if .env file exists
if (!fs.existsSync('.env')) {
  console.log('\x1b[33m%s\x1b[0m', '.env file not found. Creating a new one.');
} else {
  console.log('\x1b[33m%s\x1b[0m', 'Existing .env file will be overwritten.');
}

// Get credentials and update .env file
promptCredentials().then(({ zoneId, apiToken }) => {
  writeEnvFile(zoneId, apiToken);
}); 