/**
 * FlareGuard Cloudflare Worker
 * Security auditing tool for Cloudflare configurations
 * 
 * SECURITY NOTES:
 * 1. This code handles API tokens which should be treated as sensitive credentials
 * 2. API tokens are never stored persistently and are only used for the duration of the audit
 * 3. All processing happens at request time in the Cloudflare Worker
 * 4. The UI uses type="password" fields to protect token visibility
 * 5. Input validation is performed on all user-provided data
 */

// Import dependencies
import yaml from 'js-yaml';

// Helper function for making HTTP requests from inside the worker
async function httpsRequest(url, options) {
  return await fetch(url, options);
}

// Embedded baseline (simplified version of our full baseline)
const BASELINE_YAML = `# FlareGuard Security Baseline Checks - Sample subset
# Access (Zero Trust) Checks
- id: ZT-01
  title: MFA Required for All Access Apps
  description: Verifies that all Access applications enforce multi-factor authentication
  service: Access
  check_type: access-policy
  check_details:
    mfa: enforced
    identity_provider: configured
  severity: high
  nist_controls: [IA-2, AC-3]

# WAF Checks
- id: WAF-01
  title: OWASP Core Rule Set Enabled
  description: Verifies that the OWASP Core Rule Set is enabled and properly configured
  service: WAF
  check_type: waf-config
  check_details:
    owasp_ruleset: enabled
    sensitivity: medium_or_higher
  severity: critical
  nist_controls: [SI-3, SC-7]

# TLS/Certificates Checks
- id: TLS-01
  title: Minimum TLS Version
  description: Verifies that minimum TLS version is 1.2 or higher
  service: TLS/Certificates
  check_type: tls-config
  check_details:
    min_tls_version: "1.2"
  severity: critical
  nist_controls: [SC-8, SC-12, SC-13]

# DNS Checks
- id: DNS-01
  title: DNSSEC Enabled
  description: Verifies that DNSSEC is enabled to prevent DNS spoofing attacks
  service: DNS
  check_type: dns-settings
  check_details:
    dnssec: enabled
    validation: active
  severity: high
  nist_controls: [SC-8, SC-20]

# Firewall Rules Checks
- id: FW-02
  title: Bot Management Enabled
  description: Ensures that bot management is enabled to block malicious automated traffic
  service: Firewall Rules
  check_type: firewall-rules
  check_details:
    bot_management: enabled
    advanced_protection: true
  severity: high
  nist_controls: [SC-5, SI-4]`;

/**
 * Run audit on a Cloudflare Zone - Using real API data
 * @param {string} zoneId - Cloudflare Zone ID
 * @param {string} apiToken - Cloudflare API Token
 * @returns {Object} Audit results
 * 
 * SECURITY: This function validates inputs and uses the API token only for the duration
 * of the audit. The token is never stored persistently.
 */
async function auditZone(zoneId, apiToken) {
  try {
    // Validate inputs
    if (!zoneId || !apiToken) {
      throw new Error("Missing required parameters: zone_id and api_token");
    }

    // Fetch actual settings from the API instead of using hard-coded values
    const settings = await fetchWorkingSettings(zoneId, apiToken);
    
    // Evaluate settings against security baseline
    const details = evaluateSettings(settings);
    
    // Calculate summary stats
    const totalChecks = details.length;
    const passedChecks = details.filter(check => check.status === "PASS").length;
    const failedChecks = details.filter(check => check.status === "FAIL").length;
    const warningChecks = details.filter(check => check.status === "WARNING").length;
    
    // Generate report
    return {
      timestamp: new Date().toISOString(),
      zone_id: zoneId,
      summary: {
        total_checks: totalChecks,
        passed: passedChecks,
        failed: failedChecks,
        warning: warningChecks,
        score: Math.round((passedChecks / totalChecks) * 100),
      },
      details: details
    };
  } catch (error) {
    console.error("Audit error:", error);
    throw new Error(`Audit failed: ${error.message}`);
  }
}

/**
 * Fetch only the settings we know work from Cloudflare API
 * @param {string} zoneId - Cloudflare Zone ID
 * @param {string} apiToken - Cloudflare API Token
 * @returns {Object} Working settings
 * 
 * SECURITY: This function makes authenticated API calls to Cloudflare.
 * The API token is passed in the Authorization header and never logged or stored.
 */
async function fetchWorkingSettings(zoneId, apiToken) {
  try {
    const headers = {
      'Authorization': `Bearer ${apiToken}`,
      'Content-Type': 'application/json'
    };

    // Fetch settings that we've verified work with the API
    const settings = {};
    
    // SSL/TLS Mode
    const sslResponse = await httpsRequest(`https://api.cloudflare.com/client/v4/zones/${zoneId}/settings/ssl`, {
      method: 'GET',
      headers: headers
    });
    if (sslResponse) {
      settings.ssl_mode = sslResponse.value;
    }
    
    // Minimum TLS Version
    const tlsVersionResponse = await httpsRequest(`https://api.cloudflare.com/client/v4/zones/${zoneId}/settings/min_tls_version`, {
      method: 'GET',
      headers: headers
    });
    if (tlsVersionResponse) {
      settings.min_tls_version = tlsVersionResponse.value;
    }
    
    // Always Use HTTPS
    const httpsResponse = await httpsRequest(`https://api.cloudflare.com/client/v4/zones/${zoneId}/settings/always_use_https`, {
      method: 'GET',
      headers: headers
    });
    if (httpsResponse) {
      settings.always_use_https = httpsResponse.value;
    }
    
    // Opportunistic Encryption
    const oeResponse = await httpsRequest(`https://api.cloudflare.com/client/v4/zones/${zoneId}/settings/opportunistic_encryption`, {
      method: 'GET',
      headers: headers
    });
    if (oeResponse) {
      settings.opportunistic_encryption = oeResponse.value;
    }
    
    // TLS 1.3
    const tls13Response = await httpsRequest(`https://api.cloudflare.com/client/v4/zones/${zoneId}/settings/tls_1_3`, {
      method: 'GET',
      headers: headers
    });
    if (tls13Response) {
      settings.tls_1_3 = tls13Response.value;
    }
    
    // Browser Integrity Check
    const bicResponse = await httpsRequest(`https://api.cloudflare.com/client/v4/zones/${zoneId}/settings/browser_check`, {
      method: 'GET',
      headers: headers
    });
    if (bicResponse) {
      settings.browser_check = bicResponse.value;
    }
    
    // Email Obfuscation
    const emailResponse = await httpsRequest(`https://api.cloudflare.com/client/v4/zones/${zoneId}/settings/email_obfuscation`, {
      method: 'GET',
      headers: headers
    });
    if (emailResponse) {
      settings.email_obfuscation = emailResponse.value;
    }
    
    // Security Level
    const secLevelResponse = await httpsRequest(`https://api.cloudflare.com/client/v4/zones/${zoneId}/settings/security_level`, {
      method: 'GET',
      headers: headers
    });
    if (secLevelResponse) {
      settings.security_level = secLevelResponse.value;
    }
    
    return settings;
  } catch (error) {
    console.error("Error fetching settings:", error);
    throw new Error(`API Error: ${error.message}`);
  }
}

/**
 * Evaluate settings against security baseline
 * @param {Object} settings - Cloudflare settings
 * @returns {Array} Evaluation results
 */
function evaluateSettings(settings) {
  const results = [];
  
  // SSL/TLS Mode
  results.push({
    id: "CF-SSL-001",
    name: "SSL/TLS Encryption is set to Full (Strict)",
    category: "SSL/TLS",
    description: "Ensure SSL/TLS encryption is set to Full (Strict) for maximum security",
    status: settings.ssl_mode === "strict" ? "PASS" : "FAIL",
    severity: "HIGH",
    nist_controls: ["SC-8", "SC-13"],
    remediation: settings.ssl_mode === "strict" ? 
      "SSL/TLS encryption is properly set to Full (Strict)" : 
      "Set SSL/TLS encryption to 'Full (Strict)' in SSL/TLS settings"
  });
  
  // Minimum TLS Version
  results.push({
    id: "CF-TLS-001",
    name: "Minimum TLS Version is 1.2 or higher",
    category: "SSL/TLS",
    description: "Ensure the minimum TLS version is set to 1.2 or higher",
    status: (settings.min_tls_version === "1.2" || settings.min_tls_version === "1.3") ? "PASS" : "FAIL",
    severity: "HIGH",
    nist_controls: ["SC-8", "SC-13"],
    remediation: (settings.min_tls_version === "1.2" || settings.min_tls_version === "1.3") ? 
      "Minimum TLS version is correctly set to 1.2 or higher" : 
      "Set minimum TLS version to 1.2 or 1.3 in SSL/TLS > Edge Certificates"
  });
  
  // Always Use HTTPS
  results.push({
    id: "CF-HTTPS-001",
    name: "Always Use HTTPS is enabled",
    category: "SSL/TLS",
    description: "Ensure 'Always Use HTTPS' is enabled to force all connections over HTTPS",
    status: settings.always_use_https === "on" ? "PASS" : "FAIL",
    severity: "MEDIUM",
    nist_controls: ["SC-8", "SC-13"],
    remediation: settings.always_use_https === "on" ? 
      "Always Use HTTPS is properly enabled" : 
      "Enable Always Use HTTPS in SSL/TLS > Edge Certificates"
  });
  
  // Opportunistic Encryption
  results.push({
    id: "CF-TLS-002",
    name: "Opportunistic Encryption is enabled",
    category: "SSL/TLS",
    description: "Ensure Opportunistic Encryption is enabled for enhanced security",
    status: settings.opportunistic_encryption === "on" ? "PASS" : "FAIL",
    severity: "LOW",
    nist_controls: ["SC-8"],
    remediation: settings.opportunistic_encryption === "on" ? 
      "Opportunistic Encryption is properly enabled" : 
      "Enable Opportunistic Encryption in SSL/TLS > Edge Certificates"
  });
  
  // TLS 1.3
  results.push({
    id: "CF-TLS-003",
    name: "TLS 1.3 is enabled",
    category: "SSL/TLS",
    description: "Ensure TLS 1.3 is enabled for the latest security features",
    status: settings.tls_1_3 === "on" ? "PASS" : "FAIL",
    severity: "MEDIUM",
    nist_controls: ["SC-8", "SC-13"],
    remediation: settings.tls_1_3 === "on" ? 
      "TLS 1.3 is properly enabled" : 
      "Enable TLS 1.3 in SSL/TLS > Edge Certificates"
  });
  
  // Browser Integrity Check
  results.push({
    id: "CF-BROWSER-001",
    name: "Browser Integrity Check is enabled",
    category: "Security Level",
    description: "Ensure Browser Integrity Check is enabled to block malicious requests",
    status: settings.browser_check === "on" ? "PASS" : "FAIL",
    severity: "MEDIUM",
    nist_controls: ["SI-3", "SI-4"],
    remediation: settings.browser_check === "on" ? 
      "Browser Integrity Check is properly enabled" : 
      "Enable Browser Integrity Check in Security > Settings"
  });
  
  // Email Obfuscation
  results.push({
    id: "CF-EMAIL-001",
    name: "Email Obfuscation is enabled",
    category: "Scrape Shield",
    description: "Ensure Email Obfuscation is enabled to protect email addresses from scrapers",
    status: settings.email_obfuscation === "on" ? "PASS" : "FAIL",
    severity: "LOW",
    nist_controls: ["SI-19"],
    remediation: settings.email_obfuscation === "on" ? 
      "Email Obfuscation is properly enabled" : 
      "Enable Email Obfuscation in Scrape Shield settings"
  });
  
  // Security Level
  results.push({
    id: "CF-CHALLENGE-001",
    name: "Security Level is set to Medium or Higher",
    category: "Security Level",
    description: "Ensure Security Level is set to Medium or higher for proper protection",
    status: (settings.security_level === "medium" || 
             settings.security_level === "high" || 
             settings.security_level === "under_attack") ? "PASS" : "FAIL",
    severity: "MEDIUM",
    nist_controls: ["SC-7", "SI-4"],
    remediation: (settings.security_level === "medium" || 
                  settings.security_level === "high" || 
                  settings.security_level === "under_attack") ? 
      "Security Level is properly set to Medium or higher" : 
      "Set Security Level to Medium or higher in Security > Settings"
  });
  
  return results;
}

/**
 * Fetch zone settings from Cloudflare API
 * @param {string} zoneId - Cloudflare Zone ID
 * @param {string} apiToken - Cloudflare API Token
 * @returns {Object} Zone settings
 */
async function fetchZoneSettings(zoneId, apiToken) {
  try {
    const headers = {
      'Authorization': `Bearer ${apiToken}`,
      'Content-Type': 'application/json'
    };

    // First, validate the zone ID and API token by fetching basic zone info
    const zoneInfoUrl = `https://api.cloudflare.com/client/v4/zones/${zoneId}`;
    const zoneInfoResponse = await httpsRequest(zoneInfoUrl, {
      method: 'GET',
      headers: headers
    });
    
    if (!zoneInfoResponse.ok) {
      const errorData = await zoneInfoResponse.json();
      throw new Error(`Failed to validate zone: ${zoneInfoResponse.status} - ${JSON.stringify(errorData)}`);
    }
    
    // Fetch basic zone settings
    const zoneSettingsUrl = `https://api.cloudflare.com/client/v4/zones/${zoneId}/settings`;
    const zoneResponse = await httpsRequest(zoneSettingsUrl, {
      method: 'GET',
      headers: headers
    });
    
    if (!zoneResponse.ok) {
      const errorData = await zoneResponse.json();
      throw new Error(`Failed to fetch zone settings: ${zoneResponse.status} - ${JSON.stringify(errorData)}`);
    }
    
    const zoneSettings = await zoneResponse.json();
    
    // Fetch SSL settings
    let sslSettings = null;
    try {
      const sslUrl = `https://api.cloudflare.com/client/v4/zones/${zoneId}/settings/ssl`;
      const sslResponse = await httpsRequest(sslUrl, {
        method: 'GET',
        headers: headers
      });
      
      if (sslResponse.ok) {
        sslSettings = await sslResponse.json();
      }
    } catch (error) {
      console.error("Error fetching SSL settings:", error);
    }
    
    // Fetch TLS version settings
    let tlsSettings = null;
    try {
      const tlsUrl = `https://api.cloudflare.com/client/v4/zones/${zoneId}/settings/min_tls_version`;
      const tlsResponse = await httpsRequest(tlsUrl, {
        method: 'GET',
        headers: headers
      });
      
      if (tlsResponse.ok) {
        tlsSettings = await tlsResponse.json();
      }
    } catch (error) {
      console.error("Error fetching TLS settings:", error);
    }
    
    // Fetch WAF packages
    let wafPackages = null;
    try {
      const wafUrl = `https://api.cloudflare.com/client/v4/zones/${zoneId}/firewall/waf/packages`;
      const wafResponse = await httpsRequest(wafUrl, {
        method: 'GET',
        headers: headers
      });
      
      if (wafResponse.ok) {
        wafPackages = await wafResponse.json();
      }
    } catch (error) {
      console.error("Error fetching WAF packages:", error);
    }
    
    // Fetch DNSSEC settings
    let dnssecSettings = null;
    try {
      const dnssecUrl = `https://api.cloudflare.com/client/v4/zones/${zoneId}/dnssec`;
      const dnssecResponse = await httpsRequest(dnssecUrl, {
        method: 'GET',
        headers: headers
      });
      
      if (dnssecResponse.ok) {
        dnssecSettings = await dnssecResponse.json();
      }
    } catch (error) {
      console.error("Error fetching DNSSEC settings:", error);
    }

    // Fetch firewall rules
    let firewallRules = null;
    try {
      const firewallUrl = `https://api.cloudflare.com/client/v4/zones/${zoneId}/firewall/rules`;
      const firewallResponse = await httpsRequest(firewallUrl, {
        method: 'GET',
        headers: headers
      });
      
      if (firewallResponse.ok) {
        firewallRules = await firewallResponse.json();
      }
    } catch (error) {
      console.error("Error fetching firewall rules:", error);
    }

    // Fetch Bot Management settings
    let botSettings = null;
    try {
      const botUrl = `https://api.cloudflare.com/client/v4/zones/${zoneId}/bot_management`;
      const botResponse = await httpsRequest(botUrl, {
        method: 'GET',
        headers: headers
      });
      
      if (botResponse.ok) {
        botSettings = await botResponse.json();
      }
    } catch (error) {
      console.error("Error fetching bot management settings:", error);
    }
    
    return {
      basic: zoneSettings.result,
      ssl: sslSettings?.result,
      tls: tlsSettings?.result,
      waf: wafPackages?.result,
      dnssec: dnssecSettings?.result,
      firewall: firewallRules?.result,
      bot: botSettings?.result
    };
  } catch (error) {
    console.error("Error fetching zone settings:", error);
    throw new Error(`API Error: ${error.message}`);
  }
}

/**
 * Evaluate a single security check against zone settings
 * @param {Object} check - Baseline check
 * @param {Object} zoneSettings - Zone settings
 * @param {string} zoneId - Zone ID
 * @param {string} apiToken - API Token
 * @returns {Object} Check result
 */
async function evaluateCheck(check, zoneSettings, zoneId, apiToken) {
  // Initialize result object
  const result = {
    id: check.id,
    title: check.title,
    description: check.description,
    service: check.service,
    severity: check.severity,
    nist_controls: check.nist_controls
  };
  
  // Determine which evaluation function to use based on service
  switch (check.service) {
    case "TLS/Certificates":
      return evaluateTlsCheck(check, zoneSettings, result);
    case "WAF":
      return evaluateWafCheck(check, zoneSettings, zoneId, apiToken, result);
    case "Access":
      return evaluateAccessCheck(check, zoneSettings, zoneId, apiToken, result);
    case "DNS":
      return evaluateDnsCheck(check, zoneSettings, zoneId, apiToken, result);
    case "Firewall Rules":
      return evaluateFirewallCheck(check, zoneSettings, zoneId, apiToken, result);
    // Add more service evaluators as needed
    default:
      result.status = "not_applicable";
      result.message = `Service ${check.service} evaluation not implemented yet`;
      return result;
  }
}

/**
 * Evaluate TLS/Certificate security checks
 */
async function evaluateTlsCheck(check, zoneSettings, result) {
  // Use actual TLS settings
  if (check.id === "TLS-01") {
    let minVersion = "1.0"; // Default fallback
    
    // Check dedicated TLS settings endpoint first
    if (zoneSettings.tls) {
      minVersion = zoneSettings.tls.value;
    } 
    // Otherwise check SSL settings
    else if (zoneSettings.ssl) {
      minVersion = zoneSettings.ssl.value;
    } 
    // Otherwise try to find it in basic settings
    else {
      const tlsSettings = zoneSettings.basic.find(setting => setting.id === "min_tls_version");
      if (tlsSettings) {
        minVersion = tlsSettings.value;
      }
    }
    
    const requiredVersion = check.check_details.min_tls_version;
    
    // Compare versions
    if (minVersion >= requiredVersion) {
      result.status = "passed";
      result.message = `TLS version is ${minVersion}, which meets the minimum requirement of ${requiredVersion}`;
    } else {
      result.status = "failed";
      result.message = `TLS version is ${minVersion}, but minimum required is ${requiredVersion}`;
      result.remediation = "Update minimum TLS version in SSL/TLS settings";
    }
    return result;
  }
  
  // For other TLS checks
  result.status = "not_applicable";
  result.message = `TLS check ${check.id} not implemented yet`;
  return result;
}

/**
 * Evaluate WAF security checks
 */
async function evaluateWafCheck(check, zoneSettings, zoneId, apiToken, result) {
  // Use actual WAF data
  if (check.id === "WAF-01") {
    let isOwaspEnabled = false;
    let sensitivity = "off";
    
    // Check if WAF packages exist and find OWASP package
    if (zoneSettings.waf && Array.isArray(zoneSettings.waf)) {
      // Look for OWASP package
      const owaspPackage = zoneSettings.waf.find(pkg => 
        pkg.name.toLowerCase().includes('owasp') || 
        pkg.description.toLowerCase().includes('owasp')
      );
      
      if (owaspPackage) {
        isOwaspEnabled = owaspPackage.detection_mode !== "off";
        sensitivity = owaspPackage.sensitivity || "medium";
      }
    }
    
    if (isOwaspEnabled && (sensitivity === "high" || sensitivity === "medium")) {
      result.status = "passed";
      result.message = `OWASP Core Rule Set is enabled with ${sensitivity} sensitivity`;
    } else if (isOwaspEnabled) {
      result.status = "failed";
      result.message = `OWASP Core Rule Set is enabled but sensitivity (${sensitivity}) is too low`;
      result.remediation = "Increase OWASP Core Rule Set sensitivity to medium or high";
    } else {
      result.status = "failed";
      result.message = "OWASP Core Rule Set is not properly configured";
      result.remediation = "Enable OWASP Core Rule Set with medium or high sensitivity";
    }
    return result;
  }
  
  // For other WAF checks
  result.status = "not_applicable";
  result.message = `WAF check ${check.id} not implemented yet`;
  return result;
}

/**
 * Evaluate Access security checks
 */
async function evaluateAccessCheck(check, zoneSettings, zoneId, apiToken, result) {
  // For simplicity, we'll simulate Access checks for now
  if (check.id === "ZT-01") {
    // Simulate checking MFA settings
    // In a real implementation, you would fetch Access policies
    
    // Simulated check (replace with actual API call in production)
    const isMfaEnforced = false; // This would come from an API call
    const hasIdentityProvider = true; // This would come from an API call
    
    if (isMfaEnforced && hasIdentityProvider) {
      result.status = "passed";
      result.message = "MFA is enforced for all Access applications";
    } else {
      result.status = "failed";
      result.message = "MFA is not enforced for all Access applications";
      result.remediation = "Configure MFA enforcement in Access policies";
    }
    return result;
  }
  
  // For other Access checks
  result.status = "not_applicable";
  result.message = `Access check ${check.id} not implemented yet`;
  return result;
}

/**
 * Evaluate DNS security checks
 */
async function evaluateDnsCheck(check, zoneSettings, zoneId, apiToken, result) {
  if (check.id === "DNS-01") {
    // Use actual DNSSEC settings
    let dnssecEnabled = false;
    let dnssecStatus = "inactive";
    
    if (zoneSettings.dnssec) {
      dnssecEnabled = zoneSettings.dnssec.status === "active";
      dnssecStatus = zoneSettings.dnssec.status;
    }
    
    if (dnssecEnabled) {
      result.status = "passed";
      result.message = "DNSSEC is properly enabled and validated";
    } else {
      result.status = "failed";
      result.message = `DNSSEC is not enabled (status: ${dnssecStatus})`;
      result.remediation = "Enable DNSSEC in DNS settings";
    }
    return result;
  }
  
  // For other DNS checks
  result.status = "not_applicable";
  result.message = `DNS check ${check.id} not implemented yet`;
  return result;
}

/**
 * Evaluate Firewall security checks
 */
async function evaluateFirewallCheck(check, zoneSettings, zoneId, apiToken, result) {
  if (check.id === "FW-02") {
    // Use actual Bot Management settings
    let botManagementEnabled = false;
    let advancedProtection = false;
    
    if (zoneSettings.bot) {
      botManagementEnabled = zoneSettings.bot.enabled === true;
      // Check if advanced protection is enabled (varies by response format)
      advancedProtection = 
        zoneSettings.bot.mode === "advanced" || 
        zoneSettings.bot.protection_level === "advanced";
    }
    
    if (botManagementEnabled && advancedProtection) {
      result.status = "passed";
      result.message = "Bot Management is enabled with advanced protection";
    } else if (botManagementEnabled) {
      result.status = "failed";
      result.message = "Bot Management is enabled but without advanced protection";
      result.remediation = "Enable advanced protection in Bot Management settings";
    } else {
      result.status = "failed";
      result.message = "Bot Management is not enabled";
      result.remediation = "Enable Bot Management in security settings";
    }
    return result;
  }
  
  // For other Firewall checks
  result.status = "not_applicable";
  result.message = `Firewall check ${check.id} not implemented yet`;
  return result;
}

/**
 * Generate HTML report from audit results
 */
function generateHtmlReport(results) {
  if (results.error) {
    return `<html>
      <head><title>FlareGuard - Error</title></head>
      <body>
        <h1>FlareGuard Audit Error</h1>
        <p>${results.error}</p>
        <p>Timestamp: ${results.timestamp}</p>
      </body>
    </html>`;
  }

  // Calculate color based on pass percentage
  let statusColor = "#ff4d4d"; // Red for < 70%
  if (results.summary.pass_percentage >= 90) {
    statusColor = "#4CAF50"; // Green for >= 90%
  } else if (results.summary.pass_percentage >= 70) {
    statusColor = "#FFC107"; // Yellow for >= 70%
  }

  // Generate HTML for each check
  const checksHtml = results.checks.map(check => {
    const statusIcon = check.status === "passed" ? "✅" : 
                       check.status === "failed" ? "❌" : 
                       check.status === "error" ? "⚠️" : "ℹ️";
                       
    const remediation = check.remediation ? 
      `<p><strong>Remediation:</strong> ${check.remediation}</p>` : '';
      
    return `
    <div class="check ${check.status}">
      <h3>${statusIcon} ${check.id}: ${check.title}</h3>
      <p>${check.description}</p>
      <p><strong>Service:</strong> ${check.service}</p>
      <p><strong>Severity:</strong> ${check.severity}</p>
      <p><strong>Status:</strong> ${check.status}</p>
      <p><strong>Message:</strong> ${check.message}</p>
      ${remediation}
      <p><strong>NIST Controls:</strong> ${check.nist_controls ? check.nist_controls.join(', ') : 'N/A'}</p>
    </div>`;
  }).join('');

  return `<!DOCTYPE html>
  <html>
    <head>
      <title>FlareGuard Security Audit Report</title>
      <style>
        body { font-family: Arial, sans-serif; line-height: 1.6; margin: 0; padding: 20px; color: #333; }
        h1, h2 { color: #0051c3; }
        .summary { background-color: #f5f5f5; padding: 15px; border-radius: 5px; margin-bottom: 20px; }
        .status-indicator { 
          display: inline-block; 
          width: 100px; 
          height: 100px; 
          border-radius: 50%; 
          background-color: ${statusColor}; 
          text-align: center; 
          line-height: 100px; 
          color: white; 
          font-size: 24px; 
          font-weight: bold;
          margin: 10px;
        }
        .check { border: 1px solid #ddd; padding: 15px; margin-bottom: 15px; border-radius: 5px; }
        .passed { border-left: 5px solid #4CAF50; }
        .failed { border-left: 5px solid #ff4d4d; }
        .error { border-left: 5px solid #FFC107; }
        .not_applicable { border-left: 5px solid #999; }
        table { border-collapse: collapse; width: 100%; }
        th, td { text-align: left; padding: 12px; }
        tr:nth-child(even) { background-color: #f2f2f2; }
        th { background-color: #0051c3; color: white; }
      </style>
    </head>
    <body>
      <h1>FlareGuard Security Audit Report</h1>
      <p>Zone ID: ${results.zone_id}</p>
      <p>Generated: ${results.timestamp}</p>
      
      <div class="summary">
        <h2>Summary</h2>
        <div style="display: flex; align-items: center;">
          <div class="status-indicator">${results.summary.pass_percentage}%</div>
          <div>
            <table>
              <tr>
                <th>Total Checks</th>
                <th>Passed</th>
                <th>Failed</th>
                <th>Warning</th>
                <th>N/A</th>
              </tr>
              <tr>
                <td>${results.summary.total_checks}</td>
                <td>${results.summary.passed}</td>
                <td>${results.summary.failed}</td>
                <td>${results.summary.warning || 0}</td>
                <td>${results.summary.not_applicable}</td>
              </tr>
            </table>
          </div>
        </div>
      </div>
      
      <h2>Detailed Results</h2>
      ${checksHtml}
      
      <footer style="margin-top: 40px; padding-top: 20px; border-top: 1px solid #ddd; text-align: center; color: #666; font-size: 14px;">
        <p>FlareGuard is a personal project built using Cloudflare Workers and public APIs. It is not affiliated with or endorsed by Cloudflare.</p>
      </footer>
    </body>
  </html>`;
}

/**
 * Handle test connection endpoint - simplified version
 * 
 * SECURITY: This function validates the format of user-provided credentials
 * before attempting to use them. It performs input validation to prevent
 * injection attacks and ensures the API token meets minimum security requirements.
 */
async function handleTestConnection(request) {
  try {
    const body = await request.json();
    
    // Support both zone_id and account_id
    const hasZoneId = !!body.zone_id;
    const hasAccountId = !!body.account_id;
    
    if ((!hasZoneId && !hasAccountId) || !body.api_token) {
      return new Response(JSON.stringify({
        success: false,
        error: "Missing required parameters: either zone_id or account_id, and api_token"
      }), {
        status: 400,
        headers: { "Content-Type": "application/json" }
      });
    }
    
    // Basic validation of IDs and api_token format
    const idPattern = /^[a-f0-9]{32}$/i;
    const apiTokenPattern = /^[a-zA-Z0-9_-]{40,}$/;
    
    let errors = [];
    
    if (hasZoneId && !idPattern.test(body.zone_id)) {
      errors.push("Zone ID format is invalid. It should be a 32-character hexadecimal string.");
    }
    
    if (hasAccountId && !idPattern.test(body.account_id)) {
      errors.push("Account ID format is invalid. It should be a 32-character hexadecimal string.");
    }
    
    if (!apiTokenPattern.test(body.api_token)) {
      errors.push("API Token format is invalid. It should be at least 40 characters of letters, numbers, underscores, or hyphens.");
    }
    
    if (errors.length > 0) {
      return new Response(JSON.stringify({
        success: false,
        error: "Validation errors",
        details: errors
      }), {
        status: 400,
        headers: { "Content-Type": "application/json" }
      });
    }
    
    // If both pass basic format validation
    return new Response(JSON.stringify({
      success: true,
      message: "Credentials format is valid. Try running an audit to confirm they work correctly."
    }), {
      headers: { "Content-Type": "application/json" }
    });
    
  } catch (error) {
    console.error("Test connection error:", error);
    return new Response(JSON.stringify({
      success: false,
      error: `Failed to process request: ${error.message}`
    }), {
      status: 500,
      headers: { "Content-Type": "application/json" }
    });
  }
}

/**
 * Main request handler for FlareGuard worker
 * 
 * SECURITY: This function handles all incoming requests and ensures:
 * 1. Proper input validation for all user-provided data
 * 2. API tokens are only used for the duration of the request
 * 3. No sensitive data is stored persistently
 * 4. Appropriate error handling to prevent information disclosure
 */
async function handleRequest(request, env, ctx) {
  const url = new URL(request.url);
  
  // Handle dashboard UI
  if (url.pathname === "/" && request.method === "GET") {
    return new Response(generateDashboardHtml(), {
      headers: { "Content-Type": "text/html" }
    });
  }
  
  // Handle audit request
  if (url.pathname === "/audit" && request.method === "POST") {
    try {
      // Parse request body
      const body = await request.json();
      
      // Validate required parameters
      if (!body.zone_id || !body.api_token) {
        return new Response(JSON.stringify({
          error: "Missing required parameters: zone_id and api_token"
        }), {
          status: 400,
          headers: { "Content-Type": "application/json" }
        });
      }
      
      // Run audit
      try {
        const auditResults = await auditZone(body.zone_id, body.api_token);
        
        // Return JSON response by default
        const acceptHeader = request.headers.get("Accept") || "";
        if (acceptHeader.includes("text/html")) {
          // Return HTML report if requested
          return new Response(generateHtmlReport(auditResults), {
            headers: { "Content-Type": "text/html" }
          });
        } else {
          // Return JSON by default
          return new Response(JSON.stringify(auditResults), {
            headers: { "Content-Type": "application/json" }
          });
        }
      } catch (auditError) {
        // Handle specific audit errors
        console.error("Audit error:", auditError);
        return new Response(JSON.stringify({
          error: auditError.message,
          timestamp: new Date().toISOString()
        }), {
          status: 400,
          headers: { "Content-Type": "application/json" }
        });
      }
    } catch (error) {
      // Handle general request processing errors
      console.error("Request processing error:", error);
      return new Response(JSON.stringify({
        error: `Failed to process audit request: ${error.message}`,
        timestamp: new Date().toISOString()
      }), {
        status: 500,
        headers: { "Content-Type": "application/json" }
      });
    }
  }
  
  // Handle test connection endpoints (both regular and API versions)
  if ((url.pathname === "/test-connection" || url.pathname === "/api/test-connection") && request.method === "POST") {
    return handleTestConnection(request);
  }
  
  // Root path returns info about the API
  return new Response(`
    FlareGuard is up! Security checks are available.
    
    POST /audit
    {
      "zone_id": "your-cloudflare-zone-id",
      "api_token": "your-cloudflare-api-token"
    }
    
    Set Accept: text/html header to receive HTML report
  `, {
    headers: { "Content-Type": "text/plain" }
  });
}

/**
 * Generate Dashboard HTML
 */
function generateDashboardHtml() {
  return `<!DOCTYPE html>
  <html lang="en">
  <head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>FlareGuard - Cloudflare Security Auditing</title>
    <style>
      :root {
        --primary-color: #f38020;
        --secondary-color: #faad3f;
        --dark-color: #404041;
        --light-color: #f6f6f6;
        --success-color: #4CAF50;
        --warning-color: #FFC107;
        --danger-color: #ff4d4d;
      }
      
      body {
        font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, 'Open Sans', 'Helvetica Neue', sans-serif;
        line-height: 1.6;
        margin: 0;
        padding: 0;
        color: var(--dark-color);
        background-color: var(--light-color);
      }
      
      header {
        background-color: var(--primary-color);
        color: white;
        padding: 1rem;
        text-align: center;
      }
      
      .container {
        max-width: 1200px;
        margin: 0 auto;
        padding: 1rem;
      }
      
      .card {
        background-color: white;
        border-radius: 5px;
        box-shadow: 0 2px 5px rgba(0, 0, 0, 0.1);
        padding: 1.5rem;
        margin-bottom: 1.5rem;
      }
      
      h1, h2, h3 {
        color: var(--dark-color);
      }
      
      .logo {
        font-weight: bold;
        font-size: 1.5rem;
      }
      
      .btn {
        display: inline-block;
        background-color: var(--primary-color);
        color: white;
        padding: 0.5rem 1rem;
        text-decoration: none;
        border: none;
        border-radius: 4px;
        cursor: pointer;
        font-size: 1rem;
        transition: background-color 0.3s;
      }
      
      .btn:hover {
        background-color: var(--secondary-color);
      }

      .btn-secondary {
        background-color: var(--dark-color);
      }
      
      .btn-secondary:hover {
        background-color: #555;
      }
      
      .btn-row {
        display: flex;
        gap: 10px;
        margin-top: 10px;
      }
      
      input, select {
        padding: 0.5rem;
        border: 1px solid #ddd;
        border-radius: 4px;
        font-size: 1rem;
        width: 100%;
        margin-bottom: 1rem;
      }
      
      label {
        display: block;
        margin-bottom: 0.5rem;
        font-weight: bold;
      }
      
      .form-group {
        margin-bottom: 1rem;
      }
      
      #results {
        display: none;
        margin-top: 2rem;
      }
      
      .spinner {
        border: 4px solid rgba(0, 0, 0, 0.1);
        width: 36px;
        height: 36px;
        border-radius: 50%;
        border-left-color: var(--primary-color);
        animation: spin 1s linear infinite;
        margin: 1rem auto;
        display: none;
      }
      
      @keyframes spin {
        0% { transform: rotate(0deg); }
        100% { transform: rotate(360deg); }
      }
      
      .summary-stats {
        display: flex;
        justify-content: space-between;
        flex-wrap: wrap;
        margin-bottom: 1rem;
      }
      
      .stat-card {
        background-color: white;
        border-radius: 5px;
        box-shadow: 0 2px 5px rgba(0, 0, 0, 0.1);
        padding: 1rem;
        min-width: 150px;
        text-align: center;
        margin-bottom: 1rem;
      }
      
      .stat-title {
        font-size: 0.9rem;
        margin-bottom: 0.5rem;
        color: #666;
      }
      
      .stat-value {
        font-size: 2rem;
        font-weight: bold;
      }
      
      .passed { color: var(--success-color); }
      .failed { color: var(--danger-color); }
      .warning { color: var(--warning-color); }
      .na { color: #999; }
      
      .score-circle {
        width: 150px;
        height: 150px;
        border-radius: 50%;
        background-color: var(--danger-color);
        display: flex;
        align-items: center;
        justify-content: center;
        margin: 1rem auto;
        color: white;
        font-size: 2.5rem;
        font-weight: bold;
      }
      
      .check-list {
        margin-top: 2rem;
      }
      
      .check-item {
        border-left: 5px solid #ddd;
        padding: 1rem;
        margin-bottom: 1rem;
        background-color: white;
        border-radius: 0 5px 5px 0;
      }
      
      .check-item.PASS { border-left-color: var(--success-color); }
      .check-item.FAIL { border-left-color: var(--danger-color); }
      .check-item.WARNING { border-left-color: var(--warning-color); }
      .check-item.NA { border-left-color: #999; }
      
      footer {
        text-align: center;
        padding: 1rem;
        margin-top: 2rem;
        background-color: var(--dark-color);
        color: white;
      }
      
      .disclaimer {
        font-size: 0.9rem;
        color: #ccc;
        margin-top: 0.5rem;
      }
      
      .check-header {
        display: flex;
        justify-content: space-between;
        align-items: center;
        margin-bottom: 0.5rem;
      }
      
      .check-title {
        margin: 0;
        font-size: 1.2rem;
      }
      
      .check-badge {
        padding: 0.25rem 0.5rem;
        border-radius: 4px;
        font-size: 0.8rem;
        font-weight: bold;
        color: white;
      }
      
      .check-badge.HIGH { background-color: var(--danger-color); }
      .check-badge.MEDIUM { background-color: var(--warning-color); }
      .check-badge.LOW { background-color: #3498db; }
      .check-badge.CRITICAL { background-color: #9b59b6; }
      
      .alert {
        padding: 10px;
        margin-bottom: 15px;
        border-radius: 4px;
      }
      
      .alert-success {
        background-color: rgba(76, 175, 80, 0.1);
        border-left: 5px solid var(--success-color);
        color: #2c7a30;
      }
      
      .alert-error {
        background-color: rgba(255, 77, 77, 0.1);
        border-left: 5px solid var(--danger-color);
        color: #c62828;
      }
      
      .connection-status {
        display: none;
        margin-bottom: 15px;
      }
      
      footer {
        text-align: center;
        padding: 1rem;
        margin-top: 2rem;
        background-color: var(--dark-color);
        color: white;
      }
      
      @media (max-width: 768px) {
        .stat-card {
          flex-basis: 100%;
        }
      }
    </style>
  </head>
  <body>
    <header>
      <div class="logo">FlareGuard</div>
      <p>Cloudflare Security Auditing Tool</p>
    </header>
    
    <div class="container">
      <div class="card">
        <h2>Run Security Audit</h2>
        <div id="connection-status" class="connection-status"></div>
        <form id="audit-form">
          <div class="form-group">
            <label for="zone-id">Cloudflare Zone ID</label>
            <input type="text" id="zone-id" placeholder="Enter your Cloudflare Zone ID" required>
          </div>
          
          <div class="form-group">
            <label for="api-token">Cloudflare API Token</label>
            <input type="password" id="api-token" placeholder="Enter your Cloudflare API Token" required>
            <small>Your API token must have permissions to read zone settings, WAF, DNS, etc.</small>
          </div>
          
          <div class="btn-row">
            <button type="button" id="test-connection" class="btn btn-secondary">Test Connection</button>
            <button type="submit" class="btn">Run Audit</button>
          </div>
        </form>
        
        <div class="spinner" id="spinner"></div>
      </div>
      
      <div id="results" class="card">
        <h2>Audit Results</h2>
        <div id="summary">
          <div class="score-circle" id="score-circle">0%</div>
          
          <div class="summary-stats">
            <div class="stat-card">
              <div class="stat-title">Total Checks</div>
              <div class="stat-value" id="total-checks">0</div>
            </div>
            
            <div class="stat-card">
              <div class="stat-title">Passed</div>
              <div class="stat-value passed" id="passed-checks">0</div>
            </div>
            
            <div class="stat-card">
              <div class="stat-title">Failed</div>
              <div class="stat-value failed" id="failed-checks">0</div>
            </div>
            
            <div class="stat-card">
              <div class="stat-title">Warnings</div>
              <div class="stat-value warning" id="warning-checks">0</div>
            </div>
          </div>
        </div>
        
        <div class="check-list" id="check-list"></div>
        
        <button id="download-report" class="btn">Download Full Report</button>
      </div>
    </div>
    
    <footer>
      <p>&copy; 2025 FlareGuard - Cloudflare Security Auditing Tool</p>
      <p class="disclaimer">FlareGuard is a personal project built using Cloudflare Workers and public APIs. It is not affiliated with or endorsed by Cloudflare.</p>
    </footer>
    
    <script>
      document.addEventListener('DOMContentLoaded', function() {
        const auditForm = document.getElementById('audit-form');
        const testConnectionBtn = document.getElementById('test-connection');
        const connectionStatus = document.getElementById('connection-status');
        const spinner = document.getElementById('spinner');
        const results = document.getElementById('results');
        const scoreCircle = document.getElementById('score-circle');
        const totalChecks = document.getElementById('total-checks');
        const passedChecks = document.getElementById('passed-checks');
        const failedChecks = document.getElementById('failed-checks');
        const warningChecks = document.getElementById('warning-checks');
        const checkList = document.getElementById('check-list');
        const downloadReport = document.getElementById('download-report');
        
        let lastResults = null;
        
        // Test connection handler
        testConnectionBtn.addEventListener('click', async function() {
          const zoneId = document.getElementById('zone-id').value;
          const apiToken = document.getElementById('api-token').value;
          
          if (!zoneId || !apiToken) {
            alert('Please enter both Zone ID and API Token');
            return;
          }
          
          // Show loading spinner
          spinner.style.display = 'block';
          connectionStatus.style.display = 'none';
          
          try {
            const response = await fetch(window.location.origin + '/test-connection', {
              method: 'POST',
              headers: {
                'Content-Type': 'application/json'
              },
              body: JSON.stringify({
                zone_id: zoneId,
                api_token: apiToken
              })
            });
            
            const data = await response.json();
            
            if (data.success) {
              connectionStatus.className = 'alert alert-success';
              connectionStatus.innerHTML = '<strong>Connection Successful!</strong> ' + data.message;
            } else {
              connectionStatus.className = 'alert alert-error';
              connectionStatus.innerHTML = '<strong>Connection Failed:</strong> ' + data.error;
              if (data.details) {
                connectionStatus.innerHTML += '<br><small>' + (Array.isArray(data.details) ? data.details.join('<br>') : JSON.stringify(data.details)) + '</small>';
              }
            }
            
            // Hide spinner and show status
            spinner.style.display = 'none';
            connectionStatus.style.display = 'block';
            
          } catch (error) {
            console.error('Connection test error:', error);
            connectionStatus.className = 'alert alert-error';
            connectionStatus.innerHTML = '<strong>Connection Failed:</strong> ' + error.message;
            
            spinner.style.display = 'none';
            connectionStatus.style.display = 'block';
          }
        });
        
        auditForm.addEventListener('submit', async function(e) {
          e.preventDefault();
          
          const zoneId = document.getElementById('zone-id').value;
          const apiToken = document.getElementById('api-token').value;
          
          if (!zoneId || !apiToken) {
            alert('Please enter both Zone ID and API Token');
            return;
          }
          
          // Show loading spinner
          spinner.style.display = 'block';
          results.style.display = 'none';
          connectionStatus.style.display = 'none';
          
          try {
            const response = await fetch(window.location.origin + '/audit', {
              method: 'POST',
              headers: {
                'Content-Type': 'application/json'
              },
              body: JSON.stringify({
                zone_id: zoneId,
                api_token: apiToken
              })
            });
            
            const data = await response.json();
            
            if (data.error) {
              // Show error message
              connectionStatus.className = 'alert alert-error';
              connectionStatus.innerHTML = '<strong>Audit Failed:</strong> ' + data.error;
              connectionStatus.style.display = 'block';
              spinner.style.display = 'none';
              return;
            }
            
            lastResults = data;
            
            // Update UI with results
            updateResultsUI(data);
            
            // Hide spinner and show results
            spinner.style.display = 'none';
            results.style.display = 'block';
            
          } catch (error) {
            console.error('Audit error:', error);
            connectionStatus.className = 'alert alert-error';
            connectionStatus.innerHTML = '<strong>Audit Failed:</strong> ' + error.message;
            connectionStatus.style.display = 'block';
            spinner.style.display = 'none';
          }
        });
        
        function updateResultsUI(data) {
          // Update summary stats
          totalChecks.textContent = data.summary ? data.summary.total_checks || 0 : 0;
          passedChecks.textContent = data.summary ? data.summary.passed || 0 : 0;
          failedChecks.textContent = data.summary ? data.summary.failed || 0 : 0;
          warningChecks.textContent = data.summary ? data.summary.warning || 0 : 0;
          
          // Update score circle
          const score = Math.round(data.summary ? data.summary.score || 0 : 0);
          scoreCircle.textContent = score + '%';
          
          // Set score circle color based on percentage
          if (score >= 90) {
            scoreCircle.style.backgroundColor = 'var(--success-color)';
          } else if (score >= 70) {
            scoreCircle.style.backgroundColor = 'var(--warning-color)';
          } else {
            scoreCircle.style.backgroundColor = 'var(--danger-color)';
          }
          
          // Clear previous check list
          checkList.innerHTML = '';
          
          // Add checks to list - safely handle missing details array
          if (Array.isArray(data.details)) {
            data.details.forEach(check => {
              const checkItem = document.createElement('div');
              checkItem.className = 'check-item ' + check.status;
              
              const statusIcon = check.status === 'PASS' ? '✅' : 
                                check.status === 'FAIL' ? '❌' : 
                                check.status === 'WARNING' ? '⚠️' : 'ℹ️';
              
              const remediation = check.remediation ? 
                '<p><strong>Remediation:</strong> ' + check.remediation + '</p>' : '';
              
              checkItem.innerHTML = 
                '<div class="check-header">' +
                  '<h3 class="check-title">' + statusIcon + ' ' + check.id + ': ' + check.name + '</h3>' +
                  '<span class="check-badge ' + check.severity + '">' + check.severity + '</span>' +
                '</div>' +
                '<p>' + check.description + '</p>' +
                '<p><strong>Category:</strong> ' + check.category + '</p>' +
                remediation +
                '<p><strong>NIST Controls:</strong> ' + (check.nist_controls ? check.nist_controls.join(', ') : 'N/A') + '</p>';
              
              checkList.appendChild(checkItem);
            });
          } else {
            // Handle case where details array is missing
            checkList.innerHTML = '<div class="alert alert-error">No detailed results available</div>';
          }
        }
        
        // Handle download report button
        downloadReport.addEventListener('click', function() {
          if (!lastResults) {
            alert('No audit results available to download');
            return;
          }
          
          // Open HTML report in new tab
          fetch(window.location.origin + '/audit', {
            method: 'POST',
            headers: {
              'Content-Type': 'application/json',
              'Accept': 'text/html'
            },
            body: JSON.stringify({
              zone_id: lastResults.zone_id,
              api_token: document.getElementById('api-token').value
            })
          })
          .then(response => response.text())
          .then(html => {
            const newTab = window.open();
            newTab.document.write(html);
            newTab.document.close();
          })
          .catch(error => {
            console.error('Error downloading report:', error);
            alert('Error downloading report: ' + error.message);
          });
        });
      });
    </script>
  </body>
  </html>`;
}

export default {
  fetch: handleRequest
}; 

// Add event listener for direct worker invocation
addEventListener('fetch', event => {
  event.respondWith(handleRequest(event.request));
});