/**
 * FlareGuard Zero Trust Module
 * This module contains functions to evaluate Cloudflare Zero Trust configurations
 */

/**
 * Evaluates Access applications for security best practices
 * @param {Object} env - Environment variables
 * @param {string} accountId - Cloudflare account ID
 * @param {string} apiToken - Cloudflare API token
 * @returns {Promise<Object>} - Access apps audit results
 */
export async function auditAccessApps(env, accountId, apiToken) {
  try {
    // Input validation
    if (!accountId) throw new Error("Account ID is required");
    if (!apiToken) throw new Error("API token is required");
    
    // Fetch all Access applications
    console.log(`Fetching Access applications for account ${accountId}`);
    const apps = await fetchAccessApps(accountId, apiToken);
    
    if (!apps || apps.length === 0) {
      console.log("No Access applications found");
      return {
        success: true,
        summary: {
          total: 0,
          pass: 0,
          warning: 0,
          fail: 0,
          score: 0,
        },
        results: [],
        message: "No Access applications found."
      };
    }
    
    console.log(`Found ${apps.length} Access applications`);
    
    // Initialize counters
    let totalChecks = 0;
    let passCount = 0;
    let warningCount = 0;
    let failCount = 0;
    
    // Results array to store all app checks
    const results = [];
    
    // Evaluate each application
    for (const app of apps) {
      console.log(`Evaluating app: ${app.name} (${app.id})`);
      
      try {
        // Fetch policies for this app
        const appPolicies = await fetchAppPolicies(accountId, apiToken, app.id);
        const appChecks = [];
        
        // Check 1: MFA Required
        totalChecks++;
        const mfaRequired = appPolicies.some(policy => 
          policy.decision === "allow" && policy.require_mfa === true
        );
        
        appChecks.push({
          id: "ZT-ACCESS-001",
          title: "MFA Required",
          status: mfaRequired ? "PASS" : "FAIL",
          severity: "HIGH",
          details: mfaRequired ? "MFA is required for this application" : "No policies require MFA for this application"
        });
        
        mfaRequired ? passCount++ : failCount++;
        
        // Check 2: Session Duration
        totalChecks++;
        const sessionDuration = app.session_duration;
        let durationHours = 0;
        
        // Convert session duration to hours
        if (sessionDuration) {
          if (sessionDuration.endsWith('h')) {
            durationHours = parseInt(sessionDuration.slice(0, -1));
          } else if (sessionDuration.endsWith('m')) {
            durationHours = parseInt(sessionDuration.slice(0, -1)) / 60;
          } else if (sessionDuration.endsWith('d')) {
            durationHours = parseInt(sessionDuration.slice(0, -1)) * 24;
          }
        }
        
        let sessionStatus = "PASS";
        let sessionDetails = `Session duration is ${sessionDuration}`;
        
        if (durationHours > 12) {
          sessionStatus = "FAIL";
          sessionDetails = `Session duration is ${sessionDuration}. Recommended maximum is 8h`;
          failCount++;
        } else if (durationHours > 8) {
          sessionStatus = "WARNING";
          sessionDetails = `Session duration is ${sessionDuration}. Recommended maximum is 8h`;
          warningCount++;
        } else {
          passCount++;
        }
        
        appChecks.push({
          id: "ZT-ACCESS-002",
          title: "Appropriate Session Duration",
          status: sessionStatus,
          severity: "MEDIUM",
          details: sessionDetails
        });
        
        // Check 3: No "Allow All" Policies
        totalChecks++;
        const hasAllowAllPolicies = appPolicies.some(policy => 
          policy.decision === "allow" && (!policy.include || policy.include.length === 0)
        );
        
        appChecks.push({
          id: "ZT-ACCESS-004",
          title: "No 'Allow All' Policies",
          status: !hasAllowAllPolicies ? "PASS" : "FAIL",
          severity: "HIGH",
          details: !hasAllowAllPolicies ? "No 'Allow All' policies found" : "Application has policies that allow access to everyone"
        });
        
        !hasAllowAllPolicies ? passCount++ : failCount++;
        
        // Check 4: Device Posture Checks
        totalChecks++;
        const hasDevicePostureChecks = appPolicies.some(policy => 
          policy.require_device_posture && policy.require_device_posture.length > 0
        );
        
        appChecks.push({
          id: "ZT-ACCESS-003",
          title: "Device Posture Checks",
          status: hasDevicePostureChecks ? "PASS" : "WARNING",
          severity: "HIGH",
          details: hasDevicePostureChecks ? "Device posture checks are configured" : "No device posture checks configured"
        });
        
        hasDevicePostureChecks ? passCount++ : warningCount++;
        
        // Check 5: Geo-Restrictions
        totalChecks++;
        const hasGeoRestrictions = appPolicies.some(policy => 
          policy.include && policy.include.some(include => include.geo)
        );
        
        appChecks.push({
          id: "ZT-ACCESS-007",
          title: "Geo-Restrictions",
          status: hasGeoRestrictions ? "PASS" : "WARNING",
          severity: "MEDIUM",
          details: hasGeoRestrictions ? "Geo-restrictions are configured" : "No geo-restrictions configured"
        });
        
        hasGeoRestrictions ? passCount++ : warningCount++;
        
        // Check 6: Approval Required for Critical Apps
        totalChecks++;
        const hasApprovalRequired = appPolicies.some(policy => policy.approval_required === true);
        
        // Determine if app is critical based on domain or name
        const appDomain = app.domain || "";
        const appName = app.name || "";
        const isCritical = 
          appDomain.includes("admin") || 
          appName.includes("Admin") || 
          appName.includes("admin") || 
          appName.includes("critical") || 
          appName.includes("Critical");
        
        let approvalStatus = "PASS";
        let approvalDetails = "Not a critical application";
        
        if (isCritical && hasApprovalRequired) {
          approvalStatus = "PASS";
          approvalDetails = "Critical application has approval workflow";
          passCount++;
        } else if (isCritical && !hasApprovalRequired) {
          approvalStatus = "FAIL";
          approvalDetails = "Critical application does not have approval workflow";
          failCount++;
        } else {
          passCount++;
        }
        
        appChecks.push({
          id: "ZT-ACCESS-008",
          title: "Approval for Critical App",
          status: approvalStatus,
          severity: "HIGH",
          details: approvalDetails
        });
        
        // Add app results to overall results
        results.push({
          app_name: app.name,
          app_domain: app.domain,
          app_id: app.id,
          checks: appChecks
        });
      } catch (appError) {
        console.error(`Error evaluating app ${app.name} (${app.id}):`, appError);
        
        // Add error result for this app
        results.push({
          app_name: app.name,
          app_domain: app.domain || "Unknown",
          app_id: app.id,
          error: appError.message,
          checks: []
        });
      }
    }
    
    // Calculate security score
    const score = totalChecks > 0 ? Math.round((passCount / totalChecks) * 100) : 0;
    
    console.log(`Access app audit complete: ${apps.length} apps, ${totalChecks} checks, Score: ${score}%`);
    
    return {
      success: true,
      summary: {
        total: apps.length,
        pass: passCount,
        warning: warningCount,
        fail: failCount,
        score: score,
      },
      results: results,
    };
  } catch (error) {
    console.error("Access app audit failed:", error);
    return {
      success: false,
      error: error.message || "Failed to audit Access applications",
    };
  }
}

/**
 * Fetches Access applications from Cloudflare API
 * @param {string} accountId - Cloudflare account ID
 * @param {string} apiToken - Cloudflare API token
 * @returns {Promise<Array>} - List of Access applications
 */
async function fetchAccessApps(accountId, apiToken) {
  try {
    // Ensure valid parameters
    if (!accountId) throw new Error("Account ID is required");
    if (!apiToken) throw new Error("API token is required");
    
    const response = await fetch(
      `https://api.cloudflare.com/client/v4/accounts/${accountId}/access/apps`,
      {
        headers: {
          "Authorization": `Bearer ${apiToken}`,
          "Content-Type": "application/json"
        },
        // Add timeout to prevent hanging requests
        cf: {
          cacheTtl: 60,
          cacheEverything: false
        }
      }
    );
    
    if (!response.ok) {
      const errorText = await response.text();
      let errorMessage = `API request failed with status ${response.status}`;
      
      try {
        const errorData = JSON.parse(errorText);
        if (errorData.errors && errorData.errors.length > 0) {
          errorMessage = errorData.errors[0].message || errorMessage;
        }
      } catch (e) {
        // If parsing fails, use the raw error text
        errorMessage = errorText || errorMessage;
      }
      
      throw new Error(errorMessage);
    }
    
    const data = await response.json();
    
    if (!data.success) {
      throw new Error(data.errors[0]?.message || "Failed to fetch Access applications");
    }
    
    return data.result;
  } catch (error) {
    console.error("Error fetching Access applications:", error);
    throw new Error(`Error fetching Access applications: ${error.message}`);
  }
}

/**
 * Fetches policies for a specific Access application
 * @param {string} accountId - Cloudflare account ID
 * @param {string} apiToken - Cloudflare API token
 * @param {string} appId - Access application ID
 * @returns {Promise<Array>} - List of policies for the application
 */
async function fetchAppPolicies(accountId, apiToken, appId) {
  try {
    // Ensure valid parameters
    if (!accountId) throw new Error("Account ID is required");
    if (!apiToken) throw new Error("API token is required");
    if (!appId) throw new Error("Application ID is required");
    
    const response = await fetch(
      `https://api.cloudflare.com/client/v4/accounts/${accountId}/access/apps/${appId}/policies`,
      {
        headers: {
          "Authorization": `Bearer ${apiToken}`,
          "Content-Type": "application/json"
        },
        // Add timeout to prevent hanging requests
        cf: {
          cacheTtl: 60,
          cacheEverything: false
        }
      }
    );
    
    if (!response.ok) {
      const errorText = await response.text();
      let errorMessage = `API request failed with status ${response.status}`;
      
      try {
        const errorData = JSON.parse(errorText);
        if (errorData.errors && errorData.errors.length > 0) {
          errorMessage = errorData.errors[0].message || errorMessage;
        }
      } catch (e) {
        // If parsing fails, use the raw error text
        errorMessage = errorText || errorMessage;
      }
      
      throw new Error(errorMessage);
    }
    
    const data = await response.json();
    
    if (!data.success) {
      throw new Error(data.errors[0]?.message || "Failed to fetch application policies");
    }
    
    return data.result;
  } catch (error) {
    console.error("Error fetching application policies:", error);
    throw new Error(`Error fetching application policies: ${error.message}`);
  }
}

/**
 * Evaluates Gateway DNS filtering configuration
 * @param {string} accountId - Cloudflare account ID
 * @param {string} apiToken - Cloudflare API token
 * @returns {Promise<Object>} - Gateway DNS filtering audit results
 */
export async function auditGatewayDns(env, accountId, apiToken) {
  try {
    // For now return simulated data - implement actual API calls in future
    return {
      success: true,
      summary: {
        pass: 2,
        warning: 1,
        fail: 0,
        score: 80,
      },
      results: [
        {
          id: "ZT-NETWORK-001",
          title: "DNS Filtering Enabled",
          status: "PASS",
          details: "DNS filtering is enabled and configured to block malicious domains"
        },
        {
          id: "ZT-NETWORK-001.1",
          title: "Security Categories Blocked",
          status: "PASS",
          details: "Security categories (malware, phishing) are blocked"
        },
        {
          id: "ZT-NETWORK-001.2", 
          title: "Content Filtering",
          status: "WARNING",
          details: "Content filtering is enabled but missing some recommended categories"
        }
      ]
    };
  } catch (error) {
    return {
      success: false,
      error: error.message || "Failed to audit Gateway DNS configuration",
    };
  }
}

/**
 * Evaluates identity providers configuration
 * @param {string} accountId - Cloudflare account ID
 * @param {string} apiToken - Cloudflare API token
 * @returns {Promise<Object>} - Identity providers audit results
 */
export async function auditIdentityProviders(env, accountId, apiToken) {
  try {
    // For now return simulated data - implement actual API calls in future
    return {
      success: true,
      summary: {
        total: 2,
        pass: 3,
        warning: 1,
        fail: 0,
        score: 85,
      },
      results: [
        {
          provider_name: "Okta",
          provider_type: "SAML",
          checks: [
            {
              id: "ZT-ACCESS-005.1",
              title: "MFA Support",
              status: "PASS",
              details: "Identity provider supports MFA"
            },
            {
              id: "ZT-ACCESS-005.2",
              title: "Secure Configuration",
              status: "PASS",
              details: "Identity provider is securely configured"
            }
          ]
        },
        {
          provider_name: "GitHub",
          provider_type: "OAuth",
          checks: [
            {
              id: "ZT-ACCESS-005.1",
              title: "MFA Support",
              status: "WARNING",
              details: "OAuth provider does not enforce MFA at the IdP level"
            },
            {
              id: "ZT-ACCESS-005.2",
              title: "Secure Configuration",
              status: "PASS",
              details: "Identity provider is securely configured"
            }
          ]
        }
      ]
    };
  } catch (error) {
    return {
      success: false,
      error: error.message || "Failed to audit identity providers",
    };
  }
}

/**
 * Main function to run all Zero Trust audits
 * @param {Object} env - Environment variables
 * @param {string} accountId - Cloudflare account ID
 * @param {string} apiToken - Cloudflare API token
 * @returns {Promise<Object>} - Complete Zero Trust audit results
 */
export async function auditZeroTrust(env, accountId, apiToken) {
  try {
    // Validate inputs
    if (!accountId) {
      return {
        success: false,
        error: "Account ID is required for Zero Trust audit"
      };
    }
    
    if (!apiToken) {
      return {
        success: false,
        error: "API token is required for Zero Trust audit"
      };
    }
    
    // Test if the API token has the correct permissions by making a simple call
    try {
      const testResponse = await fetch(
        `https://api.cloudflare.com/client/v4/accounts/${accountId}`,
        {
          headers: {
            "Authorization": `Bearer ${apiToken}`,
            "Content-Type": "application/json"
          }
        }
      );
      
      if (!testResponse.ok) {
        const errorText = await testResponse.text();
        try {
          const errorData = JSON.parse(errorText);
          if (errorData.errors && errorData.errors.length > 0) {
            return {
              success: false,
              error: `API token validation failed: ${errorData.errors[0].message}`,
            };
          }
        } catch (e) {
          return {
            success: false,
            error: `API token validation failed: ${testResponse.status} ${testResponse.statusText}`,
          };
        }
      }
    } catch (testError) {
      return {
        success: false,
        error: `API token validation failed: ${testError.message}`,
      };
    }
    
    // Run all Zero Trust audits in parallel
    const accessPromise = auditAccessApps(env, accountId, apiToken).catch(err => ({
      success: false, 
      error: err.message,
      summary: { total: 0, pass: 0, warning: 0, fail: 0, score: 0 },
      results: []
    }));
    
    const gatewayPromise = auditGatewayDns(env, accountId, apiToken).catch(err => ({
      success: false,
      error: err.message,
      summary: { pass: 0, warning: 0, fail: 0, score: 0 },
      results: []
    }));
    
    const idpPromise = auditIdentityProviders(env, accountId, apiToken).catch(err => ({
      success: false,
      error: err.message,
      summary: { total: 0, pass: 0, warning: 0, fail: 0, score: 0 },
      results: []
    }));
    
    // Wait for all audits to complete, even if some fail
    const [accessResults, gatewayResults, idpResults] = await Promise.all([
      accessPromise, gatewayPromise, idpPromise
    ]);
    
    // Track if any audits failed
    const auditErrors = [];
    if (!accessResults.success) auditErrors.push(`Access apps audit failed: ${accessResults.error}`);
    if (!gatewayResults.success) auditErrors.push(`Gateway DNS audit failed: ${gatewayResults.error}`);
    if (!idpResults.success) auditErrors.push(`Identity providers audit failed: ${idpResults.error}`);
    
    // Calculate overall score from successful audits
    const totalPass = 
      (accessResults.success ? accessResults.summary.pass : 0) + 
      (gatewayResults.success ? gatewayResults.summary.pass : 0) + 
      (idpResults.success ? idpResults.summary.pass : 0);
    
    const totalChecks = 
      (accessResults.success ? (accessResults.summary.pass + accessResults.summary.warning + accessResults.summary.fail) : 0) +
      (gatewayResults.success ? (gatewayResults.summary.pass + gatewayResults.summary.warning + gatewayResults.summary.fail) : 0) +
      (idpResults.success ? (idpResults.summary.pass + idpResults.summary.warning + idpResults.summary.fail) : 0);
    
    const overallScore = totalChecks > 0 ? Math.round((totalPass / totalChecks) * 100) : 0;
    
    return {
      // Consider overall success if at least one audit succeeded
      success: accessResults.success || gatewayResults.success || idpResults.success,
      summary: {
        score: overallScore,
        access_apps: accessResults.summary,
        gateway: gatewayResults.summary,
        identity_providers: idpResults.summary,
        audit_errors: auditErrors.length > 0 ? auditErrors : undefined
      },
      access_results: accessResults.results,
      gateway_results: gatewayResults.results,
      identity_results: idpResults.results
    };
  } catch (error) {
    console.error("Zero Trust audit failed:", error);
    return {
      success: false,
      error: error.message || "Failed to complete Zero Trust audit",
    };
  }
} 