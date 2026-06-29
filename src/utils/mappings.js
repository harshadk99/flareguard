/**
 * Compiled compliance framework mappings for runtime use.
 * Source of truth: mappings/*.yaml — edit those files, then sync here.
 *
 * Active frameworks:
 *   NIST SP 800-53 Rev 5  (mappings/nist-800-53-r5.yaml)
 *   CIS Controls v8       (mappings/cis-v8.yaml)
 */

export const FRAMEWORK_VERSIONS = {
  nist_800_53: 'NIST SP 800-53 Rev 5',
  cis_controls: 'CIS Controls v8',
};

// ── NIST SP 800-53 Rev 5 ──────────────────────────────────────────────────────

export const NIST_800_53 = {
  'AC-3': {
    title: 'Access Enforcement',
    family: 'Access Control',
    description: 'Enforce approved authorizations for logical access to information and system resources in accordance with applicable access control policies.',
    url: 'https://csrc.nist.gov/Projects/risk-management/sp800-53-controls/release-search#!/controls?version=5.1&search=AC-3',
  },
  'AU-2': {
    title: 'Event Logging',
    family: 'Audit and Accountability',
    description: 'Identify the types of events that the system is capable of logging in support of the audit function.',
    url: 'https://csrc.nist.gov/Projects/risk-management/sp800-53-controls/release-search#!/controls?version=5.1&search=AU-2',
  },
  'AU-9': {
    title: 'Protection of Audit Information',
    family: 'Audit and Accountability',
    description: 'Protect audit information and audit tools from unauthorized access, modification, and deletion.',
    url: 'https://csrc.nist.gov/Projects/risk-management/sp800-53-controls/release-search#!/controls?version=5.1&search=AU-9',
  },
  'CM-2': {
    title: 'Baseline Configuration',
    family: 'Configuration Management',
    description: 'Develop, document, and maintain under configuration control, a current baseline configuration of the system.',
    url: 'https://csrc.nist.gov/Projects/risk-management/sp800-53-controls/release-search#!/controls?version=5.1&search=CM-2',
  },
  'CM-6': {
    title: 'Configuration Settings',
    family: 'Configuration Management',
    description: 'Establish and document configuration settings that reflect the most restrictive mode consistent with operational requirements.',
    url: 'https://csrc.nist.gov/Projects/risk-management/sp800-53-controls/release-search#!/controls?version=5.1&search=CM-6',
  },
  'CM-7': {
    title: 'Least Functionality',
    family: 'Configuration Management',
    description: 'Configure the system to provide only essential capabilities, prohibiting or restricting the use of functions, ports, protocols, and services not required.',
    url: 'https://csrc.nist.gov/Projects/risk-management/sp800-53-controls/release-search#!/controls?version=5.1&search=CM-7',
  },
  'CM-8': {
    title: 'System Component Inventory',
    family: 'Configuration Management',
    description: 'Develop and document an inventory of system components that accurately reflects the system.',
    url: 'https://csrc.nist.gov/Projects/risk-management/sp800-53-controls/release-search#!/controls?version=5.1&search=CM-8',
  },
  'IA-2': {
    title: 'Identification and Authentication (Organizational Users)',
    family: 'Identification and Authentication',
    description: 'Uniquely identify and authenticate organizational users. Implement multi-factor authentication for access to privileged and non-privileged accounts.',
    url: 'https://csrc.nist.gov/Projects/risk-management/sp800-53-controls/release-search#!/controls?version=5.1&search=IA-2',
  },
  'IA-5': {
    title: 'Authenticator Management',
    family: 'Identification and Authentication',
    description: 'Manage system authenticators by verifying identity before distributing, protecting authenticator content from unauthorized disclosure and modification.',
    url: 'https://csrc.nist.gov/Projects/risk-management/sp800-53-controls/release-search#!/controls?version=5.1&search=IA-5',
  },
  'IA-8': {
    title: 'Identification and Authentication (Non-Organizational Users)',
    family: 'Identification and Authentication',
    description: 'Uniquely identify and authenticate non-organizational users or processes acting on behalf of non-organizational users.',
    url: 'https://csrc.nist.gov/Projects/risk-management/sp800-53-controls/release-search#!/controls?version=5.1&search=IA-8',
  },
  'MA-9': {
    title: 'Media Sanitization for Diagnostics and Maintenance',
    family: 'Maintenance',
    description: 'Prevent the unauthorized removal of maintenance equipment and verify that there is no organizational information on the equipment.',
    url: 'https://csrc.nist.gov/Projects/risk-management/sp800-53-controls/release-search#!/controls?version=5.1&search=MA-9',
  },
  'SA-9': {
    title: 'External System Services',
    family: 'System and Services Acquisition',
    description: 'Require that providers of external system services comply with organizational security and privacy requirements.',
    url: 'https://csrc.nist.gov/Projects/risk-management/sp800-53-controls/release-search#!/controls?version=5.1&search=SA-9',
  },
  'SC-5': {
    title: 'Denial-of-Service Protection',
    family: 'System and Communications Protection',
    description: 'Implement controls to protect against or limit the effects of denial-of-service events, including flooding, protocol abuse, or resource exhaustion.',
    url: 'https://csrc.nist.gov/Projects/risk-management/sp800-53-controls/release-search#!/controls?version=5.1&search=SC-5',
  },
  'SC-7': {
    title: 'Boundary Protection',
    family: 'System and Communications Protection',
    description: 'Monitor and control communications at the external boundary of the system and at key internal boundaries.',
    url: 'https://csrc.nist.gov/Projects/risk-management/sp800-53-controls/release-search#!/controls?version=5.1&search=SC-7',
  },
  'SC-8': {
    title: 'Transmission Confidentiality and Integrity',
    family: 'System and Communications Protection',
    description: 'Implement cryptographic mechanisms to prevent unauthorized disclosure of information and detect changes to information during transmission.',
    url: 'https://csrc.nist.gov/Projects/risk-management/sp800-53-controls/release-search#!/controls?version=5.1&search=SC-8',
  },
  'SC-8(1)': {
    title: 'Transmission Confidentiality and Integrity | Cryptographic Protection',
    family: 'System and Communications Protection',
    description: 'Enhancement: implement HTTPS/TLS with strong cipher suites and enforce via HSTS headers to prevent protocol downgrade attacks.',
    url: 'https://csrc.nist.gov/Projects/risk-management/sp800-53-controls/release-search#!/controls?version=5.1&search=SC-8(1)',
  },
  'SC-12': {
    title: 'Cryptographic Key Establishment and Management',
    family: 'System and Communications Protection',
    description: 'Establish and manage cryptographic keys when cryptography is employed within the system.',
    url: 'https://csrc.nist.gov/Projects/risk-management/sp800-53-controls/release-search#!/controls?version=5.1&search=SC-12',
  },
  'SC-13': {
    title: 'Cryptographic Protection',
    family: 'System and Communications Protection',
    description: 'Implement FIPS-validated or NSA-approved cryptography for each specified cryptographic use.',
    url: 'https://csrc.nist.gov/Projects/risk-management/sp800-53-controls/release-search#!/controls?version=5.1&search=SC-13',
  },
  'SC-17': {
    title: 'Public Key Infrastructure Certificates',
    family: 'System and Communications Protection',
    description: 'Issue public key certificates under an appropriate certificate policy. Monitor certificate transparency logs to detect mis-issued certificates.',
    url: 'https://csrc.nist.gov/Projects/risk-management/sp800-53-controls/release-search#!/controls?version=5.1&search=SC-17',
  },
  'SC-20': {
    title: 'Secure Name/Address Resolution Service (Authoritative Source)',
    family: 'System and Communications Protection',
    description: 'Provide additional data origin authentication and integrity verification along with authoritative name resolution data (DNSSEC).',
    url: 'https://csrc.nist.gov/Projects/risk-management/sp800-53-controls/release-search#!/controls?version=5.1&search=SC-20',
  },
  'SI-3': {
    title: 'Malicious Code Protection',
    family: 'System and Information Integrity',
    description: 'Implement malicious code protection mechanisms at system entry and exit points to detect and eradicate malicious code.',
    url: 'https://csrc.nist.gov/Projects/risk-management/sp800-53-controls/release-search#!/controls?version=5.1&search=SI-3',
  },
  'SI-4': {
    title: 'System Monitoring',
    family: 'System and Information Integrity',
    description: 'Monitor the system to detect attacks, indicators of potential attacks, unauthorized connections, and unauthorized system use.',
    url: 'https://csrc.nist.gov/Projects/risk-management/sp800-53-controls/release-search#!/controls?version=5.1&search=SI-4',
  },
  'SI-8': {
    title: 'Spam Protection',
    family: 'System and Information Integrity',
    description: 'Implement spam protection mechanisms at system entry and exit points to detect and take action on unsolicited messages.',
    url: 'https://csrc.nist.gov/Projects/risk-management/sp800-53-controls/release-search#!/controls?version=5.1&search=SI-8',
  },
  'SI-19': {
    title: 'De-identification',
    family: 'System and Information Integrity',
    description: 'Remove personally identifiable information from datasets and system outputs, including email addresses exposed through web content.',
    url: 'https://csrc.nist.gov/Projects/risk-management/sp800-53-controls/release-search#!/controls?version=5.1&search=SI-19',
  },
};

// ── CIS Controls v8 ───────────────────────────────────────────────────────────

export const CIS_V8 = {
  '3.10': {
    title: 'Encrypt Sensitive Data in Transit',
    group: 'CIS Control 3: Data Protection',
    implementation_groups: ['IG1', 'IG2', 'IG3'],
    description: 'Encrypt sensitive data in transit using TLS and HTTPS. Enforce HTTPS via HSTS and monitor certificate transparency logs to detect unauthorized certificates.',
    url: 'https://www.cisecurity.org/controls/v8',
  },
  '6.1': {
    title: 'Establish an Access Granting and Revoking Process',
    group: 'CIS Control 6: Access Control Management',
    implementation_groups: ['IG1', 'IG2', 'IG3'],
    description: 'Establish and follow a process for granting and revoking access to enterprise assets. Log all access events to a centralized system.',
    url: 'https://www.cisecurity.org/controls/v8',
  },
  '8.2': {
    title: 'Collect Audit Logs',
    group: 'CIS Control 8: Audit Log Management',
    implementation_groups: ['IG1', 'IG2', 'IG3'],
    description: 'Ensure that logging has been enabled across enterprise assets. Export logs to a centralized SIEM. Monitor client-side scripts via Page Shield for supply chain attacks.',
    url: 'https://www.cisecurity.org/controls/v8',
  },
  '9.3': {
    title: 'Maintain and Enforce Network-Based URL Filters',
    group: 'CIS Control 9: Email and Web Browser Protections',
    implementation_groups: ['IG2', 'IG3'],
    description: 'Enforce network-based URL filters to limit connections to potentially malicious websites. Enable hotlink protection to prevent unauthorized resource embedding.',
    url: 'https://www.cisecurity.org/controls/v8',
  },
  '12.6': {
    title: 'Use of Secure Network Management and Communication Protocols',
    group: 'CIS Control 12: Network Infrastructure Management',
    implementation_groups: ['IG2', 'IG3'],
    description: 'Use secure network management and communication protocols such as HTTP/2 and HTTP/3 (QUIC). Enable IPv6 for modern network connectivity.',
    url: 'https://www.cisecurity.org/controls/v8',
  },
};

// ── Resolver ──────────────────────────────────────────────────────────────────

/**
 * Resolve an array of control IDs to full metadata objects.
 * Unknown IDs are returned as { id, title: id } so findings never break.
 */
export function resolveControls(nistIds = [], cisIds = []) {
  return {
    nist: nistIds.map(id => ({ id, ...NIST_800_53[id] ?? { title: id, description: null, url: null } })),
    cis:  cisIds.map(id => ({ id, ...CIS_V8[id]      ?? { title: id, description: null, url: null } })),
    framework_versions: FRAMEWORK_VERSIONS,
  };
}
