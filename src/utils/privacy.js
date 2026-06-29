/**
 * One-way hash of a zone/account ID for storage keys.
 * Raw IDs never leave the request — only the hash is persisted.
 */
export async function hashId(id) {
  const buf = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(id));
  return Array.from(new Uint8Array(buf)).map(b => b.toString(16).padStart(2, '0')).join('').slice(0, 16);
}
