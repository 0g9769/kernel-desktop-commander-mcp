/**
 * Optional KERNEL+ admission gate. Default upstream mode is unchanged.
 * Enforced mode requires an Ed25519-signed, device-bound, short-lived grant.
 * This does not authenticate the network transport or replace OS permissions.
 */
import { createPublicKey, verify } from 'node:crypto';
import { lstatSync, readFileSync } from 'node:fs';
import path from 'node:path';

export const KERNEL_AUDIENCE = 'kernel-desktop-commander-mcp';
export const KERNEL_GRANT_SCHEMA = 'kernel.mcp.grant.v1';
const MAX_GRANT_MS = 300_000;
const SKEW_MS = 30_000;
const FIELDS = ['schema','audience','deviceId','issuedAt','expiresAt','nonce','tools'];
export interface KernelGrantPayload {
  schema: typeof KERNEL_GRANT_SCHEMA;
  audience: typeof KERNEL_AUDIENCE;
  deviceId: string;
  issuedAt: number;
  expiresAt: number;
  nonce: string;
  tools: string[];
}
export interface KernelSignedGrant extends KernelGrantPayload { signature: string }

export function canonicalKernelGrantBytes(g: KernelGrantPayload): Buffer {
  return Buffer.from(JSON.stringify({
    schema:g.schema, audience:g.audience, deviceId:g.deviceId,
    issuedAt:g.issuedAt, expiresAt:g.expiresAt, nonce:g.nonce, tools:g.tools,
  }), 'utf8');
}
function readProtected(file: string | undefined, max: number): string {
  if (!file || !path.isAbsolute(file)) throw Error('invalid policy path');
  const st = lstatSync(file);
  if (!st.isFile() || st.size < 1 || st.size > max) throw Error('invalid policy file');
  if (process.platform !== 'win32') {
    if ((st.mode & 0o022) !== 0) throw Error('writable policy file');
    if (typeof process.getuid === 'function' && st.uid !== process.getuid()) throw Error('unowned policy file');
  }
  return readFileSync(file,'utf8');
}
function validGrant(value: unknown, device: string, now: number): value is KernelSignedGrant {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return false;
  const g = value as Record<string, unknown>;
  const keys = [...FIELDS,'signature'];
  if (Object.keys(g).length !== keys.length || keys.some(k=>!Object.prototype.hasOwnProperty.call(g,k))) return false;
  if (g.schema !== KERNEL_GRANT_SCHEMA || g.audience !== KERNEL_AUDIENCE || g.deviceId !== device) return false;
  if (!Number.isSafeInteger(g.issuedAt) || !Number.isSafeInteger(g.expiresAt)) return false;
  const start=g.issuedAt as number, end=g.expiresAt as number;
  if (start > now+SKEW_MS || end <= now || end <= start || end-start > MAX_GRANT_MS) return false;
  if (typeof g.nonce !== 'string' || !/^[A-Za-z0-9_-]{16,128}$/.test(g.nonce)) return false;
  if (!Array.isArray(g.tools) || g.tools.length<1 || g.tools.length>128) return false;
  if (g.tools.some(t=>typeof t!=='string' || !/^[a-z][a-z0-9_]{0,79}$/.test(t))) return false;
  if (new Set(g.tools).size !== g.tools.length) return false;
  if (typeof g.signature!=='string' || !/^[A-Za-z0-9+/]{86}==$/.test(g.signature)) return false;
  return true;
}

/**
 * null = upstream mode; empty Set = enforced but denied. Re-read on every call
 * so grant expiry, removal and key rotation are immediately effective.
 */
export function getKernelAdmittedToolNames(
  env: NodeJS.ProcessEnv=process.env, now: number=Date.now()
): Set<string> | null {
  const mode=env.KERNEL_MCP_POLICY ?? 'off';
  if (mode === 'off') return null;
  if (mode !== 'enforce') return new Set();
  try {
    const device=env.KERNEL_MCP_DEVICE_ID;
    if (!device || !/^[A-Za-z0-9_.:-]{3,128}$/.test(device)) return new Set();
    const grant: unknown=JSON.parse(readProtected(env.KERNEL_MCP_GRANT_FILE,16384));
    if (!validGrant(grant,device,now)) return new Set();
    const key=createPublicKey(readProtected(env.KERNEL_MCP_TRUST_PUBLIC_KEY,4096));
    if (key.asymmetricKeyType!=='ed25519') return new Set();
    const signature=Buffer.from(grant.signature,'base64');
    if (signature.length!==64 || signature.toString('base64')!==grant.signature) return new Set();
    if (!verify(null,canonicalKernelGrantBytes(grant),key,signature)) return new Set();
    return new Set(grant.tools);
  } catch {
    // No secret file paths, raw tokens, or error details in MCP responses.
    return new Set();
  }
}
export function isKernelToolAdmitted(
  name: string, env: NodeJS.ProcessEnv=process.env, now: number=Date.now()
): boolean {
  const allowed=getKernelAdmittedToolNames(env,now);
  return allowed===null || allowed.has(name);
}
