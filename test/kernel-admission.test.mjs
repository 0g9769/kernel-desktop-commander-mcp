import test from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPairSync, sign } from 'node:crypto';
import { mkdtempSync, writeFileSync, readFileSync, unlinkSync, symlinkSync, chmodSync, rmSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {
  canonicalKernelGrantBytes, getKernelAdmittedToolNames, isKernelToolAdmitted,
  KERNEL_AUDIENCE, KERNEL_GRANT_SCHEMA,
} from '../src/kernel/admission.ts';

const tmp = mkdtempSync(path.join(os.tmpdir(), 'kernel-mcp-grant-'));
const { privateKey, publicKey } = generateKeyPairSync('ed25519');
const publicFile = path.join(tmp, 'owner-public.pem');
const grantFile = path.join(tmp, 'grant.json');
writeFileSync(publicFile, publicKey.export({ type: 'spki', format: 'pem' }), { mode: 0o600 });
test.after(() => rmSync(tmp, { recursive: true, force: true }));
const NOW = Date.now();
const BASE_ENV = {
  KERNEL_MCP_POLICY: 'enforce',
  KERNEL_MCP_DEVICE_ID: 'oppo-a53',
  KERNEL_MCP_GRANT_FILE: grantFile,
  KERNEL_MCP_TRUST_PUBLIC_KEY: publicFile,
};
const payload = (changes = {}) => ({
  schema: KERNEL_GRANT_SCHEMA,
  audience: KERNEL_AUDIENCE,
  deviceId: 'oppo-a53',
  issuedAt: NOW - 1_000,
  expiresAt: NOW + 60_000,
  nonce: 'replay-window-nonce-001',
  tools: ['read_file', 'list_directory'],
  ...changes,
});
function saveGrant(g = payload()) {
  const signature = sign(null, canonicalKernelGrantBytes(g), privateKey).toString('base64');
  writeFileSync(grantFile, JSON.stringify({ ...g, signature }), { mode: 0o600 });
}
const admitted = (name = 'read_file', env = BASE_ENV, now = NOW) =>
  isKernelToolAdmitted(name, env, now);

test('upstream default remains unchanged', () => {
  assert.equal(admitted('start_process', {}), true);
  assert.equal(getKernelAdmittedToolNames({}, NOW), null);
});
test('unknown policy value is denied, not treated as off', () => {
  assert.equal(admitted('read_file', { ...BASE_ENV, KERNEL_MCP_POLICY: 'enforc' }), false);
});
test('missing grant fails closed', () => {
  unlinkSyncIfExists(grantFile);
  assert.equal(admitted(), false);
});
function unlinkSyncIfExists(p) { try { unlinkSync(p); } catch (e) { if (e.code !== 'ENOENT') throw e; } }
test('valid owner signature grants only named tools', () => {
  saveGrant();
  assert.equal(admitted('read_file'), true);
  assert.equal(admitted('list_directory'), true);
  assert.equal(admitted('start_process'), false);
  assert.deepEqual([...getKernelAdmittedToolNames(BASE_ENV, NOW)].sort(), ['list_directory', 'read_file']);
});
test('device binding rejects a copied grant on another worker', () => {
  saveGrant();
  assert.equal(admitted('read_file', { ...BASE_ENV, KERNEL_MCP_DEVICE_ID: 'pixel9a' }), false);
});
test('signature tampering cannot escalate to terminal access', () => {
  saveGrant();
  const g = JSON.parse(readFileSync(grantFile, 'utf8'));
  g.tools.push('start_process');
  writeFileSync(grantFile, JSON.stringify(g));
  assert.equal(admitted('start_process'), false);
  assert.equal(admitted('read_file'), false);
});
test('expiry and revocation take effect at next call', () => {
  saveGrant();
  assert.equal(admitted(), true);
  assert.equal(admitted('read_file', BASE_ENV, NOW + 120_000), false);
  unlinkSync(grantFile);
  assert.equal(admitted(), false);
});
test('expired, future-issued and excessive TTL grants fail closed', () => {
  for (const change of [
    { issuedAt: NOW - 120_000, expiresAt: NOW - 1_000 },
    { issuedAt: NOW + 31_000, expiresAt: NOW + 50_000 },
    { expiresAt: NOW + 600_000 },
  ]) {
    saveGrant(payload(change));
    assert.equal(admitted(), false);
  }
});
test('rejects wildcard tools, duplicate capabilities and extra unsigned fields', () => {
  for (const tools of [['*'], ['read_file', 'read_file']]) {
    saveGrant(payload({ tools }));
    assert.equal(admitted(), false);
  }
  saveGrant();
  const g = JSON.parse(readFileSync(grantFile, 'utf8'));
  g.claimedAdmin = true;
  writeFileSync(grantFile, JSON.stringify(g));
  assert.equal(admitted(), false);
});
test('a substituted trust key cannot validate an old grant', () => {
  saveGrant();
  const fake = generateKeyPairSync('ed25519').publicKey;
  const second = path.join(tmp, 'other.pem');
  writeFileSync(second, fake.export({type:'spki',format:'pem'}), { mode:0o600 });
  assert.equal(admitted('read_file', {...BASE_ENV, KERNEL_MCP_TRUST_PUBLIC_KEY:second}), false);
});
test('policy paths must be absolute, regular, owned and not group writable', () => {
  saveGrant();
  assert.equal(admitted('read_file', {...BASE_ENV, KERNEL_MCP_GRANT_FILE:'./grant.json'}), false);
  if (process.platform !== 'win32') {
    const symlink = path.join(tmp, 'trust-symlink.pem');
    symlinkSync(publicFile, symlink);
    assert.equal(admitted('read_file', {...BASE_ENV, KERNEL_MCP_TRUST_PUBLIC_KEY:symlink}), false);
    chmodSync(publicFile, 0o666);
    assert.equal(admitted(), false);
    chmodSync(publicFile, 0o600);
  }
  assert.equal(admitted(), true);
});
