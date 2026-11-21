# KERNEL+ Desktop Commander: signed tool admission v1

**Scope:** A local-first, opt-in admission policy for the existing Desktop Commander MCP tool catalogue. It is not a second MCP gateway, an automatic device-root escalation mechanism, a network authentication scheme, or a replacement for OS permissions.

## Modes

- **Unconfigured / `KERNEL_MCP_POLICY=off`:** identical tool admission to the upstream release. Useful for development; **not** production enforcement.
- **`KERNEL_MCP_POLICY=enforce`:** advertise and execute only the exact tools allowed by a currently valid, owner-signed, device-bound grant.
- **Any other policy string:** deny all tools. Missing/corrupted/expired/key-mismatched grants deny all tools. Revocation takes effect at the next list/call operation.
- No automatic hosted fallback, remote API calls, paid credits, telemetry collectors or system-wide changes are added by this feature.

## Environment on the worker

```text
KERNEL_MCP_POLICY=enforce
KERNEL_MCP_DEVICE_ID=oppo-a53
KERNEL_MCP_TRUST_PUBLIC_KEY=/absolute/protected/owner-ed25519.pub.pem
KERNEL_MCP_GRANT_FILE=/absolute/protected/current-grant.json
```

Both file paths must be absolute paths to **regular files** (not symlinks) with bounded sizes; on POSIX systems they must be owned by the running user and not group/other writable. Never put the Ed25519 **private** signing key on a worker or in Git. Only the owner's **public** verification key and the short-lived signed grant belong on the worker. The owner-controlled issuer distributes the signed grant over an already authenticated channel.

Do not enable enforcement until the operator has issued a signed grant covering the necessary recovery tools. Changing this environment on a running server requires a restart; swapping or removing the grant or public key does not.

## Grant wire contract

```json
{
  "schema": "kernel.mcp.grant.v1",
  "audience": "kernel-desktop-commander-mcp",
  "deviceId": "oppo-a53",
  "issuedAt": 1795000000000,
  "expiresAt": 1795000060000,
  "nonce": "unique-nonce-per-issued-grant",
  "tools": ["read_file", "list_directory"],
  "signature": "<base64-encoded-64-byte-Ed25519-signature>"
}
```

The illustration above contains fictitious timestamps and **is not a valid grant**. The issuer signs the UTF-8 bytes of compact JSON with **exactly** the fields `schema`, `audience`, `deviceId`, `issuedAt`, `expiresAt`, `nonce`, `tools` in that order, excluding `signature`; no extra fields are accepted. Use `canonicalKernelGrantBytes` in `src/kernel/admission.ts` as the canonical implementation. Time fields are Unix milliseconds. Validity must be at most five minutes. An issue time more than 30 seconds in the future, or an expired lease, is denied. Names must match exact MCP tools; wildcards and duplicates are invalid. The tool name set does not grant broader filesystem paths or bypass existing Desktop Commander access controls.

The server independently checks the grant when listing tools **and** immediately before every tool dispatch, including remote requests and UI-originated calls. The denial is a fixed `KERNEL_MCP_ADMISSION_DENIED` response with no secrets or policy-file details.

## Boundary and remaining requirements

1. This is **device-scoped capability admission**, not end-to-end client identity verification. A local process with access to the MCP server may consume the granted capabilities until expiry. Production remote use additionally requires an independently authenticated transport, agent identity binding, replay controls, protected keys, fenced writer lease and audit receipts.
2. The existing Desktop Commander file/path restrictions, command block rules, remote device policies and login controls still apply; the signed grant is a further restriction, never an expansion.
3. The fork's inherited GitHub-hosted Actions workflows must stay disabled under ZERO_SPEND. Use authorised self-hosted runners only for release verification. Do not publish until typecheck, existing tests, integration and physical-device acceptance pass.
4. The inherited upstream package contains its own telemetry/configuration paths. This patch does **not** claim to disable every outbound connection; a separate network-egress and privacy audit is required before production.
5. The owner can revoke access immediately by deleting the grant file; recovery requires a new valid signature or a deliberate operator-controlled change to local policy. Do not allow an agent to edit its own trust root or policy files via an authorised write capability.

## Local offline tests

```bash
node --experimental-strip-types --test test/kernel-admission.test.mjs
```

Tests use temporary in-memory Ed25519 keys and files and make no network calls. They cover default compatibility, reject-on-unknown-policy, valid grant scope, forged grant rejection, device mismatch, expiry, revocation, signature tampering, duplicate/wildcard rejection, malicious additional fields, key substitution, path validation and permission checks. This is a source-level security test, **not** proof of live networked agent enrolment.

## Next verified stages

- Integrate the owner-controlled issuer and trust-root registry with the canonical KERNEL+ gateway, rather than minting a new identity subsystem in this fork.
- Bind a verified agent principal and unique request to each authorised operation, including protected write scopes and independently signed receipts.
- Add self-hosted TypeScript build / original-project regression, authenticated remote transport acceptance on Pixel 9a/S21/A53/ASUS, crash recovery and least-privilege negative tests before any production install.
