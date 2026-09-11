/**
 * Signet Verify SDK — website age verification and cross-device Sign-in-with-Signet.
 *
 * ESM / bundler usage (npm):
 *   import { verifyAge, waitForAuthResponse } from 'signet-verify';
 *
 * Script-tag / CDN usage (IIFE bundle exposes `window.Signet`):
 *   <script src="https://cdn.signet.forgesworn.dev/signet-verify.iife.js"></script>
 *   <script>
 *     const result = await Signet.verifyAge('18+');
 *     if (result.verified) { // allow access }
 *   </script>
 */

export interface SignetVerifyResult {
  verified: boolean;
  ageRange: string | null;
  tier: number | null;
  entityType: string | null;
  credentialId: string | null;
  verifierPubkey: string | null;
  /** Whether the verifier is confirmed against a public professional register */
  verifierConfirmed: boolean | null;
  /** Verifier's confirmation method: A (NIP-05 on body domain), B (body-issued), C (cross-verified), D (website), null if unknown */
  verifierMethod: 'A' | 'B' | 'C' | 'D' | null;
  issuedAt: number | null;
  expiresAt: number | null;
  error?: string;
}

export interface SignetVerifyOptions {
  /** Required age range to verify (e.g., '18+', '13-17') */
  requiredAgeRange: string;
  /** Relay URL for cross-device communication */
  relayUrl?: string;
  /** Callback URL for same-device flow */
  callbackUrl?: string;
  /** Custom styling for the verification modal */
  theme?: 'light' | 'dark' | 'auto';
  /** Timeout in milliseconds (default: 120000 — 2 minutes) */
  timeout?: number;
  /**
   * URL of the verification bot that checks verifier credentials against public registers.
   * Default: 'https://verify.signet.forgesworn.dev'
   * Set to null to skip verifier checking (accept any signed credential).
   * Anyone can run their own bot — the URL is configurable, not a central authority.
   */
  verifierCheckUrl?: string | null;
  /**
   * Accept credentials from unconfirmed verifiers.
   * Default: false (safe — only confirmed verifiers pass).
   * Set to true to accept any valid credential regardless of verifier status.
   */
  acceptUnconfirmed?: boolean;
}

/**
 * Canonical types from signet-protocol.
 * Using import type to avoid runtime dependency (this SDK is bundled as IIFE).
 */
import type { VerifyRequest, VerifyResponse } from 'signet-protocol';

/** @deprecated Use VerifyRequest from signet-protocol */
type PresentationRequest = VerifyRequest;

/** @deprecated Use VerifyResponse from signet-protocol */
type PresentationResponse = VerifyResponse;

// Escape HTML special characters to prevent XSS in innerHTML
function escapeHtml(str: string): string {
  return str.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}

// Generate a random request ID
function generateRequestId(): string {
  const bytes = new Uint8Array(16);
  crypto.getRandomValues(bytes);
  return Array.from(bytes, b => b.toString(16).padStart(2, '0')).join('');
}

// Extract a tag value from a Nostr event
function getTagValue(tags: string[][], key: string): string | undefined {
  const tag = tags.find(t => t[0] === key);
  return tag ? tag[1] : undefined;
}

// BIP-340 Schnorr signature verification via @noble/curves (bundled by esbuild)
import { schnorr } from '@noble/curves/secp256k1.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { bytesToHex } from '@noble/hashes/utils.js';

// NIP-44 v2 decrypt for NIP-17 gift-wrap unwrapping (cross-device auth flow)
import { decrypt as nip44Decrypt, getConversationKey } from 'nostr-tools/nip44';

function hexToBytes(hex: string): Uint8Array {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(hex.substr(i * 2, 2), 16);
  }
  return bytes;
}

/**
 * Verify a Nostr event's Schnorr signature (BIP-340).
 * Checks: structural validity, event ID hash, and cryptographic signature.
 */
async function verifyEventSignature(event: PresentationResponse['credential']): Promise<boolean> {
  // Structural validation: check field formats
  if (!event.id || !event.pubkey || !event.sig || !event.tags || event.kind !== 30470) {
    return false;
  }
  // sig must be exactly 128 hex chars (64-byte Schnorr signature)
  if (!/^[0-9a-f]{128}$/i.test(event.sig)) return false;
  // pubkey must be exactly 64 hex chars (32-byte x-only public key)
  if (!/^[0-9a-f]{64}$/i.test(event.pubkey)) return false;
  // id must be exactly 64 hex chars (32-byte SHA-256 hash)
  if (!/^[0-9a-f]{64}$/i.test(event.id)) return false;

  // Field-size bounds
  if (event.tags.length > 100) return false;
  if (event.content.length > 65536) return false;
  if (event.tags.some(t => t.some(v => v.length > 1024))) return false;

  // Required tags must be present
  const tagKeys = event.tags.map(t => t[0]);
  if (!tagKeys.includes('tier')) return false;
  if (!tagKeys.includes('age-range')) return false;
  if (!tagKeys.includes('entity-type')) return false;

  // Verify event ID matches the SHA-256 hash of the serialized event
  const serialized = JSON.stringify([0, event.pubkey, event.created_at, event.kind, event.tags, event.content]);
  const encoder = new TextEncoder();
  const hashBytes = sha256(encoder.encode(serialized));
  const expectedId = bytesToHex(hashBytes);
  if (expectedId !== event.id.toLowerCase()) return false;

  // BIP-340 Schnorr signature verification
  try {
    const sigBytes = hexToBytes(event.sig);
    const idBytes = hexToBytes(event.id);
    const pubkeyBytes = hexToBytes(event.pubkey);
    return schnorr.verify(sigBytes, idBytes, pubkeyBytes);
  } catch {
    return false;
  }
}

// Check if the credential's age range satisfies the required range
function ageRangeSatisfies(credentialRange: string, requiredRange: string): boolean {
  // Simple range matching
  if (credentialRange === requiredRange) return true;
  // '18+' satisfies any adult requirement
  if (credentialRange === '18+' && requiredRange === '18+') return true;
  // Child ranges: credential must exactly match or be within required
  const ranges = ['0-3', '4-7', '8-12', '13-17', '18+'];
  const credIdx = ranges.indexOf(credentialRange);
  const reqIdx = ranges.indexOf(requiredRange);
  if (credIdx === -1 || reqIdx === -1) return false;
  // For '18+' requirement, credential must be '18+'
  if (requiredRange === '18+') return credentialRange === '18+';
  // For child requirements, credential range must match
  return credentialRange === requiredRange;
}

/** Response from the verification bot */
interface VerifierStatus {
  confirmed: boolean;
  method: 'A' | 'B' | 'C' | 'D' | null;
  profession?: string;
  jurisdiction?: string;
}

/**
 * Check a verifier's status against the verification bot.
 * Returns { confirmed, method } or null if the check fails/is skipped.
 */
async function checkVerifierStatus(
  verifierPubkey: string,
  checkUrl: string | null | undefined,
): Promise<VerifierStatus | null> {
  if (checkUrl === null || checkUrl === undefined) return null;
  if (!/^https:\/\//i.test(checkUrl)) return null;
  if (!/^[0-9a-f]{64}$/i.test(verifierPubkey)) return null;

  try {
    const response = await fetch(`${checkUrl}/status/${verifierPubkey}`, {
      signal: AbortSignal.timeout(5000), // 5 second timeout — don't block the UX
    });
    if (!response.ok) return null;

    const data: unknown = await response.json();
    if (typeof data !== 'object' || data === null) return null;

    const obj = data as Record<string, unknown>;
    return {
      confirmed: obj.confirmed === true,
      method: (['A', 'B', 'C', 'D'].includes(obj.method as string) ? obj.method : null) as VerifierStatus['method'],
      profession: typeof obj.profession === 'string' ? obj.profession : undefined,
      jurisdiction: typeof obj.jurisdiction === 'string' ? obj.jurisdiction : undefined,
    };
  } catch {
    // Bot unreachable — return null (unknown), don't block verification
    return null;
  }
}

/**
 * Main verification function.
 * Shows a modal with QR code, waits for the user's app to respond.
 */
export async function verifyAge(requiredAgeRange: string, options?: Partial<SignetVerifyOptions>): Promise<SignetVerifyResult> {
  const VALID_AGE_RANGES = ['0-3', '4-7', '8-12', '13-17', '18+'];
  if (!VALID_AGE_RANGES.includes(requiredAgeRange)) {
    return { verified: false, ageRange: null, tier: null, entityType: null, credentialId: null, verifierPubkey: null, verifierConfirmed: null, verifierMethod: null, issuedAt: null, expiresAt: null, error: 'invalid-age-range' };
  }

  const opts: SignetVerifyOptions = {
    requiredAgeRange,
    relayUrl: options?.relayUrl || 'wss://relay.damus.io',
    theme: options?.theme || 'auto',
    timeout: options?.timeout || 120000,
    verifierCheckUrl: options?.verifierCheckUrl !== undefined ? options.verifierCheckUrl : 'https://verify.signet.forgesworn.dev',
    acceptUnconfirmed: options?.acceptUnconfirmed || false,
    ...options,
  };
  opts.timeout = Math.max(5000, Math.min(opts.timeout ?? 120000, 600000));

  const requestId = generateRequestId();

  const request: PresentationRequest = {
    type: 'signet-verify-request',
    requestId,
    requiredAgeRange: opts.requiredAgeRange,
    relayUrl: opts.relayUrl,
    timestamp: Math.floor(Date.now() / 1000),
  };

  // Encode the request as a URL for QR code
  const requestPayload = JSON.stringify(request);
  const requestBase64 = btoa(requestPayload);

  return new Promise<SignetVerifyResult>((resolve) => {
    // Inject ::backdrop style for the native <dialog> element
    const style = document.createElement('style');
    style.textContent = '#signet-verify-dialog::backdrop{background:rgba(0,0,0,0.7)}';
    document.head.appendChild(style);

    const isDark = opts.theme === 'dark' || (opts.theme === 'auto' && window.matchMedia('(prefers-color-scheme: dark)').matches);
    const bg = isDark ? '#1a1a2e' : '#ffffff';
    const fg = isDark ? '#e0e0e0' : '#1a1a2e';
    const muted = isDark ? '#888' : '#666';

    // Use <dialog> for native focus trap and top-layer placement
    const dialog = document.createElement('dialog');
    dialog.id = 'signet-verify-dialog';
    dialog.style.cssText = `border:none;border-radius:16px;padding:32px;max-width:380px;width:90%;text-align:center;box-shadow:0 20px 60px rgba(0,0,0,0.3);background:${bg};color:${fg};font-family:system-ui,-apple-system,sans-serif;`;

    dialog.innerHTML = `
      <h2 style="margin:0 0 8px;font-size:1.3rem;">Verify your age with Signet</h2>
      <p style="margin:0 0 24px;color:${muted};font-size:0.9rem;">Scan this QR code with your Signet app to prove you are ${escapeHtml(requiredAgeRange)}. No personal data is shared.</p>
      <div id="signet-qr" style="display:flex;justify-content:center;margin-bottom:24px;"></div>
      <p style="margin:0 0 16px;color:${muted};font-size:0.8rem;">Waiting for verification...</p>
      <button id="signet-cancel" style="background:none;border:1px solid ${muted};color:${fg};padding:10px 24px;border-radius:8px;cursor:pointer;font-size:0.9rem;">Cancel</button>
    `;

    document.body.appendChild(dialog);
    dialog.showModal();

    // Generate QR code (simple SVG-based, no dependency)
    const qrContainer = dialog.querySelector<HTMLElement>('#signet-qr');
    if (qrContainer) {
      // For MVP: show the request payload as text that can be copied
      // A proper QR library should be bundled for production
      const qrPlaceholder = document.createElement('div');
      qrPlaceholder.style.cssText = `width:200px;height:200px;background:${isDark ? '#2a2a3e' : '#f0f0f0'};border-radius:8px;display:flex;align-items:center;justify-content:center;font-size:0.75rem;color:${muted};word-break:break-all;padding:12px;`;
      qrPlaceholder.textContent = `signet:verify:${requestBase64.slice(0, 40)}...`;
      qrContainer.appendChild(qrPlaceholder);
    }

    // Listen for response via BroadcastChannel (same-device, request-specific channel)
    const channel = new BroadcastChannel('signet-verify-' + requestId);

    // Cancel handler — scoped to the dialog
    dialog.querySelector<HTMLButtonElement>('#signet-cancel')?.addEventListener('click', () => {
      channel.close();
      dialog.close(); dialog.remove(); style.remove();
      resolve({ verified: false, ageRange: null, tier: null, entityType: null, credentialId: null, verifierPubkey: null, verifierConfirmed: null, verifierMethod: null, issuedAt: null, expiresAt: null, error: 'cancelled' });
    });
    channel.onmessage = async (event) => {
      const data: unknown = event.data;
      if (typeof data !== 'object' || data === null) return;
      const response = data as Partial<PresentationResponse>;
      if (response.type !== 'signet-verify-response' || response.requestId !== requestId) return;
      if (!response.credential || typeof response.credential !== 'object' || !Array.isArray(response.credential.tags)) return;
      const credential = response.credential as PresentationResponse['credential'];

      // Verify the credential
      const valid = await verifyEventSignature(credential);
      const ageRange = getTagValue(credential.tags, 'age-range');
      const tier = getTagValue(credential.tags, 'tier');
      const entityType = getTagValue(credential.tags, 'entity-type');
      const expires = getTagValue(credential.tags, 'expires');

      const satisfied = ageRange ? ageRangeSatisfies(ageRange, opts.requiredAgeRange) : false;

      // Check verifier status against the verification bot
      const verifierStatus = await checkVerifierStatus(credential.pubkey, opts.verifierCheckUrl);
      const verifierConfirmed = verifierStatus?.confirmed ?? null;
      const verifierMethod = verifierStatus?.method ?? null;

      // By default, verified is true only when:
      // 1. Credential signature is valid
      // 2. Age range satisfies requirement
      // 3. Verifier is confirmed (unless acceptUnconfirmed is true)
      const verifierOk = opts.acceptUnconfirmed || verifierConfirmed === true;

      dialog.close(); dialog.remove(); style.remove();
      channel.close();

      const tierValue = tier ? parseInt(tier, 10) : null;
      const expiresValue = expires ? parseInt(expires, 10) : null;

      const nowSec = Math.floor(Date.now() / 1000);
      const notExpired = expiresValue === null || (!isNaN(expiresValue) && expiresValue > nowSec);

      let error: string | undefined;
      if (!valid) error = 'invalid-credential';
      else if (!notExpired) error = 'credential-expired';
      else if (!satisfied) error = 'age-range-not-met';
      else if (!verifierOk) error = verifierConfirmed === false ? 'verifier-not-confirmed' : 'verifier-check-unavailable';

      resolve({
        verified: valid && notExpired && satisfied && verifierOk,
        ageRange: ageRange || null,
        tier: (tierValue !== null && !isNaN(tierValue)) ? tierValue : null,
        entityType: entityType || null,
        credentialId: credential.id,
        verifierPubkey: credential.pubkey,
        verifierConfirmed,
        verifierMethod,
        issuedAt: credential.created_at,
        expiresAt: (expiresValue !== null && !isNaN(expiresValue)) ? expiresValue : null,
        error,
      });
    };

    // Timeout
    setTimeout(() => {
      dialog.close(); dialog.remove(); style.remove();
      channel.close();
      resolve({ verified: false, ageRange: null, tier: null, entityType: null, credentialId: null, verifierPubkey: null, verifierConfirmed: null, verifierMethod: null, issuedAt: null, expiresAt: null, error: 'timeout' });
    }, opts.timeout);
  });
}

// ── Cross-device auth response subscription ──────────────────────────────────

/**
 * Seconds either side of now within which an auth response is accepted.
 *
 * This is the ONLY real deadline in the sign-in flow: a response whose rumor or
 * auth event is older (or newer) than this is dropped. Exported so a consumer
 * can build an honest countdown — `expiresAt = issuedAt + AUTH_FRESHNESS_WINDOW_SEC`
 * — instead of hardcoding 300 and drifting from this library.
 */
export const AUTH_FRESHNESS_WINDOW_SEC = 300;

/**
 * Slack subtracted from `issuedAt` when deriving the relay query window, to
 * absorb clock skew between the consumer and the signer device. Widening the
 * query loosens nothing: every response must still unwrap under this session
 * key, carry this request's session tag, carry a signature over this challenge,
 * match the expected origin, and pass the freshness check above.
 */
const ANCHOR_SKEW_SEC = 60;

/** Options for waiting on a cross-device Sign-in-with-Signet response. */
export interface WaitForAuthOptions {
  /** The challenge (also the `requestId`) sent in the auth URL. 64-char hex. */
  requestId: string;
  /** The `wss://` relay URL the consumer subscribed on. */
  relayUrl: string;
  /** The consumer's ephemeral session private key (32 bytes). Used to NIP-17 unwrap the response. */
  sessionPrivKey: Uint8Array;
  /**
   * The consumer origin (e.g. `https://example.com`). The signed auth event must
   * carry a matching `origin` tag — this prevents a response addressed to a different
   * site from being accepted. Must be supplied verbatim (scheme + host + optional port).
   */
  expectedOrigin: string;
  /**
   * Timeout in milliseconds. Clamped to [5_000, 600_000].
   *
   * Defaults to the remaining validity of the sign-in when `issuedAt` is given
   * — i.e. until `issuedAt + AUTH_FRESHNESS_WINDOW_SEC` — and to 120_000
   * otherwise. Supply it only to give up EARLIER than the response would expire.
   */
  timeout?: number;
  /**
   * Unix **SECONDS**, not milliseconds — `Math.floor(Date.now() / 1000)`. A
   * value more than `AUTH_FRESHNESS_WINDOW_SEC` seconds in the future throws
   * `invalid-issued-at`.
   *
   * The moment this sign-in was issued — when you minted the
   * challenge and opened the auth URL or rendered the QR. This is the anchor
   * everything else derives from; pass it on EVERY call for a given sign-in,
   * including retries and resumes.
   *
   * Why it matters: the relay query window is computed from this. If a wait is
   * restarted — a mobile consumer resuming after the user approved in the signer
   * app, or a retry after a timeout — a window anchored to the restart silently
   * excludes the response published while the consumer was in the background,
   * and that response is never asked for again. Anchoring to issuance fixes it:
   *
   *   const issuedAt = Math.floor(Date.now() / 1000);
   *   // …open the auth URL, user approves in the signer app, page may be suspended…
   *   waitForAuthResponse({ …, issuedAt });
   *
   * The deadline the user is actually racing is
   * `issuedAt + AUTH_FRESHNESS_WINDOW_SEC`. Show it to them.
   */
  issuedAt?: number;
  /**
   * Raw relay query anchor in unix seconds — the low-level escape hatch.
   *
   * Prefer `issuedAt`, which derives this correctly. `since` is honoured for
   * consumers written against 0.5.2 and takes precedence over `issuedAt` when
   * both are supplied. Defaults to 60 seconds before this call when neither is
   * given.
   */
  since?: number;
  /**
   * Aborts the wait and closes its relay subscription.
   *
   * Without this a cancelled attempt — the user tapped Back, or a second attempt
   * started — kept its subscription open until the internal timeout elapsed.
   * Rejects with `aborted`.
   */
  abortSignal?: AbortSignal;
}

/** Full signed Kind-21236 auth event as carried in the AuthResponse. */
export interface SignetAuthEvent {
  id: string;
  pubkey: string;
  kind: 21236;
  created_at: number;
  tags: string[][];
  content: string;
  sig: string;
}

/** Successful auth response — the user's signed proof of login. */
export interface SignetAuthResult {
  /** The user's pubkey (64-char hex x-only) — copy of `authEvent.pubkey` for convenience. */
  pubkey: string;
  /** The verified, signed Kind-21236 auth event — the raw cryptographic proof. */
  authEvent: SignetAuthEvent;
  /** Optional credential included in the response (Signet Login flows). */
  credential?: unknown;
  /**
   * Optional persona handle the user opted to share at approval time.
   * Sanitised: control + bidi characters stripped, capped at 64 chars,
   * empty strings dropped to undefined. Mirrors the `display_name` URL param
   * delivered by the redirect-back flow. Treat as untrusted display content
   * — already sanitised here, but still escape on render per usual.
   */
  displayName?: string;
  /**
   * Optional `bunker://` URI for upgrading the auth-only session to a live signer.
   * The signer device mints a one-shot pairing URI to its own NIP-46 server; the
   * consumer connects to it (passthrough) to sign cross-device. Absent on
   * auth-only flows — the consumer keeps the EphemeralSigner.
   */
  bunkerUri?: string;
  /** Unix timestamp the auth event was signed. */
  createdAt: number;
}

// Compute a NIP-01 event ID: SHA-256 of the canonical serialisation.
function computeNostrEventId(
  event: { pubkey: string; created_at: number; kind: number; tags: string[][]; content: string },
): string {
  const serialised = JSON.stringify([0, event.pubkey, event.created_at, event.kind, event.tags, event.content]);
  const hash = sha256(new TextEncoder().encode(serialised));
  return bytesToHex(hash);
}

// NIP-17 unwrap: kind-1059 wrap → kind-13 seal (verified) → inner rumor event.
// Returns the rumor or null if any step fails (decrypt error, malformed, identity mismatch).
async function unwrapGiftWrap(
  wrap: { pubkey: string; content: string },
  sessionPrivKey: Uint8Array,
): Promise<{ pubkey: string; id: string; kind: number; created_at: number; tags: string[][]; content: string } | null> {
  try {
    // Decrypt wrap → seal
    const wrapConvKey = getConversationKey(sessionPrivKey, wrap.pubkey);
    const sealJson = nip44Decrypt(wrap.content, wrapConvKey);
    const sealParsed: unknown = JSON.parse(sealJson);
    if (typeof sealParsed !== 'object' || sealParsed === null) return null;
    const seal = sealParsed as Record<string, unknown>;

    if (seal.kind !== 13) return null;
    if (typeof seal.pubkey !== 'string' || !/^[0-9a-f]{64}$/i.test(seal.pubkey)) return null;
    if (typeof seal.created_at !== 'number') return null;
    if (!Array.isArray(seal.tags)) return null;
    if (typeof seal.content !== 'string') return null;
    if (typeof seal.id !== 'string' || !/^[0-9a-f]{64}$/i.test(seal.id)) return null;
    if (typeof seal.sig !== 'string' || !/^[0-9a-f]{128}$/i.test(seal.sig)) return null;

    // Verify seal event ID matches its canonical hash (tamper check)
    const expectedSealId = computeNostrEventId({
      pubkey: seal.pubkey,
      created_at: seal.created_at,
      kind: 13,
      tags: seal.tags as string[][],
      content: seal.content,
    });
    if (expectedSealId !== seal.id.toLowerCase()) return null;

    // Verify seal Schnorr signature — proves it came from the claimed sender.
    // (The rumor itself is unsigned per NIP-59; the seal's signature is the identity anchor.)
    const sealSigBytes = hexToBytes(seal.sig);
    const sealIdBytes = hexToBytes(seal.id);
    const sealPubBytes = hexToBytes(seal.pubkey);
    if (!schnorr.verify(sealSigBytes, sealIdBytes, sealPubBytes)) return null;

    // Decrypt seal → rumor
    const sealConvKey = getConversationKey(sessionPrivKey, seal.pubkey);
    const rumorJson = nip44Decrypt(seal.content, sealConvKey);
    const rumorParsed: unknown = JSON.parse(rumorJson);
    if (typeof rumorParsed !== 'object' || rumorParsed === null) return null;
    const rumor = rumorParsed as Record<string, unknown>;

    if (typeof rumor.pubkey !== 'string') return null;
    // Identity binding: rumor sender must equal seal sender.
    if (rumor.pubkey !== seal.pubkey) return null;
    if (typeof rumor.kind !== 'number') return null;
    if (typeof rumor.created_at !== 'number') return null;
    if (!Array.isArray(rumor.tags)) return null;
    if (typeof rumor.content !== 'string') return null;

    // Rumor may or may not carry an id field; compute if absent.
    const rumorId = typeof rumor.id === 'string'
      ? rumor.id
      : computeNostrEventId({
          pubkey: rumor.pubkey,
          created_at: rumor.created_at,
          kind: rumor.kind,
          tags: rumor.tags as string[][],
          content: rumor.content,
        });

    return {
      pubkey: rumor.pubkey,
      id: rumorId,
      kind: rumor.kind,
      created_at: rumor.created_at,
      tags: rumor.tags as string[][],
      content: rumor.content,
    };
  } catch {
    return null;
  }
}

// Sanitise an optional persona handle from an AuthResponse: strip control + bidi
// chars, cap at 64, drop empty. Same character class as signet-app's
// consumer_display_name sanitiser, kept consistent so wire→consumer and
// consumer→wire treat the field identically.
function sanitiseDisplayName(raw: unknown): string | undefined {
  return sanitiseDisplayText(raw, 64);
}

// Shared by anything outside-controlled that a caller may render: the persona
// handle above, and a relay's reason for refusing a subscription.
function sanitiseDisplayText(raw: unknown, max: number): string | undefined {
  if (typeof raw !== 'string') return undefined;
  const cleaned = raw
    .replace(/[\x00-\x1f\x7f-\x9f\u200b-\u200f\u2028-\u202e\u2066-\u2069]/g, '')
    .trim()
    .slice(0, max);
  return cleaned.length > 0 ? cleaned : undefined;
}

/**
 * Wait for a cross-device Sign-in-with-Signet response on a Nostr relay.
 *
 * Consumer workflow: generate a session keypair, put the pubkey in the auth URL
 * via the `sessionPubkey` param alongside `relay`, render the QR, then call this
 * function with the matching private key. When the user approves on their phone,
 * the Signet app publishes a NIP-17 gift-wrapped response to the relay and this
 * function resolves with the verified auth result.
 *
 * Rejects with `Error(message)` where `message` (and `.code`) is one of:
 *   - `'denied'` — user rejected the request
 *   - `'timeout'` — no valid response within the timeout
 *   - `'expired'` — a structurally valid response arrived outside the freshness window
 *   - `'aborted'` — the caller's `abortSignal` fired (or was already aborted)
 *   - `'relay-error'` — WebSocket connection failure
 *   - `'relay-closed'` — WebSocket connection closed
 *   - `'relay-refused'` — the relay CLOSED the subscription (e.g. it demands AUTH); `err.reason` carries its sanitised text
 *   - `'invalid-request-id'` / `'invalid-session-privkey'` / `'invalid-relay-url'` / `'invalid-expected-origin'` / `'invalid-issued-at'` — bad input
 */
export async function waitForAuthResponse(options: WaitForAuthOptions): Promise<SignetAuthResult> {
  type WaitForAuthErrorCode =
    | 'invalid-request-id' | 'invalid-session-privkey' | 'invalid-relay-url'
    | 'invalid-expected-origin' | 'invalid-issued-at'
    | 'denied' | 'timeout' | 'expired' | 'aborted' | 'relay-error' | 'relay-closed' | 'relay-refused';

  const authError = (code: WaitForAuthErrorCode): Error => {
    const err = new Error(code) as Error & { code: WaitForAuthErrorCode };
    err.code = code;
    return err;
  };

  if (!/^[0-9a-f]{64}$/i.test(options.requestId)) {
    throw authError('invalid-request-id');
  }
  if (!(options.sessionPrivKey instanceof Uint8Array) || options.sessionPrivKey.length !== 32) {
    throw authError('invalid-session-privkey');
  }
  if (!/^wss:\/\//i.test(options.relayUrl) && !/^ws:\/\/(localhost|127\.0\.0\.1)([:\/]|$)/i.test(options.relayUrl)) {
    throw authError('invalid-relay-url');
  }
  if (typeof options.expectedOrigin !== 'string' || options.expectedOrigin.length === 0) {
    throw authError('invalid-expected-origin');
  }
  if (Number.isFinite(options.issuedAt) && (options.issuedAt as number) > Math.floor(Date.now() / 1000) + AUTH_FRESHNESS_WINDOW_SEC) {
    throw authError('invalid-issued-at');
  }

  const sessionPubkey = bytesToHex(schnorr.getPublicKey(options.sessionPrivKey));
  // Default to "wait as long as the response could still be accepted". A flat
  // 120s default gave up while a response was valid for another three minutes,
  // and with a resume the caller then had nothing left to retry against. An
  // explicit timeout still wins, for a caller that wants to give up sooner.
  const derivedTimeoutMs = Number.isFinite(options.issuedAt)
    ? (Math.floor(options.issuedAt as number) + AUTH_FRESHNESS_WINDOW_SEC) * 1000 - Date.now()
    : 120000;
  const timeout = Math.max(5000, Math.min(options.timeout ?? derivedTimeoutMs, 600000));
  const requestIdLower = options.requestId.toLowerCase();
  const expectedOrigin = options.expectedOrigin;

  // One anchor, derived once at call entry — never inside ws.onopen, or a
  // reconnect after a background pause re-anchors past the response. Precedence:
  // explicit `since` (escape hatch) > derived from `issuedAt` > legacy default.
  const since = Number.isFinite(options.since)
    ? Math.floor(options.since as number)
    : Number.isFinite(options.issuedAt)
      ? Math.floor(options.issuedAt as number) - ANCHOR_SKEW_SEC
      : Math.floor(Date.now() / 1000) - ANCHOR_SKEW_SEC;

  // True once the sign-in's own validity window has elapsed — distinct from
  // `sawExpired`, which only fires when a STALE response was actually seen.
  // Without this, a consumer who simply never got a response before
  // issuedAt + AUTH_FRESHNESS_WINDOW_SEC was told `timeout`, and the README's own
  // advice ("retry with the same issuedAt on timeout") is dead on arrival there —
  // the derived timeout for that retry is already <= 0, clamps to 5s, and fails
  // again immediately. 1s tolerance absorbs timer-firing granularity.
  const pastValidity = (): boolean =>
    Number.isFinite(options.issuedAt) &&
    Date.now() >= (Math.floor(options.issuedAt as number) + AUTH_FRESHNESS_WINDOW_SEC) * 1000 - 1000;

  return new Promise<SignetAuthResult>((resolve, reject) => {
    const subId = `sa-${Math.random().toString(36).slice(2, 12)}`;
    let settled = false;
    // Set when a response that was structurally valid for THIS challenge arrived
    // outside the freshness window. Reported on settle rather than on sight: a
    // relay may serve an unrelated replay, and that must not abort a wait a
    // genuine response could still satisfy.
    let sawExpired = false;
    let ws: WebSocket | undefined;
    let retryTimer: ReturnType<typeof setTimeout> | undefined;
    const deadline = Date.now() + timeout;

    const settle = (action: () => void): void => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      clearTimeout(retryTimer);
      if (typeof document !== 'undefined') document.removeEventListener('visibilitychange', onVisible);
      options.abortSignal?.removeEventListener('abort', onAbort);
      try { ws?.close(); } catch { /* ignore */ }
      action();
    };

    // Every give-up says the same thing: `expired` if this sign-in is over,
    // `timeout` if the wait stopped early. One helper, because there are three
    // give-up paths — the timer, a resume, and a reconnect — and a copy that
    // drifted once already reported `timeout` on the mobile reconnect path.
    const giveUp = (): void =>
      settle(() => reject(authError(sawExpired || pastValidity() ? 'expired' : 'timeout')));

    const timer = setTimeout(() => {
      giveUp();
    }, timeout);

    const subscribe = () => {
      // `since` comes from the enclosing scope so every (re)connection asks for
      // the same window — see the `since` option.
      if (!settled && ws?.readyState === 1) {
        ws.send(JSON.stringify(['REQ', subId, { kinds: [1059], '#p': [sessionPubkey], since }]));
      }
    };
    const onVisible = () => {
      // Replay the stored response after switching back from a native signer.
      // The original challenge, origin, signatures and freshness checks still apply.
      if (settled || document.visibilityState !== 'visible') return;
      if (Date.now() >= deadline) return giveUp();
      if (!ws || ws.readyState >= 2) connect();
      else subscribe();
    };
    if (typeof document !== 'undefined') document.addEventListener('visibilitychange', onVisible);

    const onMessage = async (msgEvent: MessageEvent) => {
      if (settled) return;
      let msg: unknown;
      try {
        msg = JSON.parse(typeof msgEvent.data === 'string' ? msgEvent.data : '');
      } catch {
        return;
      }
      if (!Array.isArray(msg)) return;
      if (msg[0] === 'CLOSED' && msg[1] === subId) {
        // The relay refused this subscription outright — relay.damus.io closes
        // kind-1059 #p reads with "auth-required". Retrying the same filter here
        // gets the same answer, so say so now instead of waiting silently to
        // expiry while the approval sits on the relay. `reason` is the relay's
        // own text, sanitised because callers may display it.
        const reason = sanitiseDisplayText(msg[2], 200);
        settle(() => {
          const err = authError('relay-refused') as Error & { reason?: string };
          if (reason) err.reason = reason;
          reject(err);
        });
        return;
      }
      if (msg[0] !== 'EVENT' || msg[1] !== subId) return;
      const wrap = msg[2];
      if (typeof wrap !== 'object' || wrap === null) return;
      const w = wrap as Record<string, unknown>;
      if (w.kind !== 1059 || typeof w.pubkey !== 'string' || typeof w.content !== 'string') return;

      const rumor = await unwrapGiftWrap({ pubkey: w.pubkey, content: w.content }, options.sessionPrivKey);
      if (!rumor || rumor.kind !== 29999) return;

      const sessionTag = rumor.tags.find(t => t[0] === 'session');
      if (!sessionTag || sessionTag[1] !== requestIdLower) return;

      const statusTag = rumor.tags.find(t => t[0] === 'status');
      if (statusTag?.[1] === 'rejected') {
        settle(() => reject(authError('denied')));
        return;
      }
      if (statusTag?.[1] !== 'approved') return;

      // Freshness check — protects against stale replays the relay might serve.
      const ageSec = Math.abs(Date.now() / 1000 - rumor.created_at);
      if (ageSec > AUTH_FRESHNESS_WINDOW_SEC) {
        sawExpired = true;
        return;
      }

      let inner: Record<string, unknown> | null;
      try {
        const parsed: unknown = JSON.parse(rumor.content);
        if (typeof parsed !== 'object' || parsed === null) return;
        inner = parsed as Record<string, unknown>;
      } catch {
        return;
      }
      if (inner.type !== 'signet-auth-response') return;
      if (inner.requestId !== requestIdLower) return;

      // Extract and validate the embedded signed kind-21236 auth event
      if (typeof inner.authEvent !== 'object' || inner.authEvent === null) return;
      const ae = inner.authEvent as Record<string, unknown>;

      if (typeof ae.id !== 'string' || !/^[0-9a-f]{64}$/i.test(ae.id)) return;
      if (typeof ae.pubkey !== 'string' || !/^[0-9a-f]{64}$/i.test(ae.pubkey)) return;
      if (typeof ae.sig !== 'string' || !/^[0-9a-f]{128}$/i.test(ae.sig)) return;
      if (ae.kind !== 21236) return;
      if (typeof ae.created_at !== 'number') return;
      if (!Array.isArray(ae.tags)) return;
      if (typeof ae.content !== 'string') return;
      // Identity binding: the signer of the authEvent must be the sender of the rumor
      // (both are the user, wrapped and unwrapped versions of the same identity).
      if ((ae.pubkey as string).toLowerCase() !== rumor.pubkey.toLowerCase()) return;

      // Verify the authEvent's id matches its canonical SHA-256 hash (tamper detection)
      const expectedAuthEventId = computeNostrEventId({
        pubkey: ae.pubkey as string,
        created_at: ae.created_at as number,
        kind: 21236,
        tags: ae.tags as string[][],
        content: ae.content as string,
      });
      if (expectedAuthEventId !== (ae.id as string).toLowerCase()) return;

      // Verify the authEvent's Schnorr signature over its id with its claimed pubkey
      let sigValid = false;
      try {
        const sigBytes = hexToBytes(ae.sig as string);
        const idBytes = hexToBytes(ae.id as string);
        const pubBytes = hexToBytes(ae.pubkey as string);
        sigValid = schnorr.verify(sigBytes, idBytes, pubBytes);
      } catch {
        sigValid = false;
      }
      if (!sigValid) return;

      // Validate the challenge and origin tags on the authEvent
      const aeTags = ae.tags as string[][];
      const challengeTag = aeTags.find(t => Array.isArray(t) && t[0] === 'challenge');
      if (!challengeTag || typeof challengeTag[1] !== 'string' || challengeTag[1].toLowerCase() !== requestIdLower) return;
      const originTag = aeTags.find(t => Array.isArray(t) && t[0] === 'origin');
      if (!originTag || originTag[1] !== expectedOrigin) return;

      // Freshness check on the auth event itself (the user's signature timestamp)
      const authEventAgeSec = Math.abs(Date.now() / 1000 - (ae.created_at as number));
      if (authEventAgeSec > AUTH_FRESHNESS_WINDOW_SEC) {
        sawExpired = true;
        return;
      }

      const verifiedAuthEvent: SignetAuthEvent = {
        id: (ae.id as string).toLowerCase(),
        pubkey: (ae.pubkey as string).toLowerCase(),
        kind: 21236,
        created_at: ae.created_at as number,
        tags: aeTags,
        content: ae.content as string,
        sig: ae.sig as string,
      };

      const sanitisedDisplayName = sanitiseDisplayName(inner.displayName);

      // Optional bunker:// URI for the auth-only → live-signer upgrade. The signer
      // device mints a one-shot pairing URI to its own NIP-46 server; the consumer
      // connects to it (signer passthrough) to gain signing capability cross-device.
      // Accept only a well-formed bunker URI; anything else is ignored (stays
      // auth-only, exactly as before this field existed).
      const bunkerUri = (typeof inner.bunkerUri === 'string' && /^bunker:\/\//i.test(inner.bunkerUri))
        ? inner.bunkerUri
        : undefined;

      settle(() => resolve({
        pubkey: verifiedAuthEvent.pubkey,
        authEvent: verifiedAuthEvent,
        credential: inner.credential,
        ...(sanitisedDisplayName !== undefined ? { displayName: sanitisedDisplayName } : {}),
        ...(bunkerUri !== undefined ? { bunkerUri } : {}),
        createdAt: verifiedAuthEvent.created_at,
      }));
    };

    const retryOrFail = (reason: 'relay-error' | 'relay-closed') => {
      if (settled) return;
      if (typeof document === 'undefined') return settle(() => reject(authError(reason)));
      clearTimeout(retryTimer);
      // Android may close a background tab's socket. Retry on return, using
      // the same session and original filter, within the original timeout.
      if (document.visibilityState === 'visible') retryTimer = setTimeout(connect, 1000);
    };
    function connect() {
      if (settled) return;
      clearTimeout(retryTimer);
      if (Date.now() >= deadline) return giveUp();
      const previous = ws;
      ws = undefined;
      try { previous?.close(); } catch { /* already closed */ }
      try {
        const socket = new WebSocket(options.relayUrl);
        ws = socket;
        socket.onopen = subscribe;
        socket.onmessage = onMessage;
        socket.onerror = () => { if (ws === socket) retryOrFail('relay-error'); };
        socket.onclose = () => { if (ws === socket) retryOrFail('relay-closed'); };
      } catch {
        retryOrFail('relay-error');
      }
    }

    // Checked here — after onVisible exists — rather than up near `timer`:
    // settle() reaches back into onVisible via document.removeEventListener,
    // so settling any earlier (including this already-aborted short-circuit)
    // would reference onVisible before its `const` declaration had run.
    const onAbort = () => settle(() => reject(authError('aborted')));
    if (options.abortSignal?.aborted) {
      // Nothing to tear down yet — settle before a socket is ever opened.
      settle(() => reject(authError('aborted')));
      return;
    }
    options.abortSignal?.addEventListener('abort', onAbort, { once: true });

    connect();
  });
}

// Auto-attach to window for script-tag usage
if (typeof window !== 'undefined') {
  (window as any).Signet = { verifyAge, waitForAuthResponse };
}
