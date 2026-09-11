import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { waitForAuthResponse, AUTH_FRESHNESS_WINDOW_SEC } from '../src/signet-verify';
import { getConversationKey, encrypt as nip44Encrypt } from 'nostr-tools/nip44';
import { finalizeEvent, generateSecretKey } from 'nostr-tools/pure';
import { schnorr } from '@noble/curves/secp256k1.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { bytesToHex } from '@noble/hashes/utils.js';

// ── Mock WebSocket ───────────────────────────────────────────────────────────
// Drives onopen automatically, lets tests push messages via deliver().

interface MockWs {
  url: string;
  onopen: (() => void) | null;
  onmessage: ((e: { data: string }) => void) | null;
  onerror: (() => void) | null;
  onclose: (() => void) | null;
  readyState: number;
  sent: string[];
  close: () => void;
  send: (data: string) => void;
  deliver: (event: unknown) => void;
  deliverRaw: (msg: unknown[]) => void;
  fireError: () => void;
}

let lastWs: MockWs | null = null;

function makeMockWebSocket(): typeof WebSocket {
  const ctor = function (this: MockWs, url: string) {
    this.url = url;
    this.onopen = null;
    this.onmessage = null;
    this.onerror = null;
    this.onclose = null;
    this.readyState = 0;
    this.sent = [];
    this.send = (data: string) => { this.sent.push(data); };
    this.close = () => { this.readyState = 3; };
    const getSubId = (): string => {
      const req = this.sent.find(s => s.startsWith('["REQ"'));
      if (!req) return '';
      const parsed = JSON.parse(req);
      return parsed[1];
    };
    this.deliver = (event: unknown) => {
      const subId = getSubId();
      this.onmessage?.({ data: JSON.stringify(['EVENT', subId, event]) });
    };
    this.deliverRaw = (msg: unknown[]) => {
      this.onmessage?.({ data: JSON.stringify(msg) });
    };
    this.fireError = () => { this.onerror?.(); };
    lastWs = this;
    setTimeout(() => { this.readyState = 1; this.onopen?.(); }, 0);
  } as unknown as typeof WebSocket;
  return ctor;
}

beforeEach(() => {
  lastWs = null;
  (globalThis as unknown as { WebSocket: typeof WebSocket }).WebSocket = makeMockWebSocket();
});

afterEach(() => {
  vi.restoreAllMocks();
});

// ── Fixture builder ──────────────────────────────────────────────────────────
// Produces a well-formed NIP-17 gift-wrap of a kind-29999 event whose content
// is an AuthResponse with an embedded signed kind-21236 auth event.

function computeId(evt: { pubkey: string; created_at: number; kind: number; tags: string[][]; content: string }): string {
  const ser = JSON.stringify([0, evt.pubkey, evt.created_at, evt.kind, evt.tags, evt.content]);
  return bytesToHex(sha256(new TextEncoder().encode(ser)));
}

function buildAuthGiftWrap(args: {
  userPrivKey: Uint8Array;
  sessionPubkeyHex: string;
  requestId: string;
  origin: string;
  status?: 'approved' | 'rejected';
  /** Tamper switches for negative tests */
  tamperAuthEventSig?: boolean;
  tamperAuthEventId?: boolean;
  tamperChallengeTag?: string;
  tamperOriginTag?: string;
  tamperAuthEventPubkey?: string;
  staleAuthEventCreatedAt?: number;
  omitAuthEvent?: boolean;
  /** When set, included in the AuthResponse JSON. Pass `'__SKIP__'` to omit. */
  displayName?: string;
  /** When set, included as a non-string value to test type-rejection. */
  displayNameNonString?: unknown;
}) {
  const userPubkeyHex = bytesToHex(schnorr.getPublicKey(args.userPrivKey));
  const status = args.status ?? 'approved';

  // ── Build a signed kind-21236 auth event ──
  const challengeTagValue = args.tamperChallengeTag ?? args.requestId;
  const originTagValue = args.tamperOriginTag ?? args.origin;
  const aeCreatedAt = args.staleAuthEventCreatedAt ?? Math.floor(Date.now() / 1000);

  const signedAuthEvent = finalizeEvent({
    kind: 21236,
    created_at: aeCreatedAt,
    tags: [['challenge', challengeTagValue], ['origin', originTagValue]],
    content: '',
  }, args.userPrivKey);

  // Apply tampers AFTER signing so the tampered fields won't pass verification
  const authEventForWrap: Record<string, unknown> = { ...signedAuthEvent };
  if (args.tamperAuthEventSig) authEventForWrap.sig = 'f'.repeat(128);
  if (args.tamperAuthEventId) authEventForWrap.id = 'f'.repeat(64);
  if (args.tamperAuthEventPubkey) authEventForWrap.pubkey = args.tamperAuthEventPubkey;

  // ── Build the AuthResponse JSON ──
  const authResponse: Record<string, unknown> = {
    type: 'signet-auth-response',
    requestId: args.requestId,
  };
  if (!args.omitAuthEvent) {
    authResponse.authEvent = authEventForWrap;
  }
  if (args.displayName !== undefined) {
    authResponse.displayName = args.displayName;
  }
  if (args.displayNameNonString !== undefined) {
    authResponse.displayName = args.displayNameNonString;
  }

  // ── Build the rumor (kind-29999) ──
  const rumorTemplate = {
    pubkey: userPubkeyHex,
    created_at: Math.floor(Date.now() / 1000),
    kind: 29999,
    tags: [['session', args.requestId], ['status', status]] as string[][],
    content: JSON.stringify(authResponse),
  };
  const rumor = { ...rumorTemplate, id: computeId(rumorTemplate) };

  // ── Seal + wrap (standard NIP-17) ──
  const userConvKey = getConversationKey(args.userPrivKey, args.sessionPubkeyHex);
  const encryptedRumor = nip44Encrypt(JSON.stringify(rumor), userConvKey);
  const seal = finalizeEvent({
    kind: 13,
    created_at: Math.floor(Date.now() / 1000) - 300,
    tags: [],
    content: encryptedRumor,
  }, args.userPrivKey);

  const ephSk = generateSecretKey();
  const ephConvKey = getConversationKey(ephSk, args.sessionPubkeyHex);
  const encryptedSeal = nip44Encrypt(JSON.stringify(seal), ephConvKey);
  return finalizeEvent({
    kind: 1059,
    created_at: Math.floor(Date.now() / 1000),
    tags: [['p', args.sessionPubkeyHex]],
    content: encryptedSeal,
  }, ephSk);
}

// ── Test helpers ─────────────────────────────────────────────────────────────

function setupSession() {
  const sessionPrivKey = generateSecretKey();
  const sessionPubkeyHex = bytesToHex(schnorr.getPublicKey(sessionPrivKey));
  const userPrivKey = generateSecretKey();
  const userPubkeyHex = bytesToHex(schnorr.getPublicKey(userPrivKey));
  return { sessionPrivKey, sessionPubkeyHex, userPrivKey, userPubkeyHex };
}

const DEFAULT_ORIGIN = 'https://example.com';

// ── Tests ────────────────────────────────────────────────────────────────────

describe('waitForAuthResponse — input validation', () => {
  it('throws on invalid requestId', async () => {
    const sessionPrivKey = generateSecretKey();
    await expect(waitForAuthResponse({
      requestId: 'too-short', relayUrl: 'wss://relay', sessionPrivKey, expectedOrigin: DEFAULT_ORIGIN,
    })).rejects.toThrow('invalid-request-id');
  });

  it('throws on non-32-byte session privkey', async () => {
    await expect(waitForAuthResponse({
      requestId: 'a'.repeat(64), relayUrl: 'wss://relay', sessionPrivKey: new Uint8Array(31), expectedOrigin: DEFAULT_ORIGIN,
    })).rejects.toThrow('invalid-session-privkey');
  });

  it('throws on non-wss relay URL', async () => {
    const sessionPrivKey = generateSecretKey();
    await expect(waitForAuthResponse({
      requestId: 'a'.repeat(64), relayUrl: 'https://example.com', sessionPrivKey, expectedOrigin: DEFAULT_ORIGIN,
    })).rejects.toThrow('invalid-relay-url');
  });

  it('throws on missing expectedOrigin', async () => {
    const sessionPrivKey = generateSecretKey();
    await expect(waitForAuthResponse({
      requestId: 'a'.repeat(64), relayUrl: 'wss://relay', sessionPrivKey, expectedOrigin: '',
    })).rejects.toThrow('invalid-expected-origin');
  });

  it('accepts ws://localhost', async () => {
    const sessionPrivKey = generateSecretKey();
    const promise = waitForAuthResponse({
      requestId: 'a'.repeat(64), relayUrl: 'ws://localhost:7777', sessionPrivKey, expectedOrigin: DEFAULT_ORIGIN, timeout: 5000,
    });
    promise.catch(() => { /* ignore */ });
    await new Promise(r => setTimeout(r, 10));
    expect(lastWs?.url).toBe('ws://localhost:7777');
    lastWs?.fireError();
    await expect(promise).rejects.toThrow('relay-error');
  });
});

describe('waitForAuthResponse — issuedAt unit validation', () => {
  it('rejects an issuedAt given in milliseconds', async () => {
    const { sessionPrivKey } = setupSession();
    await expect(waitForAuthResponse({
      requestId: '1'.repeat(64), relayUrl: 'wss://r.test', sessionPrivKey,
      expectedOrigin: DEFAULT_ORIGIN, issuedAt: Date.now(),
    })).rejects.toThrow('invalid-issued-at');
  });

  it('rejects an issuedAt more than AUTH_FRESHNESS_WINDOW_SEC in the future', async () => {
    const { sessionPrivKey } = setupSession();
    const issuedAt = Math.floor(Date.now() / 1000) + 3600;
    await expect(waitForAuthResponse({
      requestId: '2'.repeat(64), relayUrl: 'wss://r.test', sessionPrivKey,
      expectedOrigin: DEFAULT_ORIGIN, issuedAt,
    })).rejects.toThrow('invalid-issued-at');
  });

  it('accepts an issuedAt with a small forward clock-skew tolerance', async () => {
    const { sessionPrivKey } = setupSession();
    const issuedAt = Math.floor(Date.now() / 1000) + 10;
    const promise = waitForAuthResponse({
      requestId: '3'.repeat(64), relayUrl: 'wss://r.test', sessionPrivKey,
      expectedOrigin: DEFAULT_ORIGIN, timeout: 5000, issuedAt,
    });
    promise.catch(() => { /* times out; not the point of this test */ });
    await new Promise(r => setTimeout(r, 10));
    lastWs!.fireError();
    await promise.catch(() => { /* settled */ });
  });
});

describe('waitForAuthResponse — happy path', () => {
  it('resolves with the verified auth event for a valid approved response', async () => {
    const { sessionPrivKey, sessionPubkeyHex, userPrivKey, userPubkeyHex } = setupSession();
    const requestId = 'b'.repeat(64);

    const promise = waitForAuthResponse({
      requestId, relayUrl: 'wss://r.test', sessionPrivKey, expectedOrigin: DEFAULT_ORIGIN, timeout: 5000,
    });

    await new Promise(r => setTimeout(r, 10));
    const wrap = buildAuthGiftWrap({ userPrivKey, sessionPubkeyHex, requestId, origin: DEFAULT_ORIGIN });
    lastWs!.deliver(wrap);

    const result = await promise;
    expect(result.pubkey).toBe(userPubkeyHex);
    expect(result.authEvent.kind).toBe(21236);
    expect(result.authEvent.id).toMatch(/^[0-9a-f]{64}$/);
    expect(result.authEvent.sig).toMatch(/^[0-9a-f]{128}$/);
    expect(result.authEvent.tags).toEqual(expect.arrayContaining([
      ['challenge', requestId],
      ['origin', DEFAULT_ORIGIN],
    ]));
    expect(result.createdAt).toBeGreaterThan(0);
  });
});

describe('waitForAuthResponse — subscription window', () => {
  /** The `since` value from the REQ frame the waiter sent. */
  function requestedSince(): number {
    const req = lastWs!.sent.find(x => x.startsWith('["REQ"'))!;
    return JSON.parse(req)[2].since as number;
  }

  it('defaults to a minute before the call', async () => {
    const { sessionPrivKey } = setupSession();
    const before = Math.floor(Date.now() / 1000);

    const promise = waitForAuthResponse({
      requestId: 'd'.repeat(64), relayUrl: 'wss://r.test', sessionPrivKey, expectedOrigin: DEFAULT_ORIGIN, timeout: 5000,
    });
    promise.catch(() => { /* times out; not the point of this test */ });
    await new Promise(r => setTimeout(r, 10));

    const since = requestedSince();
    expect(since).toBeGreaterThanOrEqual(before - 61);
    expect(since).toBeLessThanOrEqual(before - 59);
    lastWs!.fireError();
    await promise.catch(() => { /* settled */ });
  });

  it('asks from the caller-supplied anchor when the wait is restarted', async () => {
    // The case this exists for: a mobile consumer whose listener was killed
    // while the user approved in the signer app. Restarting the wait with the
    // default window would ask only for responses newer than the restart, and
    // the response — already published, sitting on the relay — would never be
    // asked for again.
    const { sessionPrivKey } = setupSession();
    const signInStartedAt = Math.floor(Date.now() / 1000) - 240;

    const promise = waitForAuthResponse({
      requestId: 'e'.repeat(64), relayUrl: 'wss://r.test', sessionPrivKey,
      expectedOrigin: DEFAULT_ORIGIN, timeout: 5000, since: signInStartedAt - 60,
    });
    promise.catch(() => { /* times out; not the point of this test */ });
    await new Promise(r => setTimeout(r, 10));

    expect(requestedSince()).toBe(signInStartedAt - 60);
    lastWs!.fireError();
    await promise.catch(() => { /* settled */ });
  });

  it('still accepts a response published before the restart', async () => {
    const { sessionPrivKey, sessionPubkeyHex, userPrivKey, userPubkeyHex } = setupSession();
    const requestId = 'f'.repeat(64);

    const promise = waitForAuthResponse({
      requestId, relayUrl: 'wss://r.test', sessionPrivKey, expectedOrigin: DEFAULT_ORIGIN,
      timeout: 5000, since: Math.floor(Date.now() / 1000) - 300,
    });
    await new Promise(r => setTimeout(r, 10));
    lastWs!.deliver(buildAuthGiftWrap({ userPrivKey, sessionPubkeyHex, requestId, origin: DEFAULT_ORIGIN }));

    const result = await promise;
    expect(result.pubkey).toBe(userPubkeyHex);
  });

  it('derives the relay window from issuedAt', async () => {
    const { sessionPrivKey } = setupSession();
    const issuedAt = Math.floor(Date.now() / 1000) - 240;

    const promise = waitForAuthResponse({
      requestId: '1'.repeat(64), relayUrl: 'wss://r.test', sessionPrivKey,
      expectedOrigin: DEFAULT_ORIGIN, timeout: 5000, issuedAt,
    });
    promise.catch(() => { /* times out; not the point of this test */ });
    await new Promise(r => setTimeout(r, 10));

    expect(requestedSince()).toBe(issuedAt - 60);
    lastWs!.fireError();
    await promise.catch(() => { /* settled */ });
  });

  it('lets an explicit since override issuedAt', async () => {
    // `since` is the raw escape hatch and stays authoritative for consumers
    // already passing it against 0.5.2.
    const { sessionPrivKey } = setupSession();
    const issuedAt = Math.floor(Date.now() / 1000) - 240;

    const promise = waitForAuthResponse({
      requestId: '2'.repeat(64), relayUrl: 'wss://r.test', sessionPrivKey,
      expectedOrigin: DEFAULT_ORIGIN, timeout: 5000, issuedAt, since: 1700000000,
    });
    promise.catch(() => { /* times out; not the point of this test */ });
    await new Promise(r => setTimeout(r, 10));

    expect(requestedSince()).toBe(1700000000);
    lastWs!.fireError();
    await promise.catch(() => { /* settled */ });
  });

  it('ignores a non-finite issuedAt and falls back to the default window', async () => {
    const { sessionPrivKey } = setupSession();
    const before = Math.floor(Date.now() / 1000);

    const promise = waitForAuthResponse({
      requestId: '3'.repeat(64), relayUrl: 'wss://r.test', sessionPrivKey,
      expectedOrigin: DEFAULT_ORIGIN, timeout: 5000, issuedAt: Number.NaN,
    });
    promise.catch(() => { /* times out; not the point of this test */ });
    await new Promise(r => setTimeout(r, 10));

    expect(requestedSince()).toBeGreaterThanOrEqual(before - 61);
    expect(requestedSince()).toBeLessThanOrEqual(before - 59);
    lastWs!.fireError();
    await promise.catch(() => { /* settled */ });
  });
});

describe('waitForAuthResponse — rejections', () => {
  it('rejects with denied when status is rejected', async () => {
    const { sessionPrivKey, sessionPubkeyHex, userPrivKey } = setupSession();
    const requestId = 'c'.repeat(64);

    const promise = waitForAuthResponse({
      requestId, relayUrl: 'wss://r.test', sessionPrivKey, expectedOrigin: DEFAULT_ORIGIN, timeout: 5000,
    });
    await new Promise(r => setTimeout(r, 10));
    const wrap = buildAuthGiftWrap({ userPrivKey, sessionPubkeyHex, requestId, origin: DEFAULT_ORIGIN, status: 'rejected' });
    lastWs!.deliver(wrap);

    await expect(promise).rejects.toThrow('denied');
  });

  it('rejects with timeout when no response arrives', async () => {
    const sessionPrivKey = generateSecretKey();
    const promise = waitForAuthResponse({
      requestId: 'd'.repeat(64), relayUrl: 'wss://r.test', sessionPrivKey, expectedOrigin: DEFAULT_ORIGIN, timeout: 5000,
    });
    await expect(promise).rejects.toThrow('timeout');
  }, 15000);

  it('rejects with relay-error on WebSocket error', async () => {
    const sessionPrivKey = generateSecretKey();
    const promise = waitForAuthResponse({
      requestId: 'e'.repeat(64), relayUrl: 'wss://r.test', sessionPrivKey, expectedOrigin: DEFAULT_ORIGIN, timeout: 5000,
    });
    await new Promise(r => setTimeout(r, 10));
    lastWs!.fireError();
    await expect(promise).rejects.toThrow('relay-error');
  });

  it('reports expired, not timeout, when the only response seen was out of window', async () => {
    const { sessionPrivKey, sessionPubkeyHex, userPrivKey } = setupSession();
    const requestId = '4'.repeat(64);

    const promise = waitForAuthResponse({
      requestId, relayUrl: 'wss://r.test', sessionPrivKey,
      expectedOrigin: DEFAULT_ORIGIN, timeout: 5000,
    });
    await new Promise(r => setTimeout(r, 10));
    lastWs!.deliver(buildAuthGiftWrap({
      userPrivKey, sessionPubkeyHex, requestId, origin: DEFAULT_ORIGIN,
      staleAuthEventCreatedAt: Math.floor(Date.now() / 1000) - 600,
    }));

    await expect(promise).rejects.toThrow('expired');
  }, 15000);

  it('still reports timeout when nothing at all was seen', async () => {
    const { sessionPrivKey } = setupSession();

    const promise = waitForAuthResponse({
      requestId: '5'.repeat(64), relayUrl: 'wss://r.test', sessionPrivKey,
      expectedOrigin: DEFAULT_ORIGIN, timeout: 5000,
    });
    await expect(promise).rejects.toThrow('timeout');
  }, 15000);

  it('carries a machine-readable code on the expiry error', async () => {
    const { sessionPrivKey, sessionPubkeyHex, userPrivKey } = setupSession();
    const requestId = '6'.repeat(64);

    const promise = waitForAuthResponse({
      requestId, relayUrl: 'wss://r.test', sessionPrivKey,
      expectedOrigin: DEFAULT_ORIGIN, timeout: 5000,
    });
    await new Promise(r => setTimeout(r, 10));
    lastWs!.deliver(buildAuthGiftWrap({
      userPrivKey, sessionPubkeyHex, requestId, origin: DEFAULT_ORIGIN,
      staleAuthEventCreatedAt: Math.floor(Date.now() / 1000) - 600,
    }));

    await promise.catch((err: Error & { code?: string }) => {
      expect(err.code).toBe('expired');
    });
  }, 15000);
});

describe('waitForAuthResponse — ignores invalid events', () => {
  it('ignores a wrap with a bad authEvent signature', async () => {
    const { sessionPrivKey, sessionPubkeyHex, userPrivKey } = setupSession();
    const requestId = 'a'.repeat(64);

    const promise = waitForAuthResponse({
      requestId, relayUrl: 'wss://r.test', sessionPrivKey, expectedOrigin: DEFAULT_ORIGIN, timeout: 5000,
    });
    await new Promise(r => setTimeout(r, 10));
    const wrap = buildAuthGiftWrap({
      userPrivKey, sessionPubkeyHex, requestId, origin: DEFAULT_ORIGIN, tamperAuthEventSig: true,
    });
    lastWs!.deliver(wrap);

    await expect(promise).rejects.toThrow('timeout');
  }, 15000);

  it('ignores a wrap with a tampered authEvent id (hash mismatch)', async () => {
    const { sessionPrivKey, sessionPubkeyHex, userPrivKey } = setupSession();
    const requestId = 'a'.repeat(64);

    const promise = waitForAuthResponse({
      requestId, relayUrl: 'wss://r.test', sessionPrivKey, expectedOrigin: DEFAULT_ORIGIN, timeout: 5000,
    });
    await new Promise(r => setTimeout(r, 10));
    const wrap = buildAuthGiftWrap({
      userPrivKey, sessionPubkeyHex, requestId, origin: DEFAULT_ORIGIN, tamperAuthEventId: true,
    });
    lastWs!.deliver(wrap);

    await expect(promise).rejects.toThrow('timeout');
  }, 15000);

  it('ignores a wrap whose authEvent challenge tag does not match', async () => {
    const { sessionPrivKey, sessionPubkeyHex, userPrivKey } = setupSession();
    const requestId = 'a'.repeat(64);

    const promise = waitForAuthResponse({
      requestId, relayUrl: 'wss://r.test', sessionPrivKey, expectedOrigin: DEFAULT_ORIGIN, timeout: 5000,
    });
    await new Promise(r => setTimeout(r, 10));
    const wrap = buildAuthGiftWrap({
      userPrivKey, sessionPubkeyHex, requestId, origin: DEFAULT_ORIGIN, tamperChallengeTag: 'f'.repeat(64),
    });
    lastWs!.deliver(wrap);

    await expect(promise).rejects.toThrow('timeout');
  }, 15000);

  it('ignores a wrap whose authEvent origin tag does not match expectedOrigin', async () => {
    const { sessionPrivKey, sessionPubkeyHex, userPrivKey } = setupSession();
    const requestId = 'a'.repeat(64);

    const promise = waitForAuthResponse({
      requestId, relayUrl: 'wss://r.test', sessionPrivKey, expectedOrigin: DEFAULT_ORIGIN, timeout: 5000,
    });
    await new Promise(r => setTimeout(r, 10));
    const wrap = buildAuthGiftWrap({
      userPrivKey, sessionPubkeyHex, requestId, origin: DEFAULT_ORIGIN, tamperOriginTag: 'https://attacker.com',
    });
    lastWs!.deliver(wrap);

    await expect(promise).rejects.toThrow('timeout');
  }, 15000);

  it('ignores a wrap missing the authEvent entirely', async () => {
    const { sessionPrivKey, sessionPubkeyHex, userPrivKey } = setupSession();
    const requestId = 'a'.repeat(64);

    const promise = waitForAuthResponse({
      requestId, relayUrl: 'wss://r.test', sessionPrivKey, expectedOrigin: DEFAULT_ORIGIN, timeout: 5000,
    });
    await new Promise(r => setTimeout(r, 10));
    const wrap = buildAuthGiftWrap({
      userPrivKey, sessionPubkeyHex, requestId, origin: DEFAULT_ORIGIN, omitAuthEvent: true,
    });
    lastWs!.deliver(wrap);

    await expect(promise).rejects.toThrow('timeout');
  }, 15000);

  it('ignores a wrap whose authEvent pubkey does not match the rumor sender (identity mismatch)', async () => {
    const { sessionPrivKey, sessionPubkeyHex, userPrivKey } = setupSession();
    const requestId = 'a'.repeat(64);

    const promise = waitForAuthResponse({
      requestId, relayUrl: 'wss://r.test', sessionPrivKey, expectedOrigin: DEFAULT_ORIGIN, timeout: 5000,
    });
    await new Promise(r => setTimeout(r, 10));
    // Override the authEvent pubkey to a different key — breaks identity binding
    const wrap = buildAuthGiftWrap({
      userPrivKey, sessionPubkeyHex, requestId, origin: DEFAULT_ORIGIN,
      tamperAuthEventPubkey: 'a'.repeat(64),
    });
    lastWs!.deliver(wrap);

    await expect(promise).rejects.toThrow('timeout');
  }, 15000);

  it('does not accept a stale authEvent, and says it expired', async () => {
    const { sessionPrivKey, sessionPubkeyHex, userPrivKey } = setupSession();
    const requestId = 'a'.repeat(64);

    const promise = waitForAuthResponse({
      requestId, relayUrl: 'wss://r.test', sessionPrivKey, expectedOrigin: DEFAULT_ORIGIN, timeout: 5000,
    });
    await new Promise(r => setTimeout(r, 10));
    const wrap = buildAuthGiftWrap({
      userPrivKey, sessionPubkeyHex, requestId, origin: DEFAULT_ORIGIN,
      staleAuthEventCreatedAt: Math.floor(Date.now() / 1000) - 600,
    });
    lastWs!.deliver(wrap);

    // Still not accepted — the guarantee that matters. But the caller is now
    // told WHY, so it can offer a fresh sign-in instead of a blank retry.
    await expect(promise).rejects.toThrow('expired');
  }, 15000);

  it('ignores a wrap addressed to a different session pubkey (decrypt fails)', async () => {
    const sessionPrivKey = generateSecretKey();
    const otherSessionPrivKey = generateSecretKey();
    const otherSessionPubkeyHex = bytesToHex(schnorr.getPublicKey(otherSessionPrivKey));
    const userPrivKey = generateSecretKey();
    const requestId = 'a'.repeat(64);

    const promise = waitForAuthResponse({
      requestId, relayUrl: 'wss://r.test', sessionPrivKey, expectedOrigin: DEFAULT_ORIGIN, timeout: 5000,
    });
    await new Promise(r => setTimeout(r, 10));
    const wrap = buildAuthGiftWrap({
      userPrivKey, sessionPubkeyHex: otherSessionPubkeyHex, requestId, origin: DEFAULT_ORIGIN,
    });
    lastWs!.deliver(wrap);

    await expect(promise).rejects.toThrow('timeout');
  }, 15000);

  it('returns displayName when supplied in the AuthResponse', async () => {
    const { sessionPrivKey, sessionPubkeyHex, userPrivKey } = setupSession();
    const requestId = 'a'.repeat(64);

    const promise = waitForAuthResponse({
      requestId, relayUrl: 'wss://r.test', sessionPrivKey, expectedOrigin: DEFAULT_ORIGIN, timeout: 5000,
    });
    await new Promise(r => setTimeout(r, 10));
    const wrap = buildAuthGiftWrap({
      userPrivKey, sessionPubkeyHex, requestId, origin: DEFAULT_ORIGIN, displayName: 'AxoLittle',
    });
    lastWs!.deliver(wrap);

    const result = await promise;
    expect(result.displayName).toBe('AxoLittle');
  });

  it('omits displayName from result when absent from AuthResponse', async () => {
    const { sessionPrivKey, sessionPubkeyHex, userPrivKey } = setupSession();
    const requestId = 'a'.repeat(64);

    const promise = waitForAuthResponse({
      requestId, relayUrl: 'wss://r.test', sessionPrivKey, expectedOrigin: DEFAULT_ORIGIN, timeout: 5000,
    });
    await new Promise(r => setTimeout(r, 10));
    const wrap = buildAuthGiftWrap({ userPrivKey, sessionPubkeyHex, requestId, origin: DEFAULT_ORIGIN });
    lastWs!.deliver(wrap);

    const result = await promise;
    expect(result.displayName).toBeUndefined();
    expect('displayName' in result).toBe(false);
  });

  it('strips control + bidi characters from displayName', async () => {
    const { sessionPrivKey, sessionPubkeyHex, userPrivKey } = setupSession();
    const requestId = 'a'.repeat(64);

    const promise = waitForAuthResponse({
      requestId, relayUrl: 'wss://r.test', sessionPrivKey, expectedOrigin: DEFAULT_ORIGIN, timeout: 5000,
    });
    await new Promise(r => setTimeout(r, 10));
    // Embed: NUL, DEL, RTL override (U+202E), zero-width joiner (U+200D)
    const dirty = 'Ax\x00o\x7fLi‮t‍tle';
    const wrap = buildAuthGiftWrap({
      userPrivKey, sessionPubkeyHex, requestId, origin: DEFAULT_ORIGIN, displayName: dirty,
    });
    lastWs!.deliver(wrap);

    const result = await promise;
    expect(result.displayName).toBe('AxoLittle');
  });

  it('caps displayName at 64 characters', async () => {
    const { sessionPrivKey, sessionPubkeyHex, userPrivKey } = setupSession();
    const requestId = 'a'.repeat(64);

    const promise = waitForAuthResponse({
      requestId, relayUrl: 'wss://r.test', sessionPrivKey, expectedOrigin: DEFAULT_ORIGIN, timeout: 5000,
    });
    await new Promise(r => setTimeout(r, 10));
    const long = 'A'.repeat(200);
    const wrap = buildAuthGiftWrap({
      userPrivKey, sessionPubkeyHex, requestId, origin: DEFAULT_ORIGIN, displayName: long,
    });
    lastWs!.deliver(wrap);

    const result = await promise;
    expect(result.displayName).toBe('A'.repeat(64));
  });

  it('drops displayName that becomes empty after sanitisation', async () => {
    const { sessionPrivKey, sessionPubkeyHex, userPrivKey } = setupSession();
    const requestId = 'a'.repeat(64);

    const promise = waitForAuthResponse({
      requestId, relayUrl: 'wss://r.test', sessionPrivKey, expectedOrigin: DEFAULT_ORIGIN, timeout: 5000,
    });
    await new Promise(r => setTimeout(r, 10));
    // Only control characters → cleaned to '' → dropped
    const wrap = buildAuthGiftWrap({
      userPrivKey, sessionPubkeyHex, requestId, origin: DEFAULT_ORIGIN, displayName: '\x00\x01\x02',
    });
    lastWs!.deliver(wrap);

    const result = await promise;
    expect(result.displayName).toBeUndefined();
  });

  it('rejects non-string displayName (drops to undefined)', async () => {
    const { sessionPrivKey, sessionPubkeyHex, userPrivKey } = setupSession();
    const requestId = 'a'.repeat(64);

    const promise = waitForAuthResponse({
      requestId, relayUrl: 'wss://r.test', sessionPrivKey, expectedOrigin: DEFAULT_ORIGIN, timeout: 5000,
    });
    await new Promise(r => setTimeout(r, 10));
    const wrap = buildAuthGiftWrap({
      userPrivKey, sessionPubkeyHex, requestId, origin: DEFAULT_ORIGIN,
      displayNameNonString: { evil: 'object' },
    });
    lastWs!.deliver(wrap);

    const result = await promise;
    expect(result.displayName).toBeUndefined();
  });

  it('ignores non-EVENT messages from the relay', async () => {
    const { sessionPrivKey, sessionPubkeyHex, userPrivKey } = setupSession();
    const requestId = 'a'.repeat(64);

    const promise = waitForAuthResponse({
      requestId, relayUrl: 'wss://r.test', sessionPrivKey, expectedOrigin: DEFAULT_ORIGIN, timeout: 5000,
    });
    await new Promise(r => setTimeout(r, 10));

    lastWs!.deliverRaw(['NOTICE', 'hello']);
    lastWs!.deliverRaw(['EOSE', 'some-sub']);
    const wrap = buildAuthGiftWrap({ userPrivKey, sessionPubkeyHex, requestId, origin: DEFAULT_ORIGIN });
    lastWs!.deliver(wrap);

    const result = await promise;
    expect(result.authEvent.kind).toBe(21236);
  });
});

describe('waitForAuthResponse — returning from a phone signer', () => {
  it('keeps the request-time lookback when the socket opens after a background pause', async () => {
    const { sessionPrivKey, sessionPubkeyHex, userPrivKey, userPubkeyHex } = setupSession();
    const requestId = '7'.repeat(64);
    const startedAt = Date.now();
    const now = vi.spyOn(Date, 'now').mockReturnValue(startedAt);
    const wrap = buildAuthGiftWrap({ userPrivKey, sessionPubkeyHex, requestId, origin: DEFAULT_ORIGIN });
    const promise = waitForAuthResponse({ requestId, relayUrl: 'wss://r.test', sessionPrivKey, expectedOrigin: DEFAULT_ORIGIN });
    now.mockReturnValue(startedAt + 90_000);
    await new Promise(r => setTimeout(r, 10));
    expect(JSON.parse(lastWs!.sent[0])[2].since).toBe(Math.floor(startedAt / 1000) - 60);
    lastWs!.deliver(wrap);
    expect((await promise).pubkey).toBe(userPubkeyHex);
  });

  it('requests the stored response again on resume and removes its listener after success', async () => {
    const { sessionPrivKey, sessionPubkeyHex, userPrivKey } = setupSession();
    const requestId = '8'.repeat(64);
    const doc = Object.assign(new EventTarget(), { visibilityState: 'visible' });
    vi.stubGlobal('document', doc);
    try {
      const promise = waitForAuthResponse({ requestId, relayUrl: 'wss://r.test', sessionPrivKey, expectedOrigin: DEFAULT_ORIGIN });
      await new Promise(r => setTimeout(r, 10));
      doc.visibilityState = 'hidden';
      doc.dispatchEvent(new Event('visibilitychange'));
      expect(lastWs!.sent).toHaveLength(1);
      doc.visibilityState = 'visible';
      doc.dispatchEvent(new Event('visibilitychange'));
      expect(lastWs!.sent).toEqual([lastWs!.sent[0], lastWs!.sent[0]]);
      lastWs!.deliver(buildAuthGiftWrap({ userPrivKey, sessionPubkeyHex, requestId, origin: DEFAULT_ORIGIN }));
      await promise;
      doc.dispatchEvent(new Event('visibilitychange'));
      expect(lastWs!.sent).toHaveLength(2);
    } finally { vi.unstubAllGlobals(); }
  });

  it('reports a closed connection instead of leaving the approval waiting', async () => {
    const { sessionPrivKey } = setupSession();
    const promise = waitForAuthResponse({ requestId: '9'.repeat(64), relayUrl: 'wss://r.test', sessionPrivKey, expectedOrigin: DEFAULT_ORIGIN });
    const assertion = expect(promise).rejects.toThrow('relay-closed');
    lastWs!.onclose?.();
    await assertion;
  });
});


describe('mobile socket recovery', () => {
  afterEach(() => { vi.unstubAllGlobals(); });

  it('reports expired, not timeout, when the socket is reopened after the sign-in ran out', async () => {
    // The headline mobile case: Android closes the socket while the user is in
    // the signer app, and they come back after the window has passed. The retry
    // reaches connect() past the deadline — which must say the sign-in is over,
    // not invite a retry against an anchor that has already expired.
    vi.useFakeTimers();
    try {
      const doc = new EventTarget() as EventTarget & { visibilityState: string };
      doc.visibilityState = 'visible';
      vi.stubGlobal('document', doc);
      const { sessionPrivKey } = setupSession();
      const pending = waitForAuthResponse({
        requestId: 'b'.repeat(64), relayUrl: 'wss://r.test', sessionPrivKey,
        expectedOrigin: DEFAULT_ORIGIN, issuedAt: Math.floor(Date.now() / 1000),
      });
      const assertion = expect(pending).rejects.toThrow('expired');
      await vi.advanceTimersByTimeAsync(1); // mock socket opens
      // Move the wall clock past the whole validity window WITHOUT firing the
      // wait's own timer (setSystemTime shifts pending timers with it), so the
      // reconnect is the path that observes the deadline.
      vi.setSystemTime(Date.now() + (AUTH_FRESHNESS_WINDOW_SEC + 30) * 1000);
      lastWs!.onclose?.(); // visible → schedules connect() in 1 s
      await vi.advanceTimersByTimeAsync(1000);
      await assertion;
    } finally {
      vi.useRealTimers();
    }
  });

  it('reopens a socket closed in the background and receives the stored approval', async () => {
    const doc = new EventTarget() as EventTarget & { visibilityState: string };
    doc.visibilityState = 'hidden';
    vi.stubGlobal('document', doc);
    const { sessionPrivKey, sessionPubkeyHex, userPrivKey } = setupSession();
    const requestId = 'a'.repeat(64);
    const pending = waitForAuthResponse({ requestId, relayUrl: 'wss://r.test', sessionPrivKey, expectedOrigin: DEFAULT_ORIGIN });
    await new Promise(r => setTimeout(r, 10));
    const previous = lastWs!;
    const originalRequest = previous.sent[0];
    previous.close(); previous.onclose?.();
    expect(lastWs).toBe(previous);
    doc.visibilityState = 'visible'; doc.dispatchEvent(new Event('visibilitychange'));
    await new Promise(r => setTimeout(r, 10));
    expect(lastWs).not.toBe(previous);
    expect(lastWs!.sent[0]).toBe(originalRequest);
    lastWs!.deliver(buildAuthGiftWrap({ userPrivKey, sessionPubkeyHex, requestId, origin: DEFAULT_ORIGIN }));
    await expect(pending).resolves.toMatchObject({ pubkey: bytesToHex(schnorr.getPublicKey(userPrivKey)) });
    doc.dispatchEvent(new Event('visibilitychange'));
    expect(lastWs!.readyState).toBe(3);
  });
});

describe('AUTH_FRESHNESS_WINDOW_SEC', () => {
  it('is the five-minute window the freshness checks enforce', () => {
    expect(AUTH_FRESHNESS_WINDOW_SEC).toBe(300);
  });
});

describe('waitForAuthResponse — cancellation', () => {
  it('rejects with aborted and closes the socket when the signal fires', async () => {
    const { sessionPrivKey } = setupSession();
    const controller = new AbortController();

    const promise = waitForAuthResponse({
      requestId: '7'.repeat(64), relayUrl: 'wss://r.test', sessionPrivKey,
      expectedOrigin: DEFAULT_ORIGIN, timeout: 600000, abortSignal: controller.signal,
    });
    await new Promise(r => setTimeout(r, 10));
    controller.abort();

    await expect(promise).rejects.toThrow('aborted');
    expect(lastWs!.readyState).toBe(3);
  });

  it('rejects immediately when handed an already-aborted signal', async () => {
    const { sessionPrivKey } = setupSession();
    const controller = new AbortController();
    controller.abort();

    await expect(waitForAuthResponse({
      requestId: '8'.repeat(64), relayUrl: 'wss://r.test', sessionPrivKey,
      expectedOrigin: DEFAULT_ORIGIN, timeout: 600000, abortSignal: controller.signal,
    })).rejects.toThrow('aborted');
  });

  it('ignores a response delivered after an abort', async () => {
    const { sessionPrivKey, sessionPubkeyHex, userPrivKey } = setupSession();
    const requestId = '9'.repeat(64);
    const controller = new AbortController();

    const promise = waitForAuthResponse({
      requestId, relayUrl: 'wss://r.test', sessionPrivKey, expectedOrigin: DEFAULT_ORIGIN,
      timeout: 600000, abortSignal: controller.signal,
    });
    await new Promise(r => setTimeout(r, 10));
    const ws = lastWs!;
    controller.abort();
    await expect(promise).rejects.toThrow('aborted');

    // Late delivery must not resolve an already-settled promise.
    expect(() => ws.deliver(buildAuthGiftWrap({
      userPrivKey, sessionPubkeyHex, requestId, origin: DEFAULT_ORIGIN,
    }))).not.toThrow();
  });

  it('rejects with aborted, not a ReferenceError, when document exists and the signal is already aborted', async () => {
    const { sessionPrivKey } = setupSession();
    const controller = new AbortController();
    controller.abort();

    // Reproduces a real browser environment for this one test: this repo's
    // suite otherwise runs with no `document` at all, which hid a TDZ bug
    // where `settle()` referenced `onVisible` before its `const` declaration
    // had run, on this exact (already-aborted) path.
    const fakeDocument = {
      addEventListener: () => {},
      removeEventListener: () => {},
      visibilityState: 'visible',
    };
    (globalThis as unknown as { document: unknown }).document = fakeDocument;
    try {
      await expect(waitForAuthResponse({
        requestId: 'e'.repeat(64), relayUrl: 'wss://r.test', sessionPrivKey,
        expectedOrigin: DEFAULT_ORIGIN, timeout: 600000, abortSignal: controller.signal,
      })).rejects.toThrow('aborted');
    } finally {
      delete (globalThis as unknown as { document?: unknown }).document;
    }
  });
});

describe('waitForAuthResponse — default timeout', () => {
  it('waits until the response would expire when anchored', async () => {
    const { sessionPrivKey } = setupSession();
    // Issued 60s ago: 240s of validity remain, well past the legacy 120s default.
    const issuedAt = Math.floor(Date.now() / 1000) - 60;

    // Fake timers must be installed BEFORE the call: waitForAuthResponse arms
    // its internal timeout timer synchronously (no await before it), so
    // installing fake timers afterward leaves that timer on the real clock —
    // advancing the fake clock later would then have no effect on it.
    vi.useFakeTimers();
    let promise: ReturnType<typeof waitForAuthResponse>;
    // A settlement flag, not Promise.race: racing an already-rejected promise
    // against Promise.resolve() is itself microtask-hop-dependent — a
    // `.then().catch()` chain takes two hops to resolve even off an
    // already-settled input, so a bare `Promise.resolve()` branch always wins
    // regardless of real settlement order. A single two-argument
    // `.then(onFulfilled, onRejected)` hop avoids that.
    let settled = false;
    try {
      promise = waitForAuthResponse({
        requestId: 'b'.repeat(64), relayUrl: 'wss://r.test', sessionPrivKey,
        expectedOrigin: DEFAULT_ORIGIN, issuedAt,
      });
      promise.then(() => { settled = true; }, () => { settled = true; });

      // Still waiting after the old 120s default would have given up.
      await vi.advanceTimersByTimeAsync(130_000);
      await Promise.resolve(); // let a just-fired rejection's handler above run
      expect(settled).toBe(false);
    } finally {
      vi.useRealTimers();
    }
    lastWs!.fireError();
    await promise.catch(() => { /* settled */ });
  });

  it('honours an explicit timeout over the derived one', async () => {
    const { sessionPrivKey } = setupSession();
    const issuedAt = Math.floor(Date.now() / 1000);

    const started = Date.now();
    await expect(waitForAuthResponse({
      requestId: 'c'.repeat(64), relayUrl: 'wss://r.test', sessionPrivKey,
      expectedOrigin: DEFAULT_ORIGIN, issuedAt, timeout: 5000,
    })).rejects.toThrow('timeout');
    expect(Date.now() - started).toBeLessThan(20_000);
  }, 30000);
});

describe('waitForAuthResponse — expiry vs timeout semantics', () => {
  it("reports expired, not timeout, when the sign-in's validity window simply ran out", async () => {
    const { sessionPrivKey } = setupSession();
    // 10s of validity left when the call starts — well short of the old 120s
    // default, but this is about issuedAt's own deadline, not that default.
    const issuedAt = Math.floor(Date.now() / 1000) - (AUTH_FRESHNESS_WINDOW_SEC - 10);

    // Fake timers BEFORE the call (lesson from an earlier task: waitForAuthResponse
    // arms its internal timer synchronously, so installing fake timers after the
    // call leaves that timer on the real clock and advancing the fake clock later
    // has no effect on it).
    vi.useFakeTimers();
    try {
      const promise = waitForAuthResponse({
        requestId: 'f'.repeat(64), relayUrl: 'wss://r.test', sessionPrivKey,
        expectedOrigin: DEFAULT_ORIGIN, issuedAt,
      });
      const assertion = expect(promise).rejects.toThrow('expired');
      await vi.advanceTimersByTimeAsync(11_000);
      await assertion;
    } finally {
      vi.useRealTimers();
    }
  });

  it('still reports timeout when an explicit timeout gives up well before the validity window ends', async () => {
    const { sessionPrivKey } = setupSession();
    // 290s of validity remain — nowhere near expiry — but an explicit short
    // timeout makes the wait give up long before that.
    const issuedAt = Math.floor(Date.now() / 1000) - 10;

    await expect(waitForAuthResponse({
      requestId: 'e'.repeat(64), relayUrl: 'wss://r.test', sessionPrivKey,
      expectedOrigin: DEFAULT_ORIGIN, issuedAt, timeout: 5000,
    })).rejects.toThrow('timeout');
  }, 15000);
});

describe('waitForAuthResponse — every rejection carries .code', () => {
  it('sets err.code === err.message for denied', async () => {
    const { sessionPrivKey, sessionPubkeyHex, userPrivKey } = setupSession();
    const requestId = '4'.repeat(64);
    const promise = waitForAuthResponse({
      requestId, relayUrl: 'wss://r.test', sessionPrivKey, expectedOrigin: DEFAULT_ORIGIN, timeout: 5000,
    });
    await new Promise(r => setTimeout(r, 10));
    lastWs!.deliver(buildAuthGiftWrap({ userPrivKey, sessionPubkeyHex, requestId, origin: DEFAULT_ORIGIN, status: 'rejected' }));
    await promise.catch((err: Error & { code?: string }) => {
      expect(err.code).toBe(err.message);
      expect(err.code).toBe('denied');
    });
  });

  it('sets err.code === err.message for aborted', async () => {
    const { sessionPrivKey } = setupSession();
    const controller = new AbortController();
    const promise = waitForAuthResponse({
      requestId: '5'.repeat(64), relayUrl: 'wss://r.test', sessionPrivKey,
      expectedOrigin: DEFAULT_ORIGIN, timeout: 600000, abortSignal: controller.signal,
    });
    await new Promise(r => setTimeout(r, 10));
    controller.abort();
    await promise.catch((err: Error & { code?: string }) => {
      expect(err.code).toBe(err.message);
      expect(err.code).toBe('aborted');
    });
  });

  it('sets err.code === err.message for relay-error', async () => {
    const { sessionPrivKey } = setupSession();
    const promise = waitForAuthResponse({
      requestId: '6'.repeat(64), relayUrl: 'wss://r.test', sessionPrivKey, expectedOrigin: DEFAULT_ORIGIN, timeout: 600000,
    });
    await new Promise(r => setTimeout(r, 10));
    lastWs!.fireError();
    await promise.catch((err: Error & { code?: string }) => {
      expect(err.code).toBe(err.message);
      expect(err.code).toBe('relay-error');
    });
  });

  it('sets err.code === err.message for timeout', async () => {
    const { sessionPrivKey } = setupSession();
    const promise = waitForAuthResponse({
      requestId: '7'.repeat(64), relayUrl: 'wss://r.test', sessionPrivKey, expectedOrigin: DEFAULT_ORIGIN, timeout: 5000,
    });
    await promise.catch((err: Error & { code?: string }) => {
      expect(err.code).toBe(err.message);
      expect(err.code).toBe('timeout');
    });
  }, 15000);

  it('sets err.code === err.message for an invalid-* input throw', async () => {
    const { sessionPrivKey } = setupSession();
    await waitForAuthResponse({
      requestId: 'not-hex', relayUrl: 'wss://r.test', sessionPrivKey, expectedOrigin: DEFAULT_ORIGIN,
    }).catch((err: Error & { code?: string }) => {
      expect(err.code).toBe(err.message);
      expect(err.code).toBe('invalid-request-id');
    });
  });
});

describe('waitForAuthResponse — the relay refuses the subscription', () => {
  it('rejects with relay-refused and the relay\'s reason instead of waiting silently', async () => {
    // Seen live on relay.damus.io: it accepts the gift wrap, then CLOSEDs any
    // kind-1059 #p subscription with "auth-required". The CLOSED used to be
    // ignored, so the wait ran silently to expiry while the approval sat on the
    // relay. Retrying the same filter on the same relay gets the same answer,
    // so this settles at once.
    const { sessionPrivKey } = setupSession();
    const promise = waitForAuthResponse({
      requestId: 'c'.repeat(64), relayUrl: 'wss://r.test', sessionPrivKey,
      expectedOrigin: DEFAULT_ORIGIN, timeout: 600000,
    });
    const settledErr = promise.catch((err: Error & { code?: string; reason?: string }) => err);
    await new Promise(r => setTimeout(r, 10));
    const subId = JSON.parse(lastWs!.sent[0])[1];
    lastWs!.deliverRaw(['CLOSED', subId, 'auth-required: requested filter requires authentication']);

    const err = await settledErr as Error & { code?: string; reason?: string };
    expect(err.message).toBe('relay-refused');
    expect(err.code).toBe('relay-refused');
    expect(err.reason).toBe('auth-required: requested filter requires authentication');
  });

  it('sanitises the relay\'s reason before handing it to a caller that may display it', async () => {
    const { sessionPrivKey } = setupSession();
    const promise = waitForAuthResponse({
      requestId: 'c'.repeat(64), relayUrl: 'wss://r.test', sessionPrivKey,
      expectedOrigin: DEFAULT_ORIGIN, timeout: 600000,
    });
    const settledErr = promise.catch((err: Error & { reason?: string }) => err);
    await new Promise(r => setTimeout(r, 10));
    const subId = JSON.parse(lastWs!.sent[0])[1];
    lastWs!.deliverRaw(['CLOSED', subId, 'bad‮ ' + 'x'.repeat(500)]);

    const err = await settledErr as Error & { reason?: string };
    expect(err.reason).not.toContain('‮');
    expect(err.reason!.length).toBeLessThanOrEqual(200);
  });

  it('ignores a CLOSED for some other subscription', async () => {
    const { sessionPrivKey, sessionPubkeyHex, userPrivKey, userPubkeyHex } = setupSession();
    const requestId = 'd'.repeat(64);
    const promise = waitForAuthResponse({
      requestId, relayUrl: 'wss://r.test', sessionPrivKey, expectedOrigin: DEFAULT_ORIGIN, timeout: 600000,
    });
    await new Promise(r => setTimeout(r, 10));
    lastWs!.deliverRaw(['CLOSED', 'not-ours', 'whatever']);
    lastWs!.deliver(buildAuthGiftWrap({ userPrivKey, sessionPubkeyHex, requestId, origin: DEFAULT_ORIGIN }));

    expect((await promise).pubkey).toBe(userPubkeyHex);
  });
});
