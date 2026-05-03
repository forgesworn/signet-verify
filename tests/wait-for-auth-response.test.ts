import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { waitForAuthResponse } from '../src/signet-verify';
import { getConversationKey, encrypt as nip44Encrypt } from 'nostr-tools/nip44';
import { finalizeEvent, generateSecretKey } from 'nostr-tools/pure';
import { schnorr } from '@noble/curves/secp256k1';
import { sha256 } from '@noble/hashes/sha256';
import { bytesToHex } from '@noble/hashes/utils';

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

  it('ignores a stale authEvent (outside 5-min freshness window)', async () => {
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

    await expect(promise).rejects.toThrow('timeout');
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
