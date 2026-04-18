/**
 * Integration test: real-relay round-trip for waitForAuthResponse.
 *
 * Publishes a NIP-17 gift-wrapped auth response to a live relay (mirroring
 * signet-app's publish path via nostr-tools/nip44) and verifies that
 * waitForAuthResponse on the consumer side receives, unwraps, and validates
 * it end-to-end.
 *
 * Skipped unless `INTEGRATION_RELAY_URL` is set, so the default `npm test`
 * run does not require external infrastructure.
 *
 * Usage:
 *   INTEGRATION_RELAY_URL=ws://localhost:7777 npm test
 */

import { describe, it, expect } from 'vitest';
import { waitForAuthResponse } from '../src/signet-verify';
import { getConversationKey, encrypt as nip44Encrypt } from 'nostr-tools/nip44';
import { finalizeEvent, generateSecretKey } from 'nostr-tools/pure';
import { schnorr } from '@noble/curves/secp256k1';
import { sha256 } from '@noble/hashes/sha256';
import { bytesToHex } from '@noble/hashes/utils';

const RELAY = process.env.INTEGRATION_RELAY_URL;
const describeIf = RELAY ? describe : describe.skip;

function computeId(evt: { pubkey: string; created_at: number; kind: number; tags: string[][]; content: string }): string {
  const ser = JSON.stringify([0, evt.pubkey, evt.created_at, evt.kind, evt.tags, evt.content]);
  return bytesToHex(sha256(new TextEncoder().encode(ser)));
}

/** Publish a signed event to the relay, waiting for the OK ack. */
async function publishToRelay(signedEvent: unknown, relayUrl: string): Promise<void> {
  return new Promise((resolve, reject) => {
    const ws = new WebSocket(relayUrl);
    const timer = setTimeout(() => {
      try { ws.close(); } catch { /* ignore */ }
      reject(new Error('publish timeout'));
    }, 10_000);

    ws.onopen = () => {
      ws.send(JSON.stringify(['EVENT', signedEvent]));
    };
    ws.onmessage = (e: MessageEvent) => {
      try {
        const msg = JSON.parse(typeof e.data === 'string' ? e.data : String(e.data));
        if (Array.isArray(msg) && msg[0] === 'OK') {
          clearTimeout(timer);
          try { ws.close(); } catch { /* ignore */ }
          if (msg[2] === true) resolve();
          else reject(new Error('relay rejected event: ' + msg[3]));
        }
      } catch { /* ignore non-JSON messages */ }
    };
    ws.onerror = () => {
      clearTimeout(timer);
      reject(new Error('publish WebSocket error'));
    };
  });
}

/** Build a gift-wrapped auth response using the same crypto path signet-app uses. */
function buildGiftWrap(args: {
  userPrivKey: Uint8Array;
  sessionPubkeyHex: string;
  requestId: string;
  origin: string;
}) {
  const userPubkey = bytesToHex(schnorr.getPublicKey(args.userPrivKey));

  // Kind-27235 signed auth event
  const signedAuthEvent = finalizeEvent({
    kind: 27235,
    created_at: Math.floor(Date.now() / 1000),
    tags: [['challenge', args.requestId], ['origin', args.origin]],
    content: '',
  }, args.userPrivKey);

  // AuthResponse JSON
  const authResponse = {
    type: 'signet-auth-response' as const,
    requestId: args.requestId,
    authEvent: signedAuthEvent,
  };

  // Rumor (kind-29999 unsigned, with computed id per NIP-59)
  const rumorTemplate = {
    pubkey: userPubkey,
    created_at: Math.floor(Date.now() / 1000),
    kind: 29999,
    tags: [['session', args.requestId], ['status', 'approved']] as string[][],
    content: JSON.stringify(authResponse),
  };
  const rumor = { ...rumorTemplate, id: computeId(rumorTemplate) };

  // Seal (kind-13, signed by user, encrypts rumor to session pubkey)
  const userConvKey = getConversationKey(args.userPrivKey, args.sessionPubkeyHex);
  const encryptedRumor = nip44Encrypt(JSON.stringify(rumor), userConvKey);
  const seal = finalizeEvent({
    kind: 13,
    created_at: Math.floor(Date.now() / 1000) - 300,
    tags: [],
    content: encryptedRumor,
  }, args.userPrivKey);

  // Wrap (kind-1059, signed by ephemeral key, encrypts seal to session pubkey)
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

describeIf('integration — real-relay round-trip', () => {
  it('publishes and verifies an approved auth response', async () => {
    const sessionPrivKey = generateSecretKey();
    const sessionPubkeyHex = bytesToHex(schnorr.getPublicKey(sessionPrivKey));
    const userPrivKey = generateSecretKey();
    const userPubkeyHex = bytesToHex(schnorr.getPublicKey(userPrivKey));

    const challenge = bytesToHex(sha256(new TextEncoder().encode('int-test-' + Date.now())));
    const origin = 'https://integration.test.signet';

    // Subscribe first so the REQ is in before the publish.
    const authPromise = waitForAuthResponse({
      requestId: challenge,
      relayUrl: RELAY!,
      sessionPrivKey,
      expectedOrigin: origin,
      timeout: 20_000,
    });

    // Small grace period so the subscription REQ reaches the relay.
    await new Promise(r => setTimeout(r, 500));

    const wrap = buildGiftWrap({ userPrivKey, sessionPubkeyHex, requestId: challenge, origin });
    await publishToRelay(wrap, RELAY!);

    const result = await authPromise;
    expect(result.pubkey).toBe(userPubkeyHex);
    expect(result.authEvent.kind).toBe(27235);
    expect(result.authEvent.id).toMatch(/^[0-9a-f]{64}$/);
    expect(result.authEvent.sig).toMatch(/^[0-9a-f]{128}$/);
    const challengeTag = result.authEvent.tags.find(t => t[0] === 'challenge');
    const originTag = result.authEvent.tags.find(t => t[0] === 'origin');
    expect(challengeTag?.[1]).toBe(challenge);
    expect(originTag?.[1]).toBe(origin);
  }, 30_000);
});
