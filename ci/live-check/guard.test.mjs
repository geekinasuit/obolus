import assert from 'node:assert/strict';
import { test } from 'node:test';

import { NETWORK, RefusedToSign, USDC, acceptable, guardedClient, signingPolicy } from './guard.mjs';

const PAY_TO = '0xA8DB38Cc28907C7F3423D264114eC15a0c3bB882';
const OTHER = '0x0AC8Bb380D3b8B4D976544440bE2b94d01E09160';
const CAP = 1000n;

const offer = (overrides = {}) => ({
  scheme: 'exact',
  network: NETWORK,
  asset: USDC,
  payTo: PAY_TO,
  amount: '1000',
  maxTimeoutSeconds: 300,
  extra: { name: 'USDC', version: '2' },
  ...overrides,
});

test('the expected offer is acceptable, in any address case', () => {
  assert.equal(acceptable(offer(), PAY_TO, CAP), true);
  assert.equal(acceptable(offer({ payTo: PAY_TO.toLowerCase(), asset: USDC.toLowerCase() }), PAY_TO, CAP), true);
  assert.equal(acceptable(offer({ amount: '1' }), PAY_TO, CAP), true);
});

test('anything else is refused', () => {
  const refused = {
    'another recipient': offer({ payTo: OTHER }),
    'another token': offer({ asset: OTHER }),
    'Base mainnet': offer({ network: 'eip155:8453' }),
    'another scheme': offer({ scheme: 'upto' }),
    'more than the cap': offer({ amount: '1001' }),
    'a zero amount': offer({ amount: '0' }),
    'a negative amount': offer({ amount: '-1' }),
    'a decimal amount': offer({ amount: '0.5' }),
    'a numeric amount': offer({ amount: 1000 }),
    'no recipient': offer({ payTo: undefined }),
    'a malformed recipient': offer({ payTo: '0x1234' }),
    'a Permit2 transfer': offer({ extra: { name: 'USDC', version: '2', assetTransferMethod: 'permit2' } }),
    'a named payment flow': offer({ extra: { name: 'USDC', version: '2', paymentFlow: 'anything' } }),
    'no extra': offer({ extra: undefined }),
  };
  for (const [name, r] of Object.entries(refused)) {
    assert.equal(acceptable(r, PAY_TO, CAP), false, name);
  }
  assert.equal(acceptable(undefined, PAY_TO, CAP), false, 'no offer at all');
});

test('the policy keeps only acceptable offers', () => {
  const good = offer();
  assert.deepEqual(signingPolicy(PAY_TO, CAP)(2, [offer({ payTo: OTHER }), good]), [good]);
});

test('the policy throws rather than return nothing', () => {
  const policy = signingPolicy(PAY_TO, CAP);
  assert.throws(() => policy(2, [offer({ payTo: OTHER })]), RefusedToSign);
  assert.throws(() => policy(2, []), RefusedToSign);
});

test('the policy refuses x402 v1 even for an otherwise acceptable offer', () => {
  assert.throws(() => signingPolicy(PAY_TO, CAP)(1, [offer()]), RefusedToSign);
});

test('an explicit EIP-3009 transfer method is acceptable', () => {
  assert.equal(acceptable(offer({ extra: { name: 'USDC', version: '2', assetTransferMethod: 'eip3009' } }), PAY_TO, CAP), true);
});

// The wiring: the real client, a signer that only counts. A refused offer must fail before
// anything is signed; an acceptable one must be signed once.
function countingSigner() {
  const signer = {
    address: OTHER,
    signed: 0,
    async signTypedData() {
      signer.signed += 1;
      return `0x${'11'.repeat(65)}`;
    },
  };
  return signer;
}

const challenge = (accepts) => ({
  x402Version: 2,
  resource: { url: 'http://127.0.0.1/v1/chat/completions', description: 'test', mimeType: 'application/json' },
  accepts,
});

test('the client signs nothing for a refused offer', async () => {
  const signer = countingSigner();
  await assert.rejects(guardedClient(signer, PAY_TO, CAP).createPaymentPayload(challenge([offer({ amount: '1001' })])));
  await assert.rejects(guardedClient(signer, PAY_TO, CAP).createPaymentPayload(challenge([offer({ payTo: OTHER })])));
  assert.equal(signer.signed, 0);
});

test('the client signs an acceptable offer once', async () => {
  const signer = countingSigner();
  const payload = await guardedClient(signer, PAY_TO, CAP).createPaymentPayload(challenge([offer()]));
  assert.equal(signer.signed, 1);
  assert.equal(payload.accepted.payTo, PAY_TO);
  assert.equal(payload.accepted.amount, '1000');
});
