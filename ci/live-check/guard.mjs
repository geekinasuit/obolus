// What the live check's client is willing to sign for, and the client built around it. Kept apart
// from live-check.mjs so both can be tested without a gateway, a facilitator, or a key.

import { ExactEvmScheme } from '@x402/evm';
import { x402Client } from '@x402/fetch';
import { getAddress, isAddress } from 'viem';

export const NETWORK = 'eip155:84532';
export const USDC = '0x036CbD53842c5426634e7929541eC2318f3dCF7e';

export function sameAddress(a, b) {
  return (
    typeof a === 'string' &&
    typeof b === 'string' &&
    isAddress(a, { strict: false }) &&
    isAddress(b, { strict: false }) &&
    getAddress(a) === getAddress(b)
  );
}

// Exact-scheme USDC on Base Sepolia, to the expected recipient, for a positive whole amount no
// larger than the cap, as a plain EIP-3009 transfer authorization. `extra` may name another
// transfer method or payment flow — Permit2, for one, can lead the client to sign a token approval
// rather than a single transfer — so either one present, other than EIP-3009 itself, is refused.
export function acceptable(requirement, payTo, maxAmount) {
  const r = requirement ?? {};
  const extra = r.extra;
  return (
    typeof extra === 'object' &&
    extra !== null &&
    (extra.assetTransferMethod === undefined || extra.assetTransferMethod === 'eip3009') &&
    extra.paymentFlow === undefined &&
    r.scheme === 'exact' &&
    r.network === NETWORK &&
    sameAddress(r.asset, USDC) &&
    sameAddress(r.payTo, payTo) &&
    typeof r.amount === 'string' &&
    /^[0-9]+$/.test(r.amount) &&
    BigInt(r.amount) > 0n &&
    BigInt(r.amount) <= maxAmount
  );
}

export class RefusedToSign extends Error {}

// An x402 client policy: keeps only the acceptable x402 v2 options, and throws when none is left,
// so the client refuses to pay rather than falling through to an option nobody vetted.
export function signingPolicy(payTo, maxAmount) {
  return (version, requirements) => {
    const ok = version === 2 ? requirements.filter((r) => acceptable(r, payTo, maxAmount)) : [];
    if (ok.length === 0) {
      const offered = requirements.map((r) => `${r?.scheme} ${r?.network} ${r?.asset} to ${r?.payTo} for ${r?.amount}`);
      throw new RefusedToSign(
        `Refusing to sign: no x402 v2 option is exact ${NETWORK} USDC to ${payTo} for at most ` +
          `${maxAmount}. Offered (v${version}): ${offered.join('; ') || 'nothing'}.`,
      );
    }
    return ok;
  };
}

// The paying client: the exact EVM scheme on Base Sepolia, behind the signing policy. The client
// applies policies before it creates a payment, so a refused offer is never signed.
//
// `signer` is given no public client and the scheme no RPC URL on purpose: with neither, the scheme
// cannot read chain state, so the extensions that sign token approvals on the payer's behalf have
// nothing to work with. Keep it that way.
export function guardedClient(signer, payTo, maxAmount) {
  return new x402Client()
    .register(NETWORK, new ExactEvmScheme(signer))
    .registerPolicy(signingPolicy(payTo, maxAmount));
}
