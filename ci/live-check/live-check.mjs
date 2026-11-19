// The live check: one real Base Sepolia payment through a third-party facilitator, end to end.
//
// It starts a stub OpenAI-compatible backend in this process, starts the gateway binary named by
// OBOLUS_BIN in front of it, pays the gateway with the reference x402 client, and then checks the
// result three independent ways: the client's receipt, the gateway's telemetry line, and the
// transfer on chain. Any disagreement, and any failure on the way, exits non-zero.
//
// Run by .github/workflows/live-check.yml; runnable by hand with the same environment.
//
// Inputs, all from the environment:
//   OBOLUS_BIN                path to the gateway binary under test (required)
//   LIVE_CHECK_PAYER_KEY      the payer's private key, 0x + 64 hex (required; never printed)
//   LIVE_CHECK_PAYER_ADDRESS  the address that key must derive (required)
//   LIVE_CHECK_PAY_TO         the address the gateway asks to be paid (required)
//   LIVE_CHECK_BREAK          "none" (default) or "token-domain": advertise a wrong EIP-712 domain
//                             version, so the facilitator refuses the payment and nothing moves
//   LIVE_CHECK_RPC_URL        Base Sepolia JSON-RPC endpoint (default https://sepolia.base.org)
//   LIVE_CHECK_OUT_DIR        where the gateway's stdout and stderr are written (default ./out)
//   LIVE_CHECK_GATEWAY_USER   when set, run the gateway as this user via `sudo -n` (CI: nobody)
//   GITHUB_STEP_SUMMARY       when set, the result is appended there as Markdown

import { spawn } from 'node:child_process';
import { appendFileSync, createWriteStream, mkdirSync } from 'node:fs';
import { createServer } from 'node:http';
import { join, resolve } from 'node:path';

import { toClientEvmSigner } from '@x402/evm';
import { decodePaymentResponseHeader, wrapFetchWithPayment } from '@x402/fetch';
import { createPublicClient, erc20Abi, getAddress, http, isAddress, parseEventLogs } from 'viem';
import { privateKeyToAccount } from 'viem/accounts';
import { baseSepolia } from 'viem/chains';

import { NETWORK, USDC, guardedClient, sameAddress } from './guard.mjs';

const FACILITATOR_URL = 'https://x402.org/facilitator';
// The price the gateway is told to charge, in atomic USDC (6 decimals): 0.001 USDC. The client
// refuses to sign for more than this, whatever the gateway asks.
const PRICE = 1000n;
const GATEWAY_ADDR = '127.0.0.1:18403';
const STUB_PORT = 18500;
const MODEL = 'live-check';
const STUB_ANSWER = 'live check ok';

const STARTUP_TIMEOUT_MS = 60_000;
const TELEMETRY_WAIT_MS = 5_000;
const RECEIPT_TIMEOUT_MS = 120_000;

class CheckFailed extends Error {}

function fail(message) {
  throw new CheckFailed(message);
}

function required(name) {
  const value = process.env[name];
  if (value === undefined || value.trim() === '') fail(`${name} is required and is not set.`);
  return value.trim();
}

function address(name) {
  const value = required(name);
  if (!isAddress(value, { strict: false })) fail(`${name} is not an EVM address: ${value}`);
  return getAddress(value);
}

// The key is checked for shape and for the address it derives, and is never echoed: a message
// that quoted it would put it in the run log.
function payerAccount() {
  const key = required('LIVE_CHECK_PAYER_KEY');
  if (!/^0x[0-9a-fA-F]{64}$/.test(key)) {
    fail('LIVE_CHECK_PAYER_KEY is not 0x followed by 64 hex digits (value withheld).');
  }
  // A 64-hex value outside the curve's range makes viem throw an error that quotes the key in
  // decimal, which log masking (it knows only the hex form) would not catch.
  let account;
  try {
    account = privateKeyToAccount(key);
  } catch {
    fail('LIVE_CHECK_PAYER_KEY is not a valid secp256k1 private key (value withheld).');
  }
  const expected = address('LIVE_CHECK_PAYER_ADDRESS');
  if (account.address !== expected) {
    fail(
      `LIVE_CHECK_PAYER_KEY derives ${account.address}, not LIVE_CHECK_PAYER_ADDRESS ${expected}. ` +
        'Refusing to pay from an address nobody named.',
    );
  }
  return account;
}

function domainFor(breakMode) {
  switch (breakMode) {
    case 'none':
      return { name: 'USDC', version: '2' };
    // USDC on Base Sepolia signs under version "2". A client that follows the challenge signs
    // under "1", the facilitator recovers some other address, and verification fails before
    // anything is submitted on chain.
    case 'token-domain':
      return { name: 'USDC', version: '1' };
    default:
      fail(`LIVE_CHECK_BREAK must be "none" or "token-domain", not ${JSON.stringify(breakMode)}.`);
  }
}

// A stand-in for an OpenAI-compatible backend. The payment path is under test, not the model, so
// every completion request gets the same canned answer. Calls are counted so the check can assert
// that only the paid request reached it.
function startStub() {
  const calls = [];
  const server = createServer((req, res) => {
    let body = '';
    req.on('data', (chunk) => {
      body += chunk;
    });
    req.on('end', () => {
      calls.push({ method: req.method, url: req.url });
      if (req.method !== 'POST' || req.url !== '/v1/chat/completions') {
        res.writeHead(404, { 'content-type': 'application/json' });
        res.end(JSON.stringify({ error: `stub serves POST /v1/chat/completions, not ${req.method} ${req.url}` }));
        return;
      }
      res.writeHead(200, { 'content-type': 'application/json' });
      res.end(
        JSON.stringify({
          id: 'chatcmpl-live-check',
          object: 'chat.completion',
          created: Math.floor(Date.now() / 1000),
          model: MODEL,
          choices: [
            { index: 0, message: { role: 'assistant', content: STUB_ANSWER }, finish_reason: 'stop' },
          ],
          usage: { prompt_tokens: 1, completion_tokens: 3, total_tokens: 4 },
        }),
      );
    });
  });
  return new Promise((resolvePromise, reject) => {
    server.once('error', reject);
    server.listen(STUB_PORT, '127.0.0.1', () => resolvePromise({ server, calls }));
  });
}

// The gateway gets an environment built from nothing but PATH and its own settings, so the payer
// key in this process's environment is not handed to it.
//
// That alone does not keep the key from the gateway's code: a process running as the same user
// can read this process's environment from /proc. So with LIVE_CHECK_GATEWAY_USER set, as CI
// sets it, the gateway runs as that user instead, through `sudo -n` (which must not prompt) and
// `env -i`. Its settings then travel on argv; none of them is secret.
function gatewayCommand(bin, env) {
  const runAs = (process.env.LIVE_CHECK_GATEWAY_USER ?? '').trim();
  if (!runAs) return { command: bin, args: [], env };
  const assignments = Object.entries(env).map(([k, v]) => `${k}=${v}`);
  return {
    command: 'sudo',
    args: ['-n', '-u', runAs, '--', '/usr/bin/env', '-i', ...assignments, bin],
    env: { PATH: process.env.PATH ?? '' },
  };
}

function startGateway(bin, outDir, payTo, breakMode) {
  const env = {
    PATH: process.env.PATH ?? '',
    OBOLUS_ADDR: GATEWAY_ADDR,
    OBOLUS_FACILITATOR_URL: FACILITATOR_URL,
    OBOLUS_UPSTREAM_URL: `http://127.0.0.1:${STUB_PORT}`,
    OBOLUS_NETWORK: NETWORK,
    OBOLUS_ASSET: USDC,
    OBOLUS_PAY_TO: payTo,
    OBOLUS_PRICE: PRICE.toString(),
    OBOLUS_EXTRA: JSON.stringify(domainFor(breakMode)),
    OBOLUS_TELEMETRY: 'stdout',
  };
  const { command, args, env: spawnEnv } = gatewayCommand(bin, env);
  const child = spawn(command, args, { env: spawnEnv, stdio: ['ignore', 'pipe', 'pipe'] });
  const telemetry = [];
  const stdoutFile = createWriteStream(join(outDir, 'gateway-stdout.jsonl'));
  const stderrFile = createWriteStream(join(outDir, 'gateway-stderr.log'));
  let pending = '';
  child.stdout.on('data', (chunk) => {
    stdoutFile.write(chunk);
    pending += chunk;
    const lines = pending.split('\n');
    pending = lines.pop();
    for (const line of lines) {
      if (line.trim() === '') continue;
      try {
        telemetry.push(JSON.parse(line));
      } catch {
        telemetry.push({ unparsed: line });
      }
    }
  });
  child.stderr.on('data', (chunk) => stderrFile.write(chunk));
  const exited = new Promise((resolvePromise) => {
    child.on('exit', (code, signal) => resolvePromise({ code, signal }));
  });
  child.on('error', (e) => {
    stderrFile.write(`live-check: could not start ${bin}: ${e.message}\n`);
  });
  return { child, telemetry, exited, close: () => Promise.all([stdoutFile, stderrFile].map((f) => new Promise((r) => f.end(r)))) };
}

function completionRequest() {
  return {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({
      model: MODEL,
      messages: [{ role: 'user', content: 'ping' }],
      max_tokens: 16,
    }),
  };
}

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

// Ready means the gateway answers an unpaid request with a 402. Anything else — a refusal to
// start, another status — fails here, before any key is used.
async function waitForChallenge(url, gateway) {
  const deadline = Date.now() + STARTUP_TIMEOUT_MS;
  let exitedEarly = null;
  gateway.exited.then((e) => {
    exitedEarly = e;
  });
  while (Date.now() < deadline) {
    if (exitedEarly) {
      fail(`The gateway exited before serving (code ${exitedEarly.code}, signal ${exitedEarly.signal}); see gateway-stderr.log.`);
    }
    try {
      const res = await fetch(url, completionRequest());
      await res.arrayBuffer();
      if (res.status !== 402) fail(`An unpaid request got ${res.status}, not 402.`);
      if (!res.headers.get('payment-required')) fail('The 402 carried no PAYMENT-REQUIRED header.');
      return;
    } catch (e) {
      if (e instanceof CheckFailed) throw e;
      await sleep(250);
    }
  }
  fail(`The gateway did not answer on ${GATEWAY_ADDR} within ${STARTUP_TIMEOUT_MS / 1000} s.`);
}

async function waitForSettledLine(telemetry) {
  const deadline = Date.now() + TELEMETRY_WAIT_MS;
  while (Date.now() < deadline) {
    const settled = telemetry.filter((l) => l.kind === 'request' && l.outcome === 'settled');
    if (settled.length > 0) return settled;
    await sleep(100);
  }
  return [];
}

async function checkChain(rpcUrl, hash, payer, payTo) {
  const client = createPublicClient({ chain: baseSepolia, transport: http(rpcUrl) });
  const receipt = await client.waitForTransactionReceipt({ hash, timeout: RECEIPT_TIMEOUT_MS });
  if (receipt.status !== 'success') fail(`Transaction ${hash} is on chain but reverted.`);
  const transfers = parseEventLogs({ abi: erc20Abi, eventName: 'Transfer', logs: receipt.logs }).filter((l) =>
    sameAddress(l.address, USDC),
  );
  const ours = transfers.filter(
    (l) => sameAddress(l.args.from, payer) && sameAddress(l.args.to, payTo) && l.args.value === PRICE,
  );
  if (ours.length !== 1) {
    const seen = transfers.map((l) => `${l.args.from} -> ${l.args.to}: ${l.args.value}`);
    fail(
      `Transaction ${hash} carries ${ours.length} USDC transfer(s) of ${PRICE} from ${payer} to ${payTo}, ` +
        `not exactly one. USDC transfers in it: ${seen.join('; ') || 'none'}.`,
    );
  }
  return receipt.blockNumber;
}

function summary(lines) {
  const path = process.env.GITHUB_STEP_SUMMARY;
  const text = lines.join('\n') + '\n';
  if (path) appendFileSync(path, text);
  process.stdout.write(text);
}

async function main() {
  // In CI the key is real, so running the gateway as another user is required rather than
  // assumed: an edit that drops LIVE_CHECK_GATEWAY_USER must fail the run, not quietly put the
  // gateway back beside the key.
  if (process.env.GITHUB_ACTIONS === 'true' && !(process.env.LIVE_CHECK_GATEWAY_USER ?? '').trim()) {
    fail('LIVE_CHECK_GATEWAY_USER is unset in GitHub Actions; refusing to run the gateway as the paying user.');
  }
  const bin = resolve(required('OBOLUS_BIN'));
  const payTo = address('LIVE_CHECK_PAY_TO');
  const breakMode = (process.env.LIVE_CHECK_BREAK ?? '').trim() || 'none';
  domainFor(breakMode);
  const rpcUrl = (process.env.LIVE_CHECK_RPC_URL ?? '').trim() || 'https://sepolia.base.org';
  const outDir = resolve((process.env.LIVE_CHECK_OUT_DIR ?? '').trim() || 'out');
  mkdirSync(outDir, { recursive: true });
  const account = payerAccount();

  console.log(`payer ${account.address}, payTo ${payTo}, price ${PRICE} atomic USDC, break ${breakMode}`);

  const stub = await startStub();
  const gateway = startGateway(bin, outDir, payTo, breakMode);
  const url = `http://${GATEWAY_ADDR}/v1/chat/completions`;
  try {
    await waitForChallenge(url, gateway);

    // The client signs only for exactly what this check set the gateway up to ask for (guard.mjs),
    // so a gateway advertising anything else fails the run without a signature being made.
    const pay = wrapFetchWithPayment(fetch, guardedClient(toClientEvmSigner(account), payTo, PRICE));
    const res = await pay(url, completionRequest());
    const body = await res.text();
    const header = res.headers.get('payment-response');
    if (res.status !== 200) {
      fail(`The paid request got ${res.status}, not 200. Body: ${body.slice(0, 500)}`);
    }
    if (!header) fail('The paid request got 200 with no PAYMENT-RESPONSE receipt.');
    const receipt = decodePaymentResponseHeader(header);
    if (receipt.success !== true) fail(`The receipt says the settlement failed: ${JSON.stringify(receipt)}`);
    if (receipt.network !== NETWORK) fail(`The receipt names network ${receipt.network}, not ${NETWORK}.`);
    if (!/^0x[0-9a-fA-F]{64}$/.test(receipt.transaction ?? '')) {
      fail(`The receipt's transaction is not a transaction hash: ${JSON.stringify(receipt.transaction)}`);
    }
    if (receipt.payer !== undefined && !sameAddress(receipt.payer, account.address)) {
      fail(`The receipt names payer ${receipt.payer}, not ${account.address}.`);
    }
    let answer;
    try {
      answer = JSON.parse(body).choices?.[0]?.message?.content;
    } catch {
      answer = undefined;
    }
    if (answer !== STUB_ANSWER) fail(`The paid request's answer is not the stub's: ${body.slice(0, 500)}`);
    const hash = receipt.transaction;

    const settled = await waitForSettledLine(gateway.telemetry);
    if (settled.length !== 1) fail(`Expected one settled telemetry line, found ${settled.length}.`);
    const line = settled[0];
    if (line.transaction !== hash) fail(`Telemetry names transaction ${line.transaction}, the receipt ${hash}.`);
    if (line.revenue !== PRICE.toString()) fail(`Telemetry records revenue ${line.revenue}, not ${PRICE}.`);
    if (line.paid?.network !== NETWORK || !sameAddress(line.paid?.asset ?? '', USDC)) {
      fail(`Telemetry's paid option is not ${NETWORK} USDC: ${JSON.stringify(line.paid)}`);
    }

    const completions = stub.calls.filter((c) => c.url === '/v1/chat/completions');
    if (completions.length !== 1) fail(`The stub backend was called ${completions.length} times, not once.`);

    const block = await checkChain(rpcUrl, hash, account.address, payTo);

    summary([
      '## Live check: settled',
      '',
      `| | |`,
      `|---|---|`,
      `| Transaction | [\`${hash}\`](https://sepolia.basescan.org/tx/${hash}) |`,
      `| Block | ${block} |`,
      `| Amount | ${PRICE} atomic USDC on ${NETWORK} |`,
      `| Payer | \`${account.address}\` |`,
      `| PayTo | \`${payTo}\` |`,
      `| Facilitator | ${FACILITATOR_URL} |`,
      `| Commit | ${process.env.GITHUB_SHA ?? 'local'} |`,
    ]);
  } finally {
    gateway.child.kill('SIGTERM');
    await Promise.race([gateway.exited, sleep(5_000)]);
    await gateway.close();
    await new Promise((r) => stub.server.close(r));
    const outcomes = gateway.telemetry.map((l) => l.outcome ?? l.kind ?? 'unparsed');
    console.log(`gateway telemetry outcomes: ${outcomes.join(', ') || 'none'}`);
  }
}

try {
  await main();
} catch (e) {
  const message = e instanceof Error ? e.message : String(e);
  summary(['## Live check: FAILED', '', message.replaceAll('\n', ' ')]);
  process.exitCode = 1;
}
