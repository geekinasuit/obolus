# Exposing Obolus beyond one machine

Obolus binds `127.0.0.1:8403` by default and speaks plain HTTP only. That default is deliberate and
it is the shape to keep: leave the gateway on loopback and put whatever does the exposing in front of
it. This page covers the three ways to do that, what each costs, and the development seller's
separate rules.

## Inbound TLS is terminated outside the process

The binary has no TLS server. Whatever clients connect to — a reverse proxy, Tailscale — holds the
certificate and its private key, and the gateway holds none. That is the same "holds no key it could
sign with" posture the rest of the design keeps, and it is why none of the options below ask the
gateway to bind a routable interface.

This is **inbound** TLS: clients reaching the gateway. The gateway reaching an `https` facilitator is
**outbound** TLS, a different direction with a different answer, covered in the README's
[Reaching an https facilitator](../README.md#reaching-an-https-facilitator).

## Whatever you put in front, set `OBOLUS_RESOURCE`

The 402 challenge tells a client which URL it is paying for. By default that URL is derived from the
bind address, so behind any front end it names `http://127.0.0.1:8403/...`, which no client can reach.
Set it to the address clients actually use:

```bash
OBOLUS_RESOURCE=https://gateway.example.com/v1/chat/completions
```

## Option 1: a reverse proxy on the same host (Caddy, nginx)

The proxy terminates TLS and forwards to `127.0.0.1:8403`. The plaintext hop never leaves the host.

With [Caddy](https://caddyserver.com/), which obtains a certificate for a public name on its own:

```bash
caddy reverse-proxy --from gateway.example.com --to 127.0.0.1:8403
```

With nginx, the parts that matter are the timeout and buffering:

```nginx
location / {
    proxy_pass http://127.0.0.1:8403;
    proxy_read_timeout 610s;   # above 2 × OBOLUS_MAX_TIMEOUT_SECS
    proxy_buffering off;       # let a streamed completion stream
}
```

**The proxy's timeout has to outlast a paid request.** From its arrival, a paid request can wait
until 15 s before its payment window closes (`OBOLUS_MAX_TIMEOUT_SECS`, 300 s by default) for the
model's response head. The one settle call that follows is then allowed the window plus 15 s of its
own. The worst case is therefore about twice the window, roughly 600 s at the default. A proxy that
gives up and closes its connection to the gateway before then makes the gateway abandon the request:

- before settlement, that costs the client nothing, but a slow answer becomes a proxy error;
- **during settlement, the payment may already have gone through**, and the client gets the proxy's
  error instead of the answer it paid for.

A bearer-token request never settles, and waits for the head only as long as
`OBOLUS_UPSTREAM_HEAD_TIMEOUT_SECS` allows (600 s by default). If you raise that, or the window, raise
the proxy's timeout to the larger of the two bounds.

nginx's `proxy_read_timeout` defaults to 60 s, far inside that bound; set it as above. Caddy's reverse
proxy sets no read or response timeout by default. Keep it that way, or keep any you add above the
same bound. That bound holds only for a timeout measured between reads, as nginx's is. A timeout on
the whole response also has to outlast the stream itself, which nothing in Obolus bounds, and one
that fires after settlement leaves the client paying for a truncated answer. A client's own timeout has the same effect, but that one is the client's choice to make.

## Option 2: `tailscale serve` — tailnet only

[`tailscale serve`](https://tailscale.com/kb/1312/serve) publishes a loopback service to your
tailnet over HTTPS, with Tailscale terminating TLS and your tailnet's access rules deciding who can
reach it. The gateway keeps its loopback bind:

```bash
tailscale serve --bg 8403
```

`tailscale serve reset` takes it down again. What timeout, if any, Tailscale applies to a proxied
request is not something its serve documentation states; check it against the bound above before
relying on it for long completions.

**`tailscale funnel` is not the same thing with a different name.** It publishes the same service
**to the public internet**. The two commands are one word apart and have opposite reach. A funnel is a
public deployment: everything in Option 1 applies, and nothing about your tailnet restricts who
connects. Use `serve` unless public reach is what you want.

## Option 3: a wider bind

`OBOLUS_ADDR=0.0.0.0:8403`, or any non-loopback address, is supported. It is not deprecated, and
there is no plan to remove it. What it costs:

- **Everything is plaintext on every network that can reach the host.** Anyone on the path can read
  and alter requests and responses.
- **A bearer token crossing that network can be lifted and replayed** until it expires. See the
  README's [Serving without payment](../README.md#serving-without-payment). A payment authorization
  is scoped to one request, so it is not a standing key the way a token is. It can still be taken
  in flight: what it signs is a transfer, not the request it came with, so whoever intercepts one
  before it settles can spend it on a request of their own.
- **`OBOLUS_RESOURCE` must be set** to an address clients can reach, since a wildcard bind address
  is not one.

That makes it suitable for a network you trust end to end. That includes a TLS terminator running on
a different host, where "on the same host" in Option 1 is not available, but only when the link
between the two hosts is itself trusted.

## The development seller is stricter, on purpose

`obolus-devseller` settles nothing: it verifies authorizations offline and serves the work for free.
Anything it fronts is given away to whoever can reach it, so its rules are tighter than the gateway's.

- It binds `127.0.0.1:8404` by default. To reach it from a phone or another host, forward a port
  (`adb reverse tcp:8404 tcp:8404` for Android) rather than widening the bind. That is safe because
  the forward reaches one device you chose; a proxy or `tailscale serve` also forwards, but to
  whoever can reach it (see below).
- Any non-loopback bind prints `*** BOUND BEYOND LOOPBACK ***` at startup. **This warning reads
  only the bind address.** A reverse proxy or `tailscale serve` / `funnel` in front of a loopback
  dev seller exposes it just as a wider bind would, and prints no warning, because the process
  cannot see what forwards to it.
- One combination is refused outright, **on any bind, loopback included**: `OBOLUS_DEV_VERIFY=accept`
  plus an `OBOLUS_UPSTREAM_URL` pointing at a real model. That is an unauthenticated open proxy to
  somebody's inference endpoint for whoever can reach the port, billed to whoever runs it, and a
  funnel makes it public. Loopback is not exempt for the reason above: the process cannot see a
  proxy in front of it, so it cannot tell a loopback bind nobody else reaches from one that is
  published ([#104](https://github.com/geekinasuit/obolus/issues/104)). Leave
  `OBOLUS_UPSTREAM_URL` unset to test payments against the canned response.
  `OBOLUS_DEV_ALLOW_OPEN_PROXY=1` (exactly `1`) acknowledges it and starts anyway. The cost falls on
  the port-forward workflow above: `adb reverse` in front of a real model in `accept` mode now
  needs the acknowledgement too.
- **`OBOLUS_DEV_VERIFY=verify` is not an access control.** It checks a signature over a payer address
  the caller chooses, against no balance and no record of spent nonces, and nothing settles, so a
  throwaway keypair passes it as easily as a funded one. That is why `verify` mode in front of a real
  model is allowed rather than refused, on any bind: a client on another device has to be able to
  reach a verifying seller at all. A wider bind gets the warning above; a proxy or funnel in front
  of a loopback bind gets nothing. Neither is a sign the configuration is safe in front of a real
  model. The options above are for the gateway, not for exposing the dev seller.
