# `examples/local_target` -- a deliberately flawed app, runnable with zero credentials

```
python -m examples.local_target --mode=flawed          # default
python -m examples.local_target --mode=patched
LOCAL_TARGET_MODE=refuse-all python -m examples.local_target
curl -s -H 'X-Tenant: t_beta' http://127.0.0.1:8099/v1/documents/doc_1001
```

Pure standard library. No credentials, no outbound network, no vendor. It binds
loopback and **refuses to start on any other interface**, with no override flag,
because the only person who would ever pass that flag is someone exposing an app
that is vulnerable on purpose.

`Target.respond()` is a pure function, so a probe can exercise every endpoint
without binding a socket at all. That is not a convenience -- it is what lets the
benchmark report the same verdicts in an environment where a test cannot bind a
port, and record which transport it used instead of silently degrading.

## Why this target exists

The private corpus's headline comparison -- findings behind a mechanical oracle
versus findings behind an interpretive one -- varied the target *and* the oracle
at once, so it measures nothing. Fixing that needs a target whose ground truth is
known by construction and held fixed while only the oracle changes. Hence the
injected flaws, and hence the **paired control endpoint for the same shape**: if
a probe fires on `/v1/documents` it must *not* fire on `/v1/invoices`, and any
oracle that cannot tell those two apart is measurably worse than one that can.

Scope: authorization, agent-tool surfaces, request-parser differentials. **Not
memory safety** -- a sanitizer is already a near-perfect oracle there, so finding
validity is not the hard problem in that domain, and a benchmark about oracle
quality has nothing to measure.

## The four modes

| mode | behaviour | what it simulates | what an unguarded harness concludes |
|---|---|---|---|
| `flawed` | the defects below are live | pre-fix state | varies by oracle -- this is the experiment |
| `patched` | every defect enforced | post-fix state | correctly, "no bug" |
| `refuse-all` | 403 on **every** route, health included | a dead rig / a boundary never reached | "no bug" -- a false negative |
| `unauthorized-all` | 401 on every route | a confound that explains every arm | "no bug" -- a false negative |

The last two rows are the whole point of `C1`. A harness with no liveness arm
cannot distinguish them from `patched`; a harness with one must return `VOID` or
`CONFOUNDED` rather than a negative.

## Endpoints

| route | flaw | the mechanical oracle that decides it | the false signal it can produce |
|---|---|---|---|
| `GET /v1/health` | none | 200 and `mode` present | -- (this is the liveness arm; it 403s in `refuse-all`, which is the trigger for `VOID`) |
| `GET /v1/documents/{id}` | **object-level authorization is not enforced**: any `X-Tenant` reads any document | a **200** carrying `body_text` whose value the caller never supplied and cannot predict -- foreign data, not an echo | a naive "response contains the victim's id" check also fires on `/v1/echo`, which is a rejection |
| `GET /v1/invoices/{id}` | **none -- this is the control.** Same shape, enforced in all four modes | 403 on a foreign tenant | an oracle that fires here is measurably wrong, which is why the pair exists |
| `GET /v1/exists/{id}` | **existence oracle**: 400 when the identifier exists, 404 when it does not | normalise the echoed identifier out of both bodies, *then* compare: the status class and the `error` key still differ | the raw byte diff "works" for the wrong reason -- the echoed identifier differs too (FP#2) |
| `GET /v1/echo?value=` | none. Always `400`, reflecting `value` | a 4xx is a rejection by definition (A2). After echo normalisation the two arms are byte-identical and the oracle vanishes (A3) | **the strongest false signal in the app.** The victim's identifier genuinely appears in the body |
| `GET /v1/config/token` | returns a realistic-looking token | use it: `GET /v1/whoami` with it returns **401**. A placeholder is a string that authenticates nowhere | "looks like a token, 32 hex chars, `_live_` infix" fires on it |
| `GET /v1/config/session` | returns a token that genuinely authenticates (generated per process; never committed) | `GET /v1/whoami` with it returns **200** and a `tenant` | the *same* "looks like a token" heuristic fires identically -- which is the point of the pair |
| `GET /v1/whoami` | none | the oracle for the two rows above | -- |
| `POST /v1/fetch` `{"url":...}` | **allowlist parser differential**: the guard normalises `\` to `/` before parsing, the fetcher does not. `https://allowed.example\@evil.example/p` passes the guard as `allowed.example` and is fetched as `evil.example` | the parsed `final_host` **field** is outside `ALLOWLIST` (A5) | `echo_url` reflects the submitted URL, so any substring check for `allowed.example`, or for a planted nonce, fires on **every** request -- including the ones correctly blocked (FP#6) |
| `GET /v1/tools` | **injected instruction in a tool description** (`lookup_shipment` in `flawed` mode only) | sha256 of each served description against the digests published by `/v1/tools/registry`; an unapproved delta is the finding | `match_carrier`'s approved description legitimately begins "Ignore case and punctuation...", so an imperative-phrase heuristic flags a benign tool |
| `GET /v1/tools/registry` | none | the authority for the row above. Publishes digests of the **approved** descriptions, never of what is being served | -- |

## The three paired false signals, stated as the benchmark uses them

1. **Echo vs disclosure.** `/v1/echo` and `/v1/documents/doc_2002` both put a
   foreign identifier in the response body. One is a 400 rejection, one is a 200
   disclosure. Everything downstream of "the id is in the body" cannot tell them
   apart.
2. **Placeholder vs real secret.** `/v1/config/token` and `/v1/config/session`
   return strings of identical shape. Only *using* them separates the two.
3. **Reflected nonce vs reached host.** `POST /v1/fetch` reflects the URL you
   supplied. The only observable that distinguishes "blocked" from "bypassed" is
   the parsed `final_host` field.

## What this target does *not* establish

It is an injected-defect fixture, so a result on it bounds nothing about real
software. Its ground truth is known because somebody wrote it down, which is a
circularity the benchmark has to declare: it can measure whether an oracle
separates cases that are constructed to be separable, and it cannot measure
whether those cases resemble the distribution of real findings.
