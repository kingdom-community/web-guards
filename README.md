# @kingdom-community/web-guards

The security primitives a small community website needs and usually gets wrong.

Five of them, with no runtime dependencies:

| Module | What it does |
|---|---|
| `RateLimiter` | Fixed-window rate limiter with an optional lockout and an injectable clock. |
| `checkRequestOrigin` | The `Origin`/`Referer` check for state-changing routes — and it fails closed on the two edges that normally fail open. |
| `createSessionCookieRules` | `__Host-` prefixed session and refresh cookies: how they are written, how they are cleared, how they are read back. |
| `issueState` / `verifyState` | A signed OAuth `state` bound to the session that started the flow. |
| `clientAddress` | The address a rate limit is keyed on, read correctly from behind a reverse proxy. |

Plus `guards.ts`, which wires the rate limiter, the origin check and the client
address into route-level answers (405, 403, 503, 429) without importing a
framework.

Written for Next.js API routes, bound to nothing more than the shape of a
request and a response. Ships ESM and CommonJS with TypeScript types, strict
mode throughout.

**The comments in the source are the point.** Every control here is a control
somebody has to *not* weaken in six months, and the reason each one fails the way
it does is written where the person weakening it will be looking. If you read
one file, read [`src/csrf.ts`](src/csrf.ts).

## Install

```
npm install @kingdom-community/web-guards
```

Node 18 or newer.

## Usage

A login route for a made-up community called Harborlight, with all four controls
on it. This is a Next.js API route; the guards themselves never import `next`.

```ts
// pages/api/auth/login.ts
import {
    RateLimiter,
    createSessionCookieRules,
    methodNotAllowed,
    recommendedAuthLimits,
    refuseCrossOriginRequest,
    refuseIfLimited,
    requestAddress,
    stringField
} from '@kingdom-community/web-guards';
import type {NextApiRequest, NextApiResponse} from 'next';

// Module state: these counters are shared by every request this process serves
// and die when it restarts. That is a deliberate trade — see "What the limiter
// cannot do" below.
const attempts = new RateLimiter(recommendedAuthLimits.loginAttempts);
const failures = new RateLimiter(recommendedAuthLimits.loginFailures);

const cookies = createSessionCookieRules({
    sessionCookieName: '__Host-harborlight_session',
    refreshCookieName: '__Host-harborlight_refresh'
});

export default async function login(request: NextApiRequest, response: NextApiResponse) {
    if (request.method !== 'POST') {
        return methodNotAllowed(response, ['POST']);
    }

    // 1. Origin check. A missing base URL DISABLES this route rather than
    //    disabling the check, and says so in the log.
    if (refuseCrossOriginRequest(request, response, {
        baseUrl: process.env.PUBLIC_BASE_URL,
        baseUrlSetting: 'PUBLIC_BASE_URL'
    })) {
        return;
    }

    // 2. Rate limits, keyed on the address the proxy saw — never the socket.
    const address = requestAddress(request);
    if (refuseIfLimited(response, failures.check(address), 'Too many failed sign-in attempts.')) {
        return;
    }
    if (refuseIfLimited(response, attempts.consume(address), 'Too many sign-in attempts.')) {
        return;
    }

    const username = stringField(request.body, 'username');
    const password = stringField(request.body, 'password', 256);
    const session = await signIn(username, password);

    if (!session) {
        // Consumed only on FAILURE, so a person who mistypes once and then gets
        // it right is not one typo away from a lockout.
        failures.consume(address);
        return response.status(401).json({error: 'invalid_credentials'});
    }

    // 3. A successful login forgets the failure history for this address.
    failures.reset(address);

    // 4. `__Host-` cookies, host-only by specification.
    response.setHeader('Set-Cookie', cookies.issued(session));
    return response.status(200).json({ok: true});
}
```

Logging out is `cookies.cleared()`, sent unconditionally — a user who clicked
sign-out must end up signed out of your site regardless of what any upstream had
to say about it.

Reading the session back on any request:

```ts
const token = cookies.sessionTokenFrom(request.headers.cookie);
```

And the OAuth `state`, for linking a Discord or GitHub account:

```ts
import {issueState, verifyState} from '@kingdom-community/web-guards';

// Starting the flow. Null means the secret is unset: answer 503 rather than
// sending an unsigned state to the provider.
const state = issueState(session.username, process.env.OAUTH_STATE_SECRET);

// Finishing it, in the callback route.
const verdict = verifyState(request.query.state, session.username, process.env.OAUTH_STATE_SECRET);
if (!verdict.ok) {
    // 'wrong-session' is the attack; 'expired' is a person who left the tab
    // open. Different log lines, identical answer to the visitor.
}
```

## Configuration

This package reads no environment variables and no files. Everything is passed
in, which is what makes every rule here unit-testable including the "unset"
cases. Your application supplies two values:

| Value | Passed to | If unset |
|---|---|---|
| Your site's base URL, e.g. `https://harborlight.example` | `refuseCrossOriginRequest({baseUrl})` | **State-changing routes are disabled** with a 503 and a log line. Deliberate. |
| A random signing secret, 32+ bytes | `issueState` / `verifyState` | Account linking is disabled. Nothing else is affected. |

Name the environment variables whatever you like. `PUBLIC_BASE_URL` and
`OAUTH_STATE_SECRET` are used in the examples.

Two notes worth putting in your own deployment docs:

- **The base URL must be set in local development too.** Everything else in your
  codebase probably falls back to `http://localhost:3000` when it is missing —
  correct for a canonical link tag, wrong for an origin allowlist. This module
  refuses rather than inventing one, so sign-in will not work until you set it.
  That loudness is the feature.
- **If your framework inlines public variables at build time** — anything named
  `NEXT_PUBLIC_*`, `VITE_*`, and so on — then a missing base URL is baked into an
  *image*, not fixable by restarting a container. The 503 says so.

## What the origin check refuses, and why

`SameSite=Lax` on the session cookie already blocks the realistic cross-site
POST. The origin check is the second line, because `Lax` does not cover a
same-site subdomain attacker and because leaning on one flag for every
state-changing route is thin.

Two cases fail *open* in the obvious implementation. Both are closed here:

1. **Neither `Origin` nor `Referer` is present.** "Reject a mismatch" says
   nothing about the case where there is nothing to mismatch, and sending
   neither header is the standard way around exactly this control. Such a
   request is rejected with 403. The cost is real: a client that strips both
   cannot post to your site. Every browser sends `Origin` on a cross-origin
   state-changing request, so no ordinary user is in that set — but a
   hand-written API client might be, and that is a trade to make knowingly.
2. **The base URL is unset.** Comparing every incoming `Origin` against
   `undefined` either passes nothing or passes everything, depending on how the
   comparison happens to be written. Neither is acceptable, so an unset base URL
   *disables the route* (503) rather than *disabling the check*. There is no
   third option where a misconfiguration silently removes a security control.

## Why `__Host-` is load-bearing

A browser accepts a cookie named `__Host-…` only if it is `Secure`, has `Path=/`,
and carries **no** `Domain` attribute. That makes the cookie host-only *by
specification* rather than by everyone remembering.

The threat is not the attacker you are picturing. A community site does not stay
one hostname for long: somebody adds a map, a wiki, a status page, a game panel,
and at least one of those subdomains ends up proxying something nobody audits. A
session cookie scoped to `.example.com` rides along to every one of them.

The dangerous moment is the day somebody notices that signing in at
`www.example.com` does not carry over to `example.com` and fixes it by adding one
`Domain=` attribute. That change is a one-line diff, it is obviously correct to
the person writing it, it makes the symptom go away, and it ships the session
token to every subdomain the site will ever have. Nothing in review looks wrong.

With `__Host-`, that diff does not work: the browser refuses the cookie and the
mistake surfaces as "sign-in stopped working" in the first minute of testing.
`createSessionCookieRules` throws on a cookie name without the prefix for the
same reason — so the guarantee cannot quietly decay back into a convention. The
`www` case belongs in a redirect to the canonical host, which is where it is
actually solvable.

That guarantee also has to survive the values passed *through* it. A `Set-Cookie`
header is a value followed by `;`-separated attributes, so a `;` inside a token
does not corrupt the cookie — it *ends* it and starts an attribute. A token of
`jwt; Domain=.evil.example` would produce a header carrying a `Domain`, which is
the exact thing the prefix is here to prevent. So `issued()` refuses a value that
is empty or that contains anything outside RFC 6265's `cookie-octet` set, and
`createSessionCookieRules` refuses a name that is not an HTTP token — which also
catches `__Host-a; Domain=.evil.example`, a name that passes the prefix check on
a technicality. The thrown error names the offending character and never repeats
the value, because that value is a live session token and error messages end up
in logs.

(`Secure` cookies work on `http://localhost` in every current browser, so none of
this costs you anything in local development.)

## Rate limiting: the ordering constraint nobody mentions

If your site forwards logins to an upstream authentication service, that service
almost certainly runs a per-IP limiter of its own. **For every request
originating from your site, it sees your container's address** — so as far as it
is concerned, your entire site is one client.

That has a consequence which is not obvious until it happens to you: if a burst
of failed logins reaches the upstream's bucket *before* it reaches yours, the
lockout that follows is not on the attacker. It is on your website, and every
sign-in on the site fails until it clears. **Your budget has to trip first, or
the abuse mitigation *is* the outage.**

So the numbers are not a free knob. Set your per-minute budget strictly below the
upstream's, and set your failed-login lockout below your own per-minute budget so
a guesser meets the lockout rather than the ceiling.

The same argument says where the limit belongs. The website is usually the only
component positioned to see *who* is calling; an internal API behind it sees only
the website. So the per-address budget goes at the edge and the per-account
budget goes in the API, and between them you get "per account and per originating
address".

`recommendedAuthLimits` is one worked example of that arithmetic — plain
configuration, not live limiters, so adopting the numbers is a decision rather
than a side effect of importing this package:

```ts
import {RateLimiter, recommendedAuthLimits} from '@kingdom-community/web-guards';

const failures = new RateLimiter(recommendedAuthLimits.loginFailures);
```

| Preset | Budget | Reasoning |
|---|---|---|
| `loginAttempts` | 10 / minute / address | Half the assumed upstream budget of 20/minute, so one address cannot walk the whole site into the upstream's lockout. |
| `loginFailures` | 5 per 15 min, then a 15-minute lockout | Below the attempt budget, so a guesser meets the lockout first. Consume on failure only; `reset()` on success. |
| `registrations` | 3 / hour / address | A real person registers once. Note what this does *not* solve: per-IP limiting is no answer to distributed automated signup. |
| `issuedCodes` | 10 / hour / address | For anything the site *mints* on request — invite codes, link codes. Bounds issuing, not guessing; whatever redeems the code needs its own cap. |

They were derived against an upstream that allowed 20 requests per minute
(`ASSUMED_UPSTREAM_REQUESTS_PER_MINUTE`). If yours is different, or you have no
upstream at all, **the numbers are the wrong ones and the method is the right
one.**

Budgets with no upstream ceiling — posting a thread, replying, moderation
actions — are a different problem. Nothing behind them limits by address, so the
goal is not to stop a determined attacker: it is to make flooding tedious enough
that one human moderator can keep up, and to keep an accidental retry loop from
producing a hundred identical posts. Set them well above what a person writing
prose produces and well below what a script does, and do not agonise over it.

## What the limiter cannot do

Honesty about the trade, because a limiter whose weaknesses are undocumented is a
limiter somebody will trust for something it cannot do:

- **The counters are in memory and die on restart.** A deploy resets every
  budget. This is accepted rather than overlooked: the alternative is a database
  write per attempt, which turns your login page into a write endpoint for anyone
  who can send requests to it. For a community site that is the worse trade.
- **They are per-process, not per-fleet.** Two replicas behind a load balancer
  keep two sets of counters, so the effective budget is the configured one
  multiplied by the number of replicas. Divide accordingly, or run one replica,
  or reach for a shared store when you genuinely outgrow this.
- **It is a fixed window, not a sliding one.** An attacker who understands the
  window can spend a full budget at the end of one and another at the start of
  the next. The lockout mode is the answer where that matters.

If any of those is disqualifying for your site, you want a limiter backed by
Redis. This one is for the case where you have one small container and would
rather not run Redis for it.

## Getting the client address right

A rate limiter keyed on the wrong value is not a weaker limiter. It is a limiter
that either does nothing or takes your site down, and it reports neither.

- Keying on `req.socket.remoteAddress` behind a proxy collapses every visitor on
  the internet into one bucket. The first abuser to exhaust the budget locks out
  the whole site.
- Keying on `xff.split(',')[0]` — the spelling most examples use — hands an
  attacker a fresh identity on every request, because `X-Forwarded-For` is a list
  each proxy *appends* to and the client writes the beginning of it.

`clientAddress` reads `X-Real-Ip`, and failing that the **last** entry of
`X-Forwarded-For`. Two things it cannot verify for itself, and you must:

- Your proxy must trust only itself for forwarded headers — Traefik's
  `forwardedHeaders.trustedIPs`, nginx's `set_real_ip_from`, and so on. Without
  that, the proxy passes a client-supplied `X-Forwarded-For` through and appends
  to it, and reading the last entry is only correct because the proxy put it
  there.
- Reading the last entry is right for exactly **one** trusted hop. With two
  proxies, the last entry is the outer proxy. With a variable number, have your
  proxy normalise the value into `X-Real-Ip` and read that.

## Development

```
npm install
npm test         # vitest
npm run typecheck
npm run build    # ESM + CJS + .d.ts into dist/
```

## Origins

Extracted from the website and infrastructure stack behind a Minecraft community
server, generalised and released under MIT. The reasoning in the comments is
load-bearing and came with the code; the specifics it used to name — a particular
site, a particular authentication service, a particular reverse proxy — were
rewritten into the general principle.
