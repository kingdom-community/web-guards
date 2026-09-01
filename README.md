# @kingdom-community/web-guards

The security primitives a small community website needs and usually gets wrong,
as a dependency-free TypeScript package: a fixed-window rate limiter with an
injectable clock, an origin check for state-changing routes that fails closed on
the two edges that normally fail open, `__Host-` prefixed session cookie rules,
a signed OAuth `state` bound to a session, and proxy-aware client address
extraction. Aimed at Next.js API routes, but bound to nothing more than the
shape of a request and a response.
