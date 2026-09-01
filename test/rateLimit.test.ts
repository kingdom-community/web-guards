import {describe, expect, it} from 'vitest';

import {RateLimiter} from '../src/rateLimit.js';
import {
    ASSUMED_UPSTREAM_REQUESTS_PER_MINUTE,
    recommendedAuthLimits
} from '../src/recommendedAuthLimits.js';

// The limiter, with time injected so a fifteen-minute lockout is asserted in
// microseconds. Every test below passes an explicit `now`; none of them reads
// the wall clock, which is the point of the injection.

const START = 1_700_000_000_000;

describe('RateLimiter', () => {
    it('allows exactly the configured number of attempts and then refuses', () => {
        const limiter = new RateLimiter({limit: 3, windowMs: 60_000});

        expect(limiter.consume('a', START).allowed).toBe(true);
        expect(limiter.consume('a', START).allowed).toBe(true);
        expect(limiter.consume('a', START).allowed).toBe(true);
        expect(limiter.consume('a', START).allowed).toBe(false);
    });

    it('keys are independent, so one abuser does not refuse everybody', () => {
        // The failure this whole design is built around, in its simplest form.
        const limiter = new RateLimiter({limit: 1, windowMs: 60_000});

        limiter.consume('203.0.113.7', START);

        expect(limiter.consume('203.0.113.7', START).allowed).toBe(false);
        expect(limiter.consume('198.51.100.9', START).allowed).toBe(true);
    });

    it('says how long to wait, in whole seconds and never zero', () => {
        const limiter = new RateLimiter({limit: 1, windowMs: 60_000});
        limiter.consume('a', START);

        const refused = limiter.consume('a', START + 30_000);

        expect(refused.allowed).toBe(false);
        expect(refused.retryAfterSeconds).toBe(30);
    });

    it('forgets the window once it has passed', () => {
        const limiter = new RateLimiter({limit: 1, windowMs: 60_000});
        limiter.consume('a', START);

        expect(limiter.consume('a', START + 60_000).allowed).toBe(true);
    });

    it('locks out for the configured period once the limit is reached', () => {
        const limiter = new RateLimiter({limit: 2, windowMs: 60_000, lockoutMs: 900_000});

        expect(limiter.consume('a', START).allowed).toBe(true);
        expect(limiter.consume('a', START).allowed).toBe(true);

        // ...and the lockout outlasts the window, which is the difference between
        // a budget and a lockout.
        expect(limiter.consume('a', START + 61_000).allowed).toBe(false);
        expect(limiter.consume('a', START + 899_000).allowed).toBe(false);
        expect(limiter.consume('a', START + 901_000).allowed).toBe(true);
    });

    it('check() reports without spending, so knocking does not extend a lockout', () => {
        const limiter = new RateLimiter({limit: 1, windowMs: 60_000, lockoutMs: 900_000});
        limiter.consume('a', START);

        expect(limiter.check('a', START + 1000).allowed).toBe(false);
        expect(limiter.check('a', START + 2000).retryAfterSeconds).toBe(898);
        // Still expiring at the original moment: check() did not push it back.
        expect(limiter.check('a', START + 901_000).allowed).toBe(true);
    });

    it('reset() clears one key, which is what a successful login does', () => {
        const limiter = new RateLimiter({limit: 1, windowMs: 60_000, lockoutMs: 900_000});
        limiter.consume('a', START);
        expect(limiter.check('a', START).allowed).toBe(false);

        limiter.reset('a');

        expect(limiter.check('a', START).allowed).toBe(true);
    });

    it('stays bounded when keys arrive faster than they expire', () => {
        // Keys are client addresses and addresses arrive from the internet.
        const limiter = new RateLimiter({limit: 5, windowMs: 60_000, maxKeys: 10});

        for (let i = 0; i < 500; i++) {
            limiter.consume(`address-${i}`, START);
        }

        expect(limiter.size()).toBeLessThanOrEqual(11);
    });
});

describe('the injected clock', () => {
    // The clock is a constructor-free seam: every method takes `now`, so the
    // limiter has no timers, no `Date.now()` in a hot path, and no test that
    // sleeps. These assert the seam itself rather than a limit.

    it('never reads the wall clock when a time is supplied', () => {
        // A window a decade wide, exercised entirely in the past. If any method
        // fell back to Date.now(), the second consume would be seen as far
        // outside the window and would be allowed.
        const decade = 10 * 365 * 24 * 60 * 60 * 1000;
        const limiter = new RateLimiter({limit: 1, windowMs: decade});

        expect(limiter.consume('a', 0).allowed).toBe(true);
        expect(limiter.consume('a', 1000).allowed).toBe(false);
        expect(limiter.check('a', 1000).allowed).toBe(false);
    });

    it('defaults to the real clock when no time is supplied', () => {
        // The other half of the seam: the default argument has to be live, or
        // production would limit against a frozen instant.
        const limiter = new RateLimiter({limit: 1, windowMs: 60_000});

        expect(limiter.consume('a').allowed).toBe(true);
        expect(limiter.consume('a').allowed).toBe(false);
        // A moment far enough ahead of the real clock clears the window, which
        // only works if the first call recorded the real one.
        expect(limiter.check('a', Date.now() + 120_000).allowed).toBe(true);
    });

    it('a clock that goes backwards refuses rather than resets', () => {
        // Time is not guaranteed monotonic across a container's life. An earlier
        // `now` must not look like a fresh window that hands an attacker their
        // budget back.
        const limiter = new RateLimiter({limit: 1, windowMs: 60_000, lockoutMs: 900_000});
        limiter.consume('a', START);

        expect(limiter.check('a', START - 5_000).allowed).toBe(false);
    });
});

describe('the recommended auth limits', () => {
    // These are policy, shipped as a documented example rather than as defaults.
    // The tests assert the ARITHMETIC that makes them coherent, because that is
    // the part that generalises: if a site's own limiter does not trip before
    // the upstream's, the lockout lands on the site and the abuse mitigation
    // becomes the outage.

    it('spends less of the upstream per-minute budget than the upstream allows', () => {
        expect(recommendedAuthLimits.loginAttempts.limit)
            .toBeLessThan(ASSUMED_UPSTREAM_REQUESTS_PER_MINUTE);
        expect(recommendedAuthLimits.loginAttempts.windowMs).toBe(60_000);
    });

    it('trips its own failed-login lockout before the per-minute budget bites', () => {
        expect(recommendedAuthLimits.loginFailures.limit)
            .toBeLessThan(recommendedAuthLimits.loginAttempts.limit);
        expect(recommendedAuthLimits.loginFailures.lockoutMs).toBeGreaterThanOrEqual(5 * 60_000);
    });

    it('keeps registration far below the login budget', () => {
        // Account creation, often on a shared identity service. A real person
        // does it once.
        expect(recommendedAuthLimits.registrations.limit).toBeLessThanOrEqual(5);
        expect(recommendedAuthLimits.registrations.windowMs).toBe(60 * 60_000);
    });

    it('is plain configuration, not a live limiter anybody imports by accident', () => {
        // Mechanism and policy stay apart: adopting these numbers is a decision,
        // not a side effect of importing the package.
        for (const config of Object.values(recommendedAuthLimits)) {
            expect(config).not.toBeInstanceOf(RateLimiter);
            expect(typeof config.limit).toBe('number');
            expect(typeof config.windowMs).toBe('number');
        }
    });

    it('produces a working limiter when handed to the mechanism', () => {
        const limiter = new RateLimiter(recommendedAuthLimits.loginFailures);

        for (let i = 0; i < recommendedAuthLimits.loginFailures.limit; i++) {
            expect(limiter.consume('203.0.113.7', START).allowed).toBe(true);
        }

        expect(limiter.consume('203.0.113.7', START).allowed).toBe(false);
        // And the lockout, not merely the window, is what holds it shut.
        expect(limiter.consume('203.0.113.7', START + 16 * 60_000).allowed).toBe(true);
    });
});
