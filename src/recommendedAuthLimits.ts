// A worked example of the numbers, kept apart from the mechanism on purpose.
//
// `rateLimit.ts` is the mechanism and knows nothing about what is being limited.
// These are POLICY: one set of budgets that worked for a community site of a few
// hundred members sitting in front of a shared authentication service. They are
// exported as plain configuration, not as live limiters, so that adopting them
// is a decision you make rather than a side effect of importing this package.
//
// Read the reasoning before taking the numbers. The reasoning generalises; the
// numbers only generalise if your upstream looks like the one described here.
//
// THE CEILING THESE SIT UNDER
//
// The upstream authentication service ran its own per-IP limiter on its login
// and registration endpoints: 20 requests per 60 seconds. Every request
// originating from the website reached it from the website's container address,
// so as far as it was concerned the entire site was one client. A burst that
// reached the upstream bucket first would have locked out the SITE, not the
// attacker, and every login would have failed until it cleared.
//
// That is the arithmetic below: every number is chosen so the site's own limiter
// trips first. If your upstream's budget is different, or you have no upstream
// at all, these numbers are the wrong ones and the method is the right one.

import type {LimiterConfig} from './rateLimit.js';

const MINUTE = 60 * 1000;

// The upstream budget these were derived against. Stated as a constant so the
// relationship between the two is visible, and so a test can assert it.
export const ASSUMED_UPSTREAM_REQUESTS_PER_MINUTE = 20;

export interface AuthLimitPresets {
    // Total login attempts per address per minute, successful or not. This one
    // exists to bound OUTBOUND traffic to the upstream rather than to stop
    // guessing: at half the upstream's own budget, a single address cannot walk
    // the whole site into the upstream's lockout.
    loginAttempts: LimiterConfig;
    // Failed logins per address before a lockout. Intended to be consumed only
    // on failure and reset on success, so somebody who mistypes twice and then
    // gets it right is not one typo away from being locked out for the next
    // quarter of an hour.
    loginFailures: LimiterConfig;
    // Registrations per address per hour. Deliberately small: a real person
    // registers once. Note what this does NOT solve — per-IP limiting is no
    // answer to distributed automated signup, and if public registration matters
    // to you the answer is a challenge of some kind, which is a third-party
    // dependency and a privacy question this package does not take on.
    registrations: LimiterConfig;
    // One-time codes, invitations, or anything else the site MINTS on request.
    // A real person needs one, occasionally two when they mistype; ten leaves
    // room for a household behind one address and for somebody who lost the code
    // and clicked again, while keeping the endpoint from becoming a generator.
    //
    // It bounds ISSUING, not GUESSING. Whatever redeems the code needs its own
    // cap, because issuing and redeeming are attacked differently.
    issuedCodes: LimiterConfig;
}

export const recommendedAuthLimits: AuthLimitPresets = {
    loginAttempts: {
        // Half the assumed upstream budget.
        limit: 10,
        windowMs: MINUTE
    },
    loginFailures: {
        // Below the per-minute attempt budget, so a guesser meets the lockout
        // first rather than meeting the attempt ceiling and waiting a minute.
        limit: 5,
        windowMs: 15 * MINUTE,
        lockoutMs: 15 * MINUTE
    },
    registrations: {
        limit: 3,
        windowMs: 60 * MINUTE
    },
    issuedCodes: {
        limit: 10,
        windowMs: 60 * MINUTE
    }
};
