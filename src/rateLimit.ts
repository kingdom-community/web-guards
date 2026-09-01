// A fixed-window rate limiter with optional lockout. Pure, injectable clock, no
// storage: the counters live in module memory in whatever process imports it and
// reset on restart.
//
// That last weakness is accepted rather than overlooked. The alternative is a
// database write per attempt, which turns the login page into a write endpoint
// for anyone who can send requests to it — a worse trade for a community site
// than losing the counters on a deploy. It is also per-process rather than
// per-fleet: two containers behind a load balancer keep two sets of counters, so
// the effective budget is the configured one multiplied by the number of
// replicas. Both facts are in the README, because a limiter whose weaknesses are
// undocumented is a limiter somebody will trust for something it cannot do.
//
// WHY THE LIMIT BELONGS AT THE EDGE THAT CAN SEE THE CALLER
//
// A website in front of an internal API is usually the only component
// positioned to see who is calling. Every browser-originated request the API
// sees arrives from the website's container, so a limiter there keyed on the
// peer address would treat the entire site as one client and the first abuser
// would lock out every visitor at once. The API's own budget should be keyed on
// the thing only it can see — the account — and the two together cover "per
// account and per originating address".
//
// WHY YOUR OWN BUDGET MUST SIT BELOW THE UPSTREAM SERVICE'S
//
// This is the non-obvious constraint, and it is the reason the numbers are not a
// free knob.
//
// If your site forwards logins to an upstream authentication service, that
// service almost certainly runs a per-IP limiter of its own. For every request
// originating from your site it sees YOUR CONTAINER'S address, so as far as it
// is concerned the entire site is one client. If a burst of failed logins
// reaches the upstream bucket before it reaches yours, the lockout that follows
// is not on the attacker: it is on your website, and every login on the site
// fails until it clears. Yours has to trip first, or the abuse mitigation IS the
// outage.
//
// So pick your numbers against that ceiling: your per-minute budget strictly
// below the upstream's, and your failed-login lockout below your own per-minute
// budget so the lockout is what a guesser meets first. `recommendedAuthLimits`
// in this package is one worked example of that arithmetic.

export interface LimiterConfig {
    // Attempts allowed inside one window before the limiter starts refusing.
    limit: number;
    windowMs: number;
    // When set, exceeding the limit refuses everything from that key for this
    // long — a lockout rather than a rolling budget. Used for failed logins,
    // where the point is to stop guessing rather than to smooth traffic.
    lockoutMs?: number;
    // Keys are client addresses and addresses arrive from the internet, so the
    // map is bounded. Reaching the bound sweeps expired entries and, failing
    // that, clears — which costs an attacker's counter as well as everyone
    // else's, so the bound is generous.
    maxKeys?: number;
}

export interface Decision {
    allowed: boolean;
    // Seconds until the caller may try again. Zero when allowed. Suitable for a
    // Retry-After header, which is where it goes.
    retryAfterSeconds: number;
}

const ALLOWED: Decision = {allowed: true, retryAfterSeconds: 0};

interface Bucket {
    windowStart: number;
    count: number;
    lockedUntil: number;
}

const seconds = (milliseconds: number): number => Math.max(1, Math.ceil(milliseconds / 1000));

export class RateLimiter {
    private readonly config: Required<LimiterConfig>;
    private readonly buckets = new Map<string, Bucket>();

    constructor(config: LimiterConfig) {
        this.config = {
            lockoutMs: 0,
            maxKeys: 10000,
            ...config
        };
    }

    // Whether this key would be served right now, WITHOUT spending anything.
    // Used to answer a locked-out caller before doing any work on their behalf.
    check(key: string, now: number = Date.now()): Decision {
        const bucket = this.buckets.get(key);
        if (!bucket) {
            return ALLOWED;
        }
        if (bucket.lockedUntil > now) {
            return {allowed: false, retryAfterSeconds: seconds(bucket.lockedUntil - now)};
        }
        if (now - bucket.windowStart >= this.config.windowMs) {
            return ALLOWED;
        }
        if (bucket.count >= this.config.limit) {
            return {allowed: false, retryAfterSeconds: seconds(bucket.windowStart + this.config.windowMs - now)};
        }
        return ALLOWED;
    }

    // Record one attempt and say whether it is allowed. The attempt that crosses
    // the limit is itself refused — the limit is a ceiling, not a warning line.
    consume(key: string, now: number = Date.now()): Decision {
        const refusal = this.check(key, now);
        if (!refusal.allowed) {
            return refusal;
        }

        const existing = this.buckets.get(key);
        const bucket: Bucket =
            existing && now - existing.windowStart < this.config.windowMs && existing.lockedUntil <= now
                ? {...existing, count: existing.count + 1}
                : {windowStart: now, count: 1, lockedUntil: 0};

        if (bucket.count >= this.config.limit && this.config.lockoutMs > 0) {
            bucket.lockedUntil = now + this.config.lockoutMs;
        }

        this.buckets.set(key, bucket);
        this.evictIfOversized(now);

        // This attempt is allowed: it is the limit-th, not the limit-plus-first.
        // If it just armed the lockout, the NEXT one is refused — and refused for
        // lockoutMs rather than until the window rolls over.
        return ALLOWED;
    }

    // Forget a key's history. Called after a successful login so that a person
    // who mistyped their password twice and then got it right is not one typo
    // away from a lockout for the next quarter of an hour.
    reset(key: string): void {
        this.buckets.delete(key);
    }

    size(): number {
        return this.buckets.size;
    }

    // Forget everything. A test seam: a running site never needs it, because the
    // counters are process-local and die with the process.
    clear(): void {
        this.buckets.clear();
    }

    private evictIfOversized(now: number): void {
        if (this.buckets.size <= this.config.maxKeys) {
            return;
        }
        for (const [key, bucket] of this.buckets) {
            const windowOver = now - bucket.windowStart >= this.config.windowMs;
            if (windowOver && bucket.lockedUntil <= now) {
                this.buckets.delete(key);
            }
        }
        if (this.buckets.size > this.config.maxKeys) {
            this.buckets.clear();
        }
    }
}
