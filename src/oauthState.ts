// The OAuth `state` a site issues to a browser and later checks, signed with a
// secret the site holds.
//
// Pure — the secret is passed in, nothing here reads the environment or the
// network — so the rules below can be unit-tested including the cases that only
// happen when somebody is attacking them.
//
// WHAT THE SECRET SIGNS, PRECISELY: THIS, AND NOTHING ELSE.
//
// It should NOT also sign the session cookie. If that cookie carries a token an
// authentication service already signed with a key this site does not hold, a
// second signature over it adds no security property — a tampered token dies at
// the upstream's validation endpoint regardless — while creating a second secret
// whose loss silently invalidates every live session. The secret here is for
// values THIS SITE issues to browsers that nobody else has already signed, and
// the OAuth `state` is usually the only one.
//
// State this operationally, wherever you document your configuration: an unset
// signing secret disables account linking and nothing else. A reader who knows
// that will not go looking for it when logins break.
//
// WHY THE STATE IS BOUND TO THE SESSION RATHER THAN MERELY RANDOM.
//
// A random, unbound state stops a replayed callback. It does not stop the
// interesting attack, which is an attacker completing the provider's consent
// screen with THEIR account against YOUR session, landing their provider
// identity on your profile. Binding the state to the account the flow started as
// lets the callback check that the browser finishing the flow is the one that
// started it.
//
// Bind to a STABLE ACCOUNT IDENTIFIER — a canonical username, a user id —
// rather than to the session token itself. Access tokens rotate: an expired one
// is silently renewed mid-request, so a state bound to the token would break for
// anybody whose session happened to refresh during the twenty seconds they spent
// on the consent screen, and it would break in a way indistinguishable from an
// attack. The account identifier is stable and is exactly the fact the check
// needs: this callback belongs to this account.
//
// The signature means no server-side state table is needed for a flow that is
// over in seconds, and no cleanup job for the rows it would leave behind.

import {createHmac, randomBytes, timingSafeEqual} from 'node:crypto';

// How long a `state` stays valid by default. A person clicking through a consent
// screen takes seconds; ten minutes is generous for somebody who got distracted,
// and short enough that a state captured from a browser history or a proxy log
// is worthless by the time anybody reads it.
export const STATE_TTL_MS = 10 * 60 * 1000;

export type StateVerdict =
    | {ok: true; subject: string}
    | {ok: false; reason: 'not-configured' | 'malformed' | 'bad-signature' | 'expired' | 'wrong-session'};

// base64url, by hand rather than by dependency: two replaces and a strip.
const encode = (value: string): string =>
    Buffer.from(value, 'utf8').toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');

const decode = (value: string): string =>
    Buffer.from(value.replace(/-/g, '+').replace(/_/g, '/'), 'base64').toString('utf8');

const sign = (payload: string, secret: string): string =>
    createHmac('sha256', secret).update(payload).digest('base64')
        .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');

// Constant time, and length-safe: `timingSafeEqual` THROWS on differing lengths,
// which would turn a forged state into a 500 and leak the expected length
// through the difference between an error page and a redirect.
const equals = (a: string, b: string): boolean => {
    const left = Buffer.from(a, 'utf8');
    const right = Buffer.from(b, 'utf8');
    return left.length === right.length && timingSafeEqual(left, right);
};

// A `state` for a flow started by `subject`, which should be a stable account
// identifier and never the session token. Null when the secret is unset, which
// is the caller's cue to answer 503 rather than to start a flow it cannot
// finish — an unsigned state is the one thing this flow must never send to the
// provider.
export const issueState = (
    subject: string,
    secret: string | undefined,
    now: number = Date.now(),
    ttlMs: number = STATE_TTL_MS
): string | null => {
    if (!secret || secret.trim() === '') {
        return null;
    }
    // The nonce makes two states issued in the same millisecond for the same
    // account differ. It is not itself checked against anything — there is no
    // server-side table to check it against, by design — so its job is to keep
    // the signed payload from being a value somebody could accumulate copies of.
    const payload = JSON.stringify({
        n: randomBytes(16).toString('hex'),
        u: subject,
        e: now + ttlMs
    });
    const encoded = encode(payload);
    return `${encoded}.${sign(encoded, secret)}`;
};

// Check a `state` coming back from the provider against the session finishing
// the flow.
//
// Every failure is a distinct reason, because they mean different things to an
// operator reading logs — a `bad-signature` is somebody probing, an `expired` is
// a person who left the tab open — and identical things to the visitor, who is
// told the flow could not be completed either way.
export const verifyState = (
    state: string | string[] | undefined,
    sessionSubject: string,
    secret: string | undefined,
    now: number = Date.now()
): StateVerdict => {
    if (!secret || secret.trim() === '') {
        return {ok: false, reason: 'not-configured'};
    }
    const raw = Array.isArray(state) ? state[0] : state;
    if (!raw || typeof raw !== 'string') {
        // A callback with NO state at all is the case a naive implementation
        // waves through, because there is nothing to compare and nothing to
        // mismatch. It is rejected.
        return {ok: false, reason: 'malformed'};
    }

    const separator = raw.lastIndexOf('.');
    if (separator <= 0 || separator === raw.length - 1) {
        return {ok: false, reason: 'malformed'};
    }
    const encoded = raw.slice(0, separator);
    const signature = raw.slice(separator + 1);

    // SIGNATURE FIRST, ALWAYS. Parsing attacker-controlled JSON before checking
    // that we wrote it is how a malformed payload becomes a crash instead of a
    // refusal.
    if (!equals(signature, sign(encoded, secret))) {
        return {ok: false, reason: 'bad-signature'};
    }

    let payload: {n?: unknown; u?: unknown; e?: unknown};
    try {
        payload = JSON.parse(decode(encoded)) as {n?: unknown; u?: unknown; e?: unknown};
    } catch {
        return {ok: false, reason: 'malformed'};
    }
    if (typeof payload.u !== 'string' || typeof payload.e !== 'number') {
        return {ok: false, reason: 'malformed'};
    }
    if (payload.e <= now) {
        return {ok: false, reason: 'expired'};
    }
    // THE BINDING. Without this line the state is merely unforgeable, and an
    // attacker who obtains one — by starting a flow themselves — can finish it
    // against somebody else's session and land their provider identity on that
    // profile.
    if (payload.u !== sessionSubject) {
        return {ok: false, reason: 'wrong-session'};
    }
    return {ok: true, subject: payload.u};
};
