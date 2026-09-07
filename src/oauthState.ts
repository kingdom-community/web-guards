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

// AN EMPTY SUBJECT IS NOT AN IDENTIFIER, IT IS THE ABSENCE OF ONE.
//
// The binding is a comparison, and a comparison against a value meaning
// "nobody" succeeds for everybody else who also has nobody. A state issued for
// `''` verifies against a session subject of `''`, so two unauthenticated
// browsers share one subject and either can finish the other's flow — the
// attack described above, reached without forging anything. The shape that
// produces it is ordinary defensive code in a route: `issueState(session?.user
// ?? '', secret)`, or a subject read out of a request body, where a field that
// is absent or not a string reads back as the empty string.
//
// So an empty — or whitespace-only — subject is refused at BOTH ends. Issuing
// returns null, and verifying returns `unbound` whatever was signed, which is
// what makes a state issued before this rule existed unredeemable rather than
// merely unissuable: refusing only at the issuing end would leave every state
// already in a browser good for its full lifetime.
//
// Neither end rewrites a subject that survives the check. The emptiness test
// trims, the stored and compared value never does, so anything non-empty is
// signed and matched byte for byte exactly as before.

import {createHmac, randomBytes, timingSafeEqual} from 'node:crypto';

// How long a `state` stays valid by default. A person clicking through a consent
// screen takes seconds; ten minutes is generous for somebody who got distracted,
// and short enough that a state captured from a browser history or a proxy log
// is worthless by the time anybody reads it.
export const STATE_TTL_MS = 10 * 60 * 1000;

// `unbound` is the verdict for a flow that has no account on one side or the
// other: a state signed for an empty subject, or a callback presented with an
// empty session subject. It is deliberately NOT folded into `wrong-session`,
// which tells an operator that two identified accounts did not match — a
// different fact, and a different thing to go and look at.
export type StateVerdict =
    | {ok: true; subject: string}
    | {
        ok: false;
        reason: 'not-configured' | 'malformed' | 'bad-signature' | 'expired' | 'wrong-session' | 'unbound';
    };

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

// Whether a subject would bind the state to nothing. Whitespace-only counts:
// `' '` is no more an account than `''` is, and the check matches how an unset
// secret is recognised a few lines down. The `typeof` guard is for callers
// reaching this from JavaScript, where the parameter type is a suggestion.
const bindsToNothing = (subject: unknown): boolean =>
    typeof subject !== 'string' || subject.trim() === '';

// A `state` for a flow started by `subject`, which should be a stable account
// identifier and never the session token.
//
// Null when no state can be issued, which happens for two reasons. The secret
// is unset: answer 503 rather than start a flow that cannot be finished — an
// unsigned state is the one thing this flow must never send to the provider.
// Or `subject` is empty or whitespace-only: there is no account to bind to, so
// there is nobody to start a link for, and the answer belongs on the sign-in
// path rather than at the provider.
//
// One null for both is not an ambiguity the caller has to live with. It holds
// both arguments and can tell them apart before it ever calls: a secret it did
// not configure is its own deployment, a subject it does not have is its own
// session.
export const issueState = (
    subject: string,
    secret: string | undefined,
    now: number = Date.now(),
    ttlMs: number = STATE_TTL_MS
): string | null => {
    if (!secret || secret.trim() === '') {
        return null;
    }
    // Refused here so an unbindable state never reaches a browser, and refused
    // again in `verifyState` so the ones issued before this rule existed cannot
    // be redeemed either.
    if (bindsToNothing(subject)) {
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
    // Before the state is looked at at all: a caller with no account cannot be
    // the account a flow was started as. Checked against the session rather
    // than against the payload because it is a fact about this request, and
    // true however well-formed and well-signed the state turns out to be.
    if (bindsToNothing(sessionSubject)) {
        return {ok: false, reason: 'unbound'};
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
    // Not `malformed`: this is a payload this module used to write, so a state
    // carrying it is genuine and correctly signed. It is refused because what
    // it is bound to is nobody — which is the whole point of checking here as
    // well as at issue time. Ahead of the expiry check, because an unbindable
    // state is refused for the whole of its life and not only after it.
    if (bindsToNothing(payload.u)) {
        return {ok: false, reason: 'unbound'};
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
