import {describe, expect, it} from 'vitest';

import {issueState, STATE_TTL_MS, verifyState} from '../src/oauthState.js';

// The signed OAuth `state`, which is the ONLY thing standing between the
// provider's callback and somebody attaching their provider identity to another
// person's account. Every test here is a specific attack or a specific
// misconfiguration.

const SECRET = 'a-secret-nobody-else-has-0123456789';

describe('issuing a state', () => {
    it('produces a signed, opaque value', () => {
        const state = issueState('alice', SECRET);

        expect(state).toBeTruthy();
        expect(state).toContain('.');
        // The account identifier is inside the signed payload rather than in the
        // clear.
        expect(state).not.toContain('alice');
    });

    it('never repeats, so two flows started in the same moment are distinct', () => {
        const first = issueState('alice', SECRET, 1_000_000);
        const second = issueState('alice', SECRET, 1_000_000);

        expect(first).not.toEqual(second);
    });

    it('returns null when the signing secret is unset', () => {
        // The caller's cue to answer 503. An unsigned state is the one thing
        // this flow must never send to the provider.
        expect(issueState('alice', undefined)).toBeNull();
        expect(issueState('alice', '')).toBeNull();
        expect(issueState('alice', '   ')).toBeNull();
    });
});

describe('verifying a state', () => {
    it('accepts one this site issued for this session', () => {
        const state = issueState('alice', SECRET) as string;

        expect(verifyState(state, 'alice', SECRET)).toEqual({ok: true, subject: 'alice'});
    });

    it('REJECTS a callback with no state at all', () => {
        // The case a naive implementation waves through, because there is
        // nothing to compare and therefore nothing to mismatch.
        expect(verifyState(undefined, 'alice', SECRET)).toEqual({ok: false, reason: 'malformed'});
        expect(verifyState('', 'alice', SECRET)).toEqual({ok: false, reason: 'malformed'});
    });

    it('REJECTS an unsigned state', () => {
        const unsigned = Buffer.from(JSON.stringify({n: 'x', u: 'alice', e: Date.now() + 60_000}))
            .toString('base64')
            .replace(/=+$/, '');

        expect(verifyState(unsigned, 'alice', SECRET)).toEqual({ok: false, reason: 'malformed'});
        expect(verifyState(`${unsigned}.`, 'alice', SECRET)).toEqual({ok: false, reason: 'malformed'});
        expect(verifyState(`${unsigned}.not-a-signature`, 'alice', SECRET))
            .toEqual({ok: false, reason: 'bad-signature'});
    });

    it('REJECTS a state signed with a different secret', () => {
        const state = issueState('alice', 'some-other-secret') as string;

        expect(verifyState(state, 'alice', SECRET)).toEqual({ok: false, reason: 'bad-signature'});
    });

    it('REJECTS a state whose payload was edited', () => {
        // Signature is checked BEFORE the payload is parsed, so a tampered
        // payload never reaches JSON.parse.
        const state = issueState('alice', SECRET) as string;
        const [payload, signature] = state.split('.');
        const forged = Buffer.from(JSON.stringify({n: 'x', u: 'mallory', e: Date.now() + 60_000}))
            .toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');

        expect(payload).not.toEqual(forged);
        expect(verifyState(`${forged}.${signature}`, 'mallory', SECRET))
            .toEqual({ok: false, reason: 'bad-signature'});
    });

    it('REJECTS A STATE BOUND TO A DIFFERENT SESSION', () => {
        // THE attack this exists for. An attacker starts the flow themselves,
        // gets a perfectly valid signed state, and tries to finish it against
        // somebody else's session so that THEIR provider identity lands on the
        // victim's profile. The signature does not stop that; the binding does.
        const attackersState = issueState('mallory', SECRET) as string;

        expect(verifyState(attackersState, 'alice', SECRET)).toEqual({ok: false, reason: 'wrong-session'});
    });

    it('rejects an expired state', () => {
        const state = issueState('alice', SECRET, 1_000_000) as string;

        expect(verifyState(state, 'alice', SECRET, 1_000_000 + STATE_TTL_MS - 1)).toEqual({
            ok: true,
            subject: 'alice'
        });
        expect(verifyState(state, 'alice', SECRET, 1_000_000 + STATE_TTL_MS + 1))
            .toEqual({ok: false, reason: 'expired'});
    });

    it('honours a shorter configured lifetime', () => {
        const state = issueState('alice', SECRET, 1_000_000, 30_000) as string;

        expect(verifyState(state, 'alice', SECRET, 1_020_000)).toEqual({ok: true, subject: 'alice'});
        expect(verifyState(state, 'alice', SECRET, 1_040_000)).toEqual({ok: false, reason: 'expired'});
    });

    it('rejects everything when the secret is unset, rather than accepting anything', () => {
        const state = issueState('alice', SECRET) as string;

        expect(verifyState(state, 'alice', undefined)).toEqual({ok: false, reason: 'not-configured'});
        expect(verifyState(state, 'alice', '')).toEqual({ok: false, reason: 'not-configured'});
    });

    it('does not throw on a state of a different length from the expected signature', () => {
        // node's timingSafeEqual THROWS on differing lengths, which would turn a
        // forged state into a 500 and leak the expected length through the
        // difference between an error page and a redirect.
        expect(() => verifyState('a.b', 'alice', SECRET)).not.toThrow();
        expect(() => verifyState('....', 'alice', SECRET)).not.toThrow();
        expect(() => verifyState('x'.repeat(5000), 'alice', SECRET)).not.toThrow();
    });

    it('takes the first value when a query string repeats the parameter', () => {
        const state = issueState('alice', SECRET) as string;

        expect(verifyState([state, 'junk'], 'alice', SECRET)).toEqual({ok: true, subject: 'alice'});
        expect(verifyState(['junk', state], 'alice', SECRET)).toEqual({ok: false, reason: 'malformed'});
    });
});
