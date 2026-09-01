import {describe, expect, it} from 'vitest';

import {checkRequestOrigin, originVerdictStatus} from '../src/csrf.js';

// The origin check, isolated from the routes that run it.
//
// `SameSite=Lax` already blocks the realistic cross-site POST, so this is the
// second line rather than the first. It exists because Lax does not cover a
// same-site subdomain attacker, and because leaning on one flag for every
// state-changing route is thin. Most of the cases below are the two edges that
// fail OPEN in the natural implementation.

const BASE_URL = 'https://harborlight.example';

describe('checkRequestOrigin', () => {
    it('accepts a request from the site itself', () => {
        expect(checkRequestOrigin({origin: BASE_URL, baseUrl: BASE_URL})).toEqual({ok: true});
    });

    it('compares origins, not URLs', () => {
        // A Referer carries a path; an Origin does not. Comparing the raw strings
        // would refuse every same-origin form post that fell back to Referer.
        expect(checkRequestOrigin({referer: `${BASE_URL}/login?next=/account`, baseUrl: BASE_URL}))
            .toEqual({ok: true});
        expect(checkRequestOrigin({origin: BASE_URL, baseUrl: `${BASE_URL}/`})).toEqual({ok: true});
    });

    it('refuses another origin', () => {
        expect(checkRequestOrigin({origin: 'https://evil.example', baseUrl: BASE_URL}))
            .toEqual({ok: false, reason: 'mismatched-origin'});
    });

    it('refuses a subdomain of the site', () => {
        // The threat SameSite=Lax does not cover, and the same one the __Host-
        // cookie prefix closes from the other side. Sooner or later a community
        // site has a subdomain proxying something nobody audits.
        expect(checkRequestOrigin({origin: 'https://map.harborlight.example', baseUrl: BASE_URL}))
            .toEqual({ok: false, reason: 'mismatched-origin'});
    });

    it('refuses the same host on a different scheme or port', () => {
        expect(checkRequestOrigin({origin: 'http://harborlight.example', baseUrl: BASE_URL}).ok).toBe(false);
        expect(checkRequestOrigin({origin: 'https://harborlight.example:8443', baseUrl: BASE_URL}).ok)
            .toBe(false);
    });
});

describe('fail-closed edge one: neither Origin nor Referer', () => {
    // "Reject a mismatch" says nothing about the case where there is nothing to
    // mismatch, and sending neither header is the standard way around exactly
    // this control. The cost is accepted: a client that strips both cannot post
    // here, and every browser sends Origin on a cross-origin state-changing
    // request.

    it('REFUSES a request carrying neither header', () => {
        expect(checkRequestOrigin({baseUrl: BASE_URL})).toEqual({ok: false, reason: 'missing-origin'});
    });

    it('REFUSES headers that are present but empty', () => {
        expect(checkRequestOrigin({origin: '', referer: '', baseUrl: BASE_URL}))
            .toEqual({ok: false, reason: 'missing-origin'});
        expect(checkRequestOrigin({origin: '   ', referer: '   ', baseUrl: BASE_URL}))
            .toEqual({ok: false, reason: 'missing-origin'});
        expect(checkRequestOrigin({origin: undefined, referer: undefined, baseUrl: BASE_URL}))
            .toEqual({ok: false, reason: 'missing-origin'});
    });

    it('REFUSES the opaque origin a sandboxed or privacy-stripped client sends', () => {
        // `Origin: null` is not a URL and must not be treated as "no opinion".
        expect(checkRequestOrigin({origin: 'null', baseUrl: BASE_URL}))
            .toEqual({ok: false, reason: 'missing-origin'});
        expect(checkRequestOrigin({origin: 'null', referer: 'null', baseUrl: BASE_URL}))
            .toEqual({ok: false, reason: 'missing-origin'});
    });

    it('REFUSES an unparseable Origin rather than falling through to allowed', () => {
        expect(checkRequestOrigin({origin: 'not a url', baseUrl: BASE_URL}))
            .toEqual({ok: false, reason: 'missing-origin'});
    });

    it('does not accept a request whose only usable header is an empty array', () => {
        // Repeated headers arrive as arrays in Node; an empty one is still no
        // header.
        expect(checkRequestOrigin({origin: [], referer: [], baseUrl: BASE_URL}))
            .toEqual({ok: false, reason: 'missing-origin'});
    });

    it('reports missing-origin, not mismatched-origin, so the logs stay honest', () => {
        // Different problems: one is a client that sent nothing, the other is
        // somebody else's page posting here. Collapsing them loses the signal
        // that somebody is probing the control rather than tripping over it.
        const absent = checkRequestOrigin({baseUrl: BASE_URL});
        const wrong = checkRequestOrigin({origin: 'https://evil.example', baseUrl: BASE_URL});

        expect(absent.ok).toBe(false);
        expect(wrong.ok).toBe(false);
        expect(absent).not.toEqual(wrong);
    });

    it('prefers Origin over Referer when both are present', () => {
        // Origin cannot be set by page script; Referer can be suppressed and, in
        // some contexts, influenced.
        expect(checkRequestOrigin({
            origin: 'https://evil.example',
            referer: `${BASE_URL}/login`,
            baseUrl: BASE_URL
        })).toEqual({ok: false, reason: 'mismatched-origin'});
    });

    it('falls back to Referer only when Origin is genuinely unusable', () => {
        expect(checkRequestOrigin({origin: '', referer: `${BASE_URL}/login`, baseUrl: BASE_URL}))
            .toEqual({ok: true});
        expect(checkRequestOrigin({origin: 'null', referer: `${BASE_URL}/login`, baseUrl: BASE_URL}))
            .toEqual({ok: true});
    });
});

describe('fail-closed edge two: the base URL is unset', () => {
    // The more dangerous of the two, because it is a deploy-time mistake rather
    // than a request-time one. A site that reads its own base URL from
    // configuration can be deployed without it — and where the framework inlines
    // public variables at BUILD time, that is baked into an image rather than
    // fixable with a restart. Such a build would compare every Origin against
    // undefined: passing nothing, or passing everything, depending on how the
    // comparison happened to be written. So the routes disable themselves
    // instead.

    it('reports not-configured rather than passing, for every shape of unset', () => {
        expect(checkRequestOrigin({origin: BASE_URL, baseUrl: undefined}))
            .toEqual({ok: false, reason: 'not-configured'});
        expect(checkRequestOrigin({origin: BASE_URL, baseUrl: ''}))
            .toEqual({ok: false, reason: 'not-configured'});
        expect(checkRequestOrigin({origin: BASE_URL, baseUrl: '   '}))
            .toEqual({ok: false, reason: 'not-configured'});
        expect(checkRequestOrigin({origin: BASE_URL, baseUrl: 'not a url'}))
            .toEqual({ok: false, reason: 'not-configured'});
        expect(checkRequestOrigin({origin: BASE_URL, baseUrl: 'undefined'}))
            .toEqual({ok: false, reason: 'not-configured'});
    });

    it('refuses even a request that would otherwise be perfectly valid', () => {
        // The whole point. There is no third option where the check is silently
        // skipped because it cannot be applied.
        expect(checkRequestOrigin({
            origin: BASE_URL,
            referer: `${BASE_URL}/account`,
            baseUrl: undefined
        })).toEqual({ok: false, reason: 'not-configured'});
    });

    it('decides not-configured BEFORE looking at the headers', () => {
        // Ordering matters: a request with no headers and no base URL must
        // report the operator's problem, not the client's, or a broken deploy
        // reads in the logs as a wave of rejected requests.
        expect(checkRequestOrigin({baseUrl: undefined}))
            .toEqual({ok: false, reason: 'not-configured'});
    });

    it('answers 503, which is the loud half of failing closed', () => {
        // A 403 here would look like a rejected request and hide a broken
        // deploy. 503 is ours to fix and says so.
        expect(originVerdictStatus(checkRequestOrigin({origin: BASE_URL, baseUrl: undefined}))).toBe(503);
    });
});

describe('what the caller is told', () => {
    it('distinguishes our misconfiguration from their bad request', () => {
        // 503 is ours to fix; 403 is theirs. Collapsing them would hide a broken
        // deploy behind what looks like a rejected request.
        expect(originVerdictStatus({ok: false, reason: 'not-configured'})).toBe(503);
        expect(originVerdictStatus({ok: false, reason: 'missing-origin'})).toBe(403);
        expect(originVerdictStatus({ok: false, reason: 'mismatched-origin'})).toBe(403);
        expect(originVerdictStatus({ok: true})).toBe(200);
    });
});
