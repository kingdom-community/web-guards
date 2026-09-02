import {describe, expect, it} from 'vitest';

import {
    createSessionCookieRules,
    HOST_COOKIE_PREFIX,
    maxAgeFor,
    readCookie
} from '../src/session.js';

// The cookie rules.
//
// Most of this file asserts the `__Host-` prefix and the attributes it requires,
// because the prefix is the thing a browser enforces on our behalf and it is
// enforced ONLY if the name and the attributes agree. A cookie called
// `__Host-session` that carries a Domain is simply not stored, so the failure
// mode of getting this wrong is "login silently does nothing" — which is exactly
// the loudness the prefix was chosen for.

const NOW = Date.parse('2026-08-30T12:00:00Z');

const rules = createSessionCookieRules();

describe('the session cookies', () => {
    it('are named with the __Host- prefix by default', () => {
        expect(rules.sessionCookieName).toBe('__Host-session');
        expect(rules.refreshCookieName).toBe('__Host-refresh');
    });

    it('refuse a name without the prefix, with an error that says what to do', () => {
        // Not cosmetic. The prefix makes the cookie host-only BY SPECIFICATION,
        // so nobody can later "fix" a subdomain by adding a Domain attribute and
        // quietly ship the session token somewhere it must never go. Letting the
        // name drift is how that guarantee turns back into a convention.
        expect(() => createSessionCookieRules({sessionCookieName: 'session'}))
            .toThrow(/__Host-/);
        expect(() => createSessionCookieRules({refreshCookieName: 'refresh'}))
            .toThrow(/allowCookieNamesWithoutHostPrefix/);
    });

    it('accept custom names that keep the prefix', () => {
        const custom = createSessionCookieRules({
            sessionCookieName: `${HOST_COOKIE_PREFIX}harborlight_session`,
            refreshCookieName: `${HOST_COOKIE_PREFIX}harborlight_refresh`
        });

        expect(custom.sessionCookieName).toBe('__Host-harborlight_session');
        expect(custom.issued({token: 'jwt'}, NOW)[0]).toContain('__Host-harborlight_session=jwt');
    });

    it('has an escape hatch, and it still refuses to add a Domain', () => {
        // The hatch exists for a deployment that cannot serve a trustworthy
        // origin at all, where the browser would reject the prefixed cookie
        // anyway. It buys a name, not a scope: there is no way to get a
        // domain-scoped cookie out of this module.
        const unprefixed = createSessionCookieRules({
            sessionCookieName: 'session',
            refreshCookieName: 'refresh',
            allowCookieNamesWithoutHostPrefix: true
        });

        for (const cookie of unprefixed.issued({token: 'jwt', refreshToken: 'r'}, NOW)) {
            expect(cookie.toLowerCase()).not.toContain('domain=');
        }
    });

    it('carry every attribute the __Host- prefix requires', () => {
        const [session, refresh] = rules.issued(
            {token: 'jwt-value', expiresAt: '2026-08-30T13:00:00Z', refreshToken: 'refresh-value'},
            NOW
        );

        for (const cookie of [session, refresh]) {
            expect(cookie).toContain('Secure');
            expect(cookie).toContain('Path=/');
            expect(cookie).toContain('HttpOnly');
            expect(cookie).toContain('SameSite=Lax');
        }
    });

    it('carry NO Domain attribute, ever', () => {
        // A browser rejects a __Host- cookie that has one, so this assertion and
        // the browser are saying the same thing — but this one fails in CI rather
        // than in somebody's session.
        const cookies = rules.issued(
            {token: 'jwt-value', expiresAt: null, refreshToken: 'refresh-value'},
            NOW
        );

        for (const cookie of cookies) {
            expect(cookie.toLowerCase()).not.toContain('domain=');
        }
    });

    it('hold the upstream token verbatim rather than re-signing it', () => {
        // A second signature would add no property — a tampered token dies at
        // the upstream's validation endpoint anyway — and would create a secret
        // whose loss silently kills every live session.
        const [session] = rules.issued({token: 'header.payload.signature', expiresAt: null}, NOW);

        expect(session?.startsWith(`${rules.sessionCookieName}=header.payload.signature;`)).toBe(true);
    });

    it('expire with the token rather than outliving it', () => {
        const [session] = rules.issued({token: 'jwt', expiresAt: '2026-08-30T13:00:00Z'}, NOW);

        expect(session).toContain('Max-Age=3600');
    });

    it('never produce a cookie the browser would discard on arrival', () => {
        // A few seconds of clock skew between this container and the upstream
        // would otherwise mean Max-Age=0 or a negative number, which presents as
        // "login does nothing" — the same symptom as a rejected __Host- cookie,
        // and a miserable thing to tell apart.
        expect(maxAgeFor('2026-08-30T11:59:59Z', NOW)).toBeGreaterThanOrEqual(60);
        expect(maxAgeFor('2020-01-01T00:00:00Z', NOW)).toBeGreaterThanOrEqual(60);
    });

    it('fall back to a short life when the upstream reports no expiry it can read', () => {
        expect(maxAgeFor(null, NOW)).toBe(3600);
        expect(maxAgeFor('not-a-timestamp', NOW)).toBe(3600);
        expect(rules.maxAgeFor(undefined, NOW)).toBe(3600);
    });

    it('take the configured lifetimes when given them', () => {
        const custom = createSessionCookieRules({
            fallbackMaxAgeSeconds: 300,
            minMaxAgeSeconds: 30,
            refreshMaxAgeSeconds: 3600
        });

        expect(custom.maxAgeFor(null, NOW)).toBe(300);
        expect(custom.maxAgeFor('2026-08-30T11:59:00Z', NOW)).toBe(30);
        expect(custom.issued({token: 'jwt', refreshToken: 'r'}, NOW)[1]).toContain('Max-Age=3600');
    });

    it('omit the refresh cookie when the upstream issued no refresh token', () => {
        expect(rules.issued({token: 'jwt', expiresAt: null, refreshToken: null}, NOW)).toHaveLength(1);
        expect(rules.issued({token: 'jwt'}, NOW)).toHaveLength(1);
    });
});

describe('the value cannot end itself and start an attribute', () => {
    // A `Set-Cookie` header is a value followed by `;`-separated attributes, and
    // this module builds it by interpolation. So a `;` in a token does not
    // corrupt the cookie — it ENDS it and begins an attribute of the attacker's
    // choosing. Until this was checked, the "no cookie is ever domain-scoped"
    // guarantee above was a property of the tokens that happened to be passed
    // in rather than of this code.

    it('REFUSES a token that would smuggle in a Domain attribute', () => {
        expect(() => rules.issued({token: 'jwt; Domain=.evil.example'}, NOW))
            .toThrow(/cannot appear in a cookie value/);
    });

    it('refuses it through the escape hatch too, where the browser would store it', () => {
        // With the __Host- prefix the browser rejects the whole cookie and the
        // symptom is a silent sign-in failure. Without it — the one case the
        // hatch exists for — the browser stores a domain-scoped session cookie,
        // which is precisely the outcome the prefix exists to make impossible.
        const unprefixed = createSessionCookieRules({
            sessionCookieName: 'session',
            refreshCookieName: 'refresh',
            allowCookieNamesWithoutHostPrefix: true
        });

        expect(() => unprefixed.issued({token: 'jwt; Domain=.evil.example'}, NOW)).toThrow();
    });

    it('REFUSES every character that ends a value or a header', () => {
        for (const token of ['a;b', 'a b', 'a,b', 'a"b', 'a\\b', 'a\rb', 'a\nb', 'a\r\nSet-Cookie: x=y']) {
            expect(() => rules.issued({token}, NOW)).toThrow();
        }
    });

    it('REFUSES an empty token rather than writing a session that is not one', () => {
        // An empty value reads back through `readCookie` as null, so the caller
        // has written a signed-in response to a browser holding no session.
        expect(() => rules.issued({token: ''}, NOW)).toThrow(/No value was given/);
    });

    it('checks the refresh token by the same rule', () => {
        expect(() => rules.issued({token: 'jwt', refreshToken: 'r; Domain=.evil.example'}, NOW))
            .toThrow(/cannot appear in a cookie value/);
    });

    it('writes neither cookie when only the refresh token is bad', () => {
        // Not a half-written pair: the session cookie must not reach the browser
        // on a call that failed.
        expect(() => rules.issued({token: 'jwt', refreshToken: 'bad;value'}, NOW)).toThrow();
    });

    it('never repeats the value in the error, because the value is a session token', () => {
        // An error message carrying a live token is a live token in a log file.
        expect(() => rules.issued({token: 'secret-jwt; Domain=.evil.example'}, NOW))
            .toThrow(/cannot appear in a cookie value/);

        let message = '';
        try {
            rules.issued({token: 'secret-jwt; Domain=.evil.example'}, NOW);
        } catch (error) {
            message = (error as Error).message;
        }

        expect(message).not.toContain('secret-jwt');
        expect(message).not.toContain('evil.example');
    });

    it('names the offending character so the error is actionable', () => {
        expect(() => rules.issued({token: 'a;b'}, NOW)).toThrow(/";" \(U\+003B\)/);
        // A control character is named by its code point rather than printed —
        // printing it would break the log line it lands in.
        expect(() => rules.issued({token: 'a\nb'}, NOW)).toThrow(/U\+000A/);
    });

    it('still accepts the values a real upstream returns', () => {
        // The point is to reject what a cookie cannot carry, not to narrow what
        // a token may be. `=` in particular stays legal: base64 pads with it,
        // and only the first `=` in the header separates name from value.
        const [session, refresh] = rules.issued(
            {token: 'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0=.c2ln-_x', refreshToken: 'v1.abc_DEF-123=='},
            NOW
        );

        expect(session).toContain('=eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0=.c2ln-_x;');
        expect(refresh).toContain('=v1.abc_DEF-123==;');
    });
});

describe('the cookie NAME cannot carry an attribute either', () => {
    it('REFUSES a name that starts with the prefix and then ends itself', () => {
        // This one slips past the prefix check: it does start with `__Host-`.
        // The grammar check is what catches it, which is why it runs first.
        expect(() => createSessionCookieRules({sessionCookieName: '__Host-a; Domain=.evil.example'}))
            .toThrow(/not allowed in a cookie name/);
    });

    it('refuses a bad name through the escape hatch, which waives the prefix and nothing else', () => {
        expect(() => createSessionCookieRules({
            sessionCookieName: 'a;b',
            allowCookieNamesWithoutHostPrefix: true
        })).toThrow(/not allowed in a cookie name/);
    });

    it('REFUSES an empty name, and the separators a name may not contain', () => {
        expect(() => createSessionCookieRules({
            sessionCookieName: '',
            allowCookieNamesWithoutHostPrefix: true
        })).toThrow(/empty/);

        for (const name of ['a b', 'a=b', 'a,b', 'a\tb', 'a(b', 'a/b']) {
            expect(() => createSessionCookieRules({
                sessionCookieName: name,
                allowCookieNamesWithoutHostPrefix: true
            })).toThrow();
        }
    });

    it('checks the refresh cookie name too', () => {
        expect(() => createSessionCookieRules({refreshCookieName: '__Host-r; Domain=.evil.example'}))
            .toThrow(/not allowed in a cookie name/);
    });

    it('accepts the default names and any ordinary one', () => {
        expect(() => createSessionCookieRules()).not.toThrow();
        expect(() => createSessionCookieRules({
            sessionCookieName: '__Host-harborlight_session',
            refreshCookieName: '__Host-harborlight.refresh'
        })).not.toThrow();
    });
});

describe('clearing the session', () => {
    it('clears both cookies with the attributes they were written with', () => {
        // A browser matches on name, path and security attributes. A clear that
        // omits Secure or Path=/ silently leaves the cookie in place, and the user
        // stays logged in after clicking "sign out".
        const cleared = rules.cleared();

        expect(cleared).toHaveLength(2);
        expect(cleared[0]).toContain(rules.sessionCookieName);
        expect(cleared[1]).toContain(rules.refreshCookieName);
        for (const cookie of cleared) {
            expect(cookie).toContain('Max-Age=0');
            expect(cookie).toContain('Secure');
            expect(cookie).toContain('Path=/');
            expect(cookie).toContain('HttpOnly');
            expect(cookie.toLowerCase()).not.toContain('domain=');
        }
    });
});

describe('reading a cookie back', () => {
    const header = `theme=dark; ${rules.sessionCookieName}=jwt-value; ${rules.refreshCookieName}=refresh-value`;

    it('finds each token by its own name', () => {
        expect(rules.sessionTokenFrom(header)).toBe('jwt-value');
        expect(rules.refreshTokenFrom(header)).toBe('refresh-value');
    });

    it('does not match a name that merely ends with the cookie name', () => {
        // `not__Host-session` must not be read as the session.
        expect(rules.sessionTokenFrom(`not${rules.sessionCookieName}=forged`)).toBeNull();
    });

    it('answers null for no header, no cookie, and an empty value', () => {
        expect(rules.sessionTokenFrom(undefined)).toBeNull();
        expect(rules.sessionTokenFrom('theme=dark')).toBeNull();
        expect(rules.sessionTokenFrom(`${rules.sessionCookieName}=`)).toBeNull();
        expect(readCookie('malformed', 'anything')).toBeNull();
    });
});
