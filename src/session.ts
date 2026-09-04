// The session cookies: their names, how they are written, and how they are
// cleared. Pure — no environment, no network — so the rules can be unit-tested
// and so there is exactly one place that knows how a session is represented.
//
// THE `__Host-` PREFIX IS LOAD-BEARING AND IS NOT COSMETIC.
//
// A browser will only accept a cookie so named if it is `Secure`, has `Path=/`,
// and carries NO `Domain` attribute — which makes it host-only BY SPECIFICATION
// rather than by everyone remembering. The threat is concrete, and it is not
// about the attacker you were thinking of.
//
// A community site does not stay one hostname for long. Somebody adds a map, a
// wiki, a status page, a game panel; each gets a subdomain, and at least one of
// them ends up being a proxy to something the site's operators did not write and
// do not audit — a third-party service, a self-signed origin reached over the
// public internet, a container someone set up in an evening. A session cookie
// scoped to `.example.com` is attached by the browser to every request to every
// one of those hosts.
//
// The dangerous moment is not the day somebody attacks that panel. It is the day
// somebody notices that logging in at `www.example.com` does not carry over to
// `example.com` and fixes it by adding one `Domain=` attribute. That change is a
// one-line diff, it is obviously correct to the person writing it, it makes the
// symptom go away, and it ships the session token to every subdomain the site
// will ever have — including the ones added after the reviewer stopped paying
// attention. Nothing in the review would look wrong.
//
// With `__Host-`, that diff does not work. The browser refuses the cookie
// outright and the mistake surfaces as "login stopped working" in the first
// minute of testing, which is the loudest and cheapest possible failure. The
// `www` case is then handled where it belongs: a redirect to the canonical host.
//
// NO COOKIE ISSUED BY THIS MODULE IS EVER DOMAIN-SCOPED, and the constructor
// refuses a cookie name without the prefix rather than letting the guarantee
// quietly become a convention.
//
// THE NAME AND THE VALUE ARE BOTH CHECKED, BECAUSE A `;` ENDS EITHER ONE.
//
// A `Set-Cookie` header is a value followed by attributes separated by `;`, and
// this module builds it by interpolation. So an unchecked `;` anywhere in the
// token — or in a configured cookie name — does not corrupt the cookie, it ENDS
// it and starts an attribute. A token of `jwt; Domain=.example.com` produces a
// header carrying a Domain, which is the one thing the paragraph above promises
// cannot come out of here. That the promise held at all was a property of the
// tokens that happened to be passed in, not of this code, and a guarantee that
// depends on its input being well-behaved is a convention again.
//
// So values must match RFC 6265's `cookie-octet` (US-ASCII minus control
// characters, whitespace, `"`, `,`, `;` and `\`) and names must match the HTTP
// `token` grammar, and anything else THROWS. The name is checked once, at
// construction, where the mistake is a configuration line. The value is checked
// per request, where the only source of a bad one is an upstream returning
// something this module cannot represent — and answering 500 there is right,
// because the alternatives are a cookie with an attribute nobody wrote or a
// session silently written as empty.
//
// The thrown error names the offending character and NEVER echoes the value:
// that value is a live session token, and an error message carrying it is a
// session token in a log file.
//
// (`__Host-` requires `Secure`, and `Secure` cookies work on `http://localhost`
// in every current browser, because localhost is treated as a trustworthy
// origin. So this costs nothing in local development.)
//
// THE COOKIE HOLDS THE UPSTREAM TOKEN VERBATIM AND DOES NOT RE-SIGN IT.
//
// If your session token comes from an authentication service that already signed
// it, a second signature adds no property: a tampered token dies at the
// upstream's validation endpoint anyway. It would only create a second secret
// whose loss silently kills every live session.
//
// httpOnly is what keeps the token out of `document.cookie`. It does not prevent
// cross-site scripting; it removes the prize. That matters more on a site that
// renders text typed by anyone who signed up than on one whose operators write
// all the content — and it matters more still when the token is an identity
// shared with other services, because then one stored-XSS post reaches every
// logged-in reader's account everywhere that identity is accepted.

export const HOST_COOKIE_PREFIX = '__Host-';

// RFC 6265 §4.1.1 `cookie-octet`: US-ASCII with the characters that would end
// the value removed — controls (CR and LF start a new header), space, the
// double quote, the comma, the semicolon and the backslash. Note that `=` is
// deliberately IN the set: base64 padding is legal inside a value, and only the
// FIRST `=` in the header separates the name from the value.
//
// Spelled out as code-point ranges rather than as a character class, because a
// class of escaped punctuation is unreadable against the RFC it is supposed to
// reproduce, and a wrong range here fails silently in the permissive direction.
const isCookieOctet = (code: number): boolean =>
    code === 0x21
    || (code >= 0x23 && code <= 0x2b)
    || (code >= 0x2d && code <= 0x3a)
    || (code >= 0x3c && code <= 0x5b)
    || (code >= 0x5d && code <= 0x7e);

// RFC 6265 §4.1.1 `cookie-name`, which is an HTTP `token`: US-ASCII minus
// control characters, space, and the separators. `__Host-session` and
// `__Host-refresh` both satisfy it, as does any name a reasonable person picks.
const TOKEN_PUNCTUATION = '!#$%&\'*+-.^_`|~';

const isTokenCharacter = (code: number): boolean =>
    (code >= 0x30 && code <= 0x39)
    || (code >= 0x41 && code <= 0x5a)
    || (code >= 0x61 && code <= 0x7a)
    || TOKEN_PUNCTUATION.includes(String.fromCodePoint(code));

// The offending character, named so the error is actionable — and named as a
// code point when printing it would be unreadable or would itself break the log
// line it lands in. Never the value it came out of: see the note above.
const describeCharacter = (character: string): string => {
    const code = character.codePointAt(0) ?? 0;
    const point = `U+${code.toString(16).toUpperCase().padStart(4, '0')}`;
    return code <= 0x20 || code === 0x7f ? point : `"${character}" (${point})`;
};

const firstDisallowed = (value: string, allowed: (code: number) => boolean): string | null => {
    for (const character of value) {
        if (!allowed(character.codePointAt(0) ?? 0)) {
            return character;
        }
    }
    return null;
};

export interface IssuedSession {
    token: string;
    // When the upstream says the token expires, as anything `Date.parse` reads.
    expiresAt?: string | null;
    refreshToken?: string | null;
}

export interface SessionCookieOptions {
    // Both default to `__Host-` names. Give them your own names if you like;
    // they must keep the prefix unless you deliberately opt out below.
    sessionCookieName?: string;
    refreshCookieName?: string;
    // A refresh token outlives the access token by design, and the exact
    // lifetime usually belongs to the upstream, which the website does not
    // learn. So the cookie is given a generous bound rather than a guessed one:
    // expiry is enforced by the upstream refusing the token, not by this number.
    refreshMaxAgeSeconds?: number;
    // Used when the upstream reports no expiry, or one that cannot be parsed. A
    // short session is the safe failure rather than a long or an
    // immediately-dead one.
    fallbackMaxAgeSeconds?: number;
    // A floor on the session cookie's Max-Age. The upstream's expiry drives it,
    // so the two expire together rather than the browser holding a cookie whose
    // contents are already dead — but a clock skew of a few seconds must not
    // produce a cookie the browser discards on arrival, which would present as
    // "login does nothing".
    minMaxAgeSeconds?: number;
    // The escape hatch, and it exists to be refused in code review. There is one
    // legitimate use: a deployment that genuinely cannot serve over HTTPS or a
    // trustworthy origin, where the browser would reject a `__Host-` cookie
    // regardless. Anything else that reaches for this is trying to add a
    // `Domain=` attribute, which is the exact mistake the prefix is here to
    // prevent.
    allowCookieNamesWithoutHostPrefix?: boolean;
}

const DEFAULTS = {
    sessionCookieName: '__Host-session',
    refreshCookieName: '__Host-refresh',
    refreshMaxAgeSeconds: 30 * 24 * 60 * 60,
    fallbackMaxAgeSeconds: 60 * 60,
    minMaxAgeSeconds: 60,
    allowCookieNamesWithoutHostPrefix: false
} as const;

// Read one cookie out of a raw `Cookie` header. Written by hand rather than
// pulled in as a dependency, because the parsing needed here is a couple of
// names and no options.
export const readCookie = (cookieHeader: string | undefined | null, name: string): string | null => {
    if (!cookieHeader) {
        return null;
    }
    for (const part of cookieHeader.split(';')) {
        const separator = part.indexOf('=');
        if (separator === -1) {
            continue;
        }
        if (part.slice(0, separator).trim() === name) {
            const value = part.slice(separator + 1).trim();
            return value === '' ? null : value;
        }
    }
    return null;
};

export interface MaxAgeOptions {
    fallbackMaxAgeSeconds?: number;
    minMaxAgeSeconds?: number;
}

export const maxAgeFor = (
    expiresAt: string | null | undefined,
    now: number = Date.now(),
    options: MaxAgeOptions = {}
): number => {
    const fallback = options.fallbackMaxAgeSeconds ?? DEFAULTS.fallbackMaxAgeSeconds;
    const floor = options.minMaxAgeSeconds ?? DEFAULTS.minMaxAgeSeconds;
    if (!expiresAt) {
        return fallback;
    }
    const parsed = Date.parse(expiresAt);
    if (Number.isNaN(parsed)) {
        return fallback;
    }
    return Math.max(floor, Math.floor((parsed - now) / 1000));
};

export interface SessionCookieRules {
    readonly sessionCookieName: string;
    readonly refreshCookieName: string;
    // The `Set-Cookie` values that start a session.
    issued(session: IssuedSession, now?: number): string[];
    // The `Set-Cookie` values that end one.
    cleared(): string[];
    maxAgeFor(expiresAt: string | null | undefined, now?: number): number;
    sessionTokenFrom(cookieHeader: string | undefined | null): string | null;
    refreshTokenFrom(cookieHeader: string | undefined | null): string | null;
}

// Checked at construction, where a bad name is a line of configuration and the
// right moment to fail is startup. Runs BEFORE the prefix check, because a name
// like `__Host-a; Domain=.example.com` starts with the prefix and would sail
// past it while still carrying an attribute into every header this module
// writes.
const assertCookieNameIsAToken = (name: string): void => {
    if (name === '') {
        throw new Error('A session cookie name is empty. It must be a non-empty HTTP token.');
    }
    const offender = firstDisallowed(name, isTokenCharacter);
    if (offender === null) {
        return;
    }
    throw new Error(
        `Session cookie name "${name}" contains ${describeCharacter(offender)}, which is not `
        + 'allowed in a cookie name. A semicolon or a space there would end the name and turn '
        + 'the rest of it into a cookie attribute. Use letters, digits, and any of '
        + `${TOKEN_PUNCTUATION} — and keep the "${HOST_COOKIE_PREFIX}" prefix.`
    );
};

// Checked per request, on the way into a header. The value is a session token,
// so it is named in the error only by the character that made it unusable.
const assertCookieValueIsOctets = (cookieName: string, value: string): void => {
    // `typeof` as well as the empty check, because the types stop a TypeScript
    // caller and this package also ships CommonJS to callers who have none.
    if (typeof value !== 'string' || value === '') {
        throw new Error(
            `No value was given for the "${cookieName}" cookie. Writing it anyway would set an `
            + 'empty cookie, which reads back as no session at all — a signed-out user who was '
            + 'told they signed in. Answer the request with an error instead.'
        );
    }
    const offender = firstDisallowed(value, isCookieOctet);
    if (offender === null) {
        return;
    }
    throw new Error(
        `The value for the "${cookieName}" cookie contains ${describeCharacter(offender)}, which `
        + 'cannot appear in a cookie value: it would end the value and start an attribute, so the '
        + 'browser would be sent a cookie nobody wrote. The value itself is not repeated here '
        + 'because it is a session token. Check what the upstream returned.'
    );
};

const assertHostPrefixed = (name: string, allowed: boolean): void => {
    if (allowed || name.startsWith(HOST_COOKIE_PREFIX)) {
        return;
    }
    throw new Error(
        `Session cookie name "${name}" does not start with "${HOST_COOKIE_PREFIX}". `
        + 'That prefix is what makes the browser refuse the cookie if it is ever given a '
        + 'Domain attribute, which is the mistake that ships a session token to every '
        + `subdomain. Rename the cookie to "${HOST_COOKIE_PREFIX}${name}", or — only if this `
        + 'deployment cannot serve over HTTPS or another trustworthy origin, where the browser '
        + 'would reject the prefixed cookie anyway — pass '
        + 'allowCookieNamesWithoutHostPrefix: true.'
    );
};

export const createSessionCookieRules = (options: SessionCookieOptions = {}): SessionCookieRules => {
    const settings = {...DEFAULTS, ...options};
    // Grammar first, prefix second. The escape hatch below waives the prefix and
    // nothing else — there is no option that waives the grammar, because a name
    // carrying a `;` is not a name a browser would have accepted either.
    assertCookieNameIsAToken(settings.sessionCookieName);
    assertCookieNameIsAToken(settings.refreshCookieName);
    assertHostPrefixed(settings.sessionCookieName, settings.allowCookieNamesWithoutHostPrefix);
    assertHostPrefixed(settings.refreshCookieName, settings.allowCookieNamesWithoutHostPrefix);

    const attributes = (maxAgeSeconds: number): string =>
        // SameSite=Lax blocks the cross-site POST case, which is the realistic
        // CSRF attack. It is not sufficient alone — see `csrf.ts` for the Origin
        // check that backs it up.
        `; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=${maxAgeSeconds}`;

    const ageFor = (expiresAt: string | null | undefined, now: number): number =>
        maxAgeFor(expiresAt, now, settings);

    return {
        sessionCookieName: settings.sessionCookieName,
        refreshCookieName: settings.refreshCookieName,
        maxAgeFor: (expiresAt, now = Date.now()) => ageFor(expiresAt, now),
        // Returned as a list because both cookies are always written together —
        // a rotated refresh token with a stale access token is a session that
        // half-works.
        issued: (session, now = Date.now()) => {
            // Both values are checked BEFORE either header is built, so a bad
            // refresh token cannot leave a caller holding a session cookie it
            // half-wrote. Nothing here is partially applied.
            assertCookieValueIsOctets(settings.sessionCookieName, session.token);
            if (session.refreshToken) {
                assertCookieValueIsOctets(settings.refreshCookieName, session.refreshToken);
            }

            const cookies = [
                `${settings.sessionCookieName}=${session.token}${attributes(ageFor(session.expiresAt, now))}`
            ];
            if (session.refreshToken) {
                cookies.push(
                    `${settings.refreshCookieName}=${session.refreshToken}`
                    + attributes(settings.refreshMaxAgeSeconds)
                );
            }
            return cookies;
        },
        // Both are cleared unconditionally and with the same attributes they were
        // written with — a browser matches on name, path and security
        // attributes, so a clear that omits `Secure` or `Path=/` silently leaves
        // the cookie in place and the user stays logged in after clicking "sign
        // out".
        //
        // Send these even when everything else about logging out failed. A user
        // who clicked logout must end up logged out of this site regardless of
        // what any upstream had to say about it.
        cleared: () => [
            `${settings.sessionCookieName}=; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=0`,
            `${settings.refreshCookieName}=; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=0`
        ],
        sessionTokenFrom: (cookieHeader) => readCookie(cookieHeader, settings.sessionCookieName),
        refreshTokenFrom: (cookieHeader) => readCookie(cookieHeader, settings.refreshCookieName)
    };
};
