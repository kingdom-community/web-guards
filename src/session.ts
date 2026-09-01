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
