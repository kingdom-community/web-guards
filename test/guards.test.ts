import {describe, expect, it, vi} from 'vitest';

import {
    methodNotAllowed,
    originVerdictFor,
    refuseCrossOriginRequest,
    refuseIfLimited,
    requestAddress,
    stringField,
    type ApiError,
    type GuardRequest,
    type GuardResponse
} from '../src/guards.js';
import {RateLimiter} from '../src/rateLimit.js';

const BASE_URL = 'https://harborlight.example';

// A response recorder shaped exactly like the part of a route response these
// guards touch. A Next.js `NextApiResponse` satisfies the same interface, which
// is why nothing here imports a framework.
interface Recorded {
    headers: Record<string, string>;
    status: number | null;
    body: ApiError | null;
}

const recorder = (): GuardResponse & {recorded: Recorded} => {
    const recorded: Recorded = {headers: {}, status: null, body: null};
    return {
        recorded,
        setHeader(name: string, value: string) {
            recorded.headers[name] = value;
            return undefined;
        },
        status(code: number) {
            recorded.status = code;
            return {
                json(body: ApiError) {
                    recorded.body = body;
                    return undefined;
                }
            };
        }
    };
};

const request = (headers: GuardRequest['headers'], socketAddress?: string): GuardRequest => ({
    headers,
    socket: socketAddress === undefined ? null : {remoteAddress: socketAddress}
});

describe('methodNotAllowed', () => {
    it('answers 405 and says which methods are allowed', () => {
        const response = recorder();

        methodNotAllowed(response, ['POST', 'DELETE']);

        expect(response.recorded.status).toBe(405);
        expect(response.recorded.headers.Allow).toBe('POST, DELETE');
        expect(response.recorded.body?.error).toBe('method_not_allowed');
    });
});

describe('requestAddress', () => {
    it('reads the forwarded header rather than the socket', () => {
        expect(requestAddress(request({'x-real-ip': '203.0.113.7'}, '172.18.0.4')))
            .toBe('203.0.113.7');
    });

    it('tolerates a request with no socket at all', () => {
        expect(requestAddress(request({}))).toBe('unknown');
    });

    it('tolerates a socket whose remote address is null', () => {
        // `GuardRequest` admits null as well as undefined here. Either way the
        // request still lands in the shared bucket rather than going unkeyed.
        expect(requestAddress({headers: {}, socket: {remoteAddress: null}})).toBe('unknown');
    });

    it('passes the header bag through without lower-casing it first', () => {
        expect(requestAddress(request({'X-Real-Ip': '203.0.113.7'}, '172.18.0.4'))).toBe('203.0.113.7');
    });
});

describe('refuseCrossOriginRequest', () => {
    it('lets a same-origin request through and writes nothing', () => {
        const response = recorder();

        const refused = refuseCrossOriginRequest(
            request({origin: BASE_URL}),
            response,
            {baseUrl: BASE_URL}
        );

        expect(refused).toBe(false);
        expect(response.recorded.status).toBeNull();
    });

    it('answers 403 to another origin', () => {
        const response = recorder();

        const refused = refuseCrossOriginRequest(
            request({origin: 'https://evil.example'}),
            response,
            {baseUrl: BASE_URL}
        );

        expect(refused).toBe(true);
        expect(response.recorded.status).toBe(403);
        expect(response.recorded.body?.error).toBe('forbidden_origin');
    });

    it('answers 403 to a request carrying neither Origin nor Referer', () => {
        const response = recorder();

        expect(refuseCrossOriginRequest(request({}), response, {baseUrl: BASE_URL})).toBe(true);
        expect(response.recorded.status).toBe(403);
    });

    it('answers 503 and LOGS when the base URL is unset', () => {
        // The loudness is the feature. A silent 403 here would read as a wave of
        // rejected requests rather than as a broken deploy.
        const response = recorder();
        const log = vi.fn();

        const refused = refuseCrossOriginRequest(
            request({origin: BASE_URL}),
            response,
            {baseUrl: undefined, baseUrlSetting: 'PUBLIC_BASE_URL', log}
        );

        expect(refused).toBe(true);
        expect(response.recorded.status).toBe(503);
        expect(response.recorded.body?.error).toBe('not_configured');
        expect(log).toHaveBeenCalledTimes(1);
        expect(log.mock.calls[0]?.[0]).toContain('PUBLIC_BASE_URL');
    });

    it('does not leak the configured base URL to the caller', () => {
        const response = recorder();

        refuseCrossOriginRequest(request({origin: 'https://evil.example'}), response, {baseUrl: BASE_URL});

        expect(JSON.stringify(response.recorded.body)).not.toContain('harborlight');
    });
});

describe('an unusable base URL is our problem, never theirs', () => {
    // `csrf.ts` folds every base URL with no origin to compare into
    // `not-configured`. These cases follow each spelling through to the route's
    // answer: a 503 with a log line, never a 403 that would pass for a wave of
    // rejected requests, and never a request let through.
    const unusable: [string, string | undefined][] = [
        ['unset', undefined],
        ['empty', ''],
        ['whitespace-only', '   '],
        ['unparseable', 'not a url'],
        ['missing its scheme, so parsed to an opaque origin', 'localhost:3000']
    ];

    for (const [label, baseUrl] of unusable) {
        it(`answers 503 and logs once when the base URL is ${label}`, () => {
            const response = recorder();
            const log = vi.fn();

            const refused = refuseCrossOriginRequest(
                request({origin: BASE_URL}),
                response,
                {baseUrl, baseUrlSetting: 'PUBLIC_BASE_URL', log}
            );

            expect(refused).toBe(true);
            expect(response.recorded.status).toBe(503);
            expect(response.recorded.body?.error).toBe('not_configured');
            expect(log).toHaveBeenCalledTimes(1);
        });
    }

    it('names a generic setting in the log when the caller gives no name', () => {
        const log = vi.fn();

        refuseCrossOriginRequest(request({origin: BASE_URL}), recorder(), {baseUrl: undefined, log});

        expect(log.mock.calls[0]?.[0]).toContain('the site base URL');
    });

    it('logs to console.error when no log callback is given', () => {
        // The default is loud on purpose. Replacing it is supported; omitting it
        // must not mean silence.
        const consoleError = vi.spyOn(console, 'error').mockImplementation(() => undefined);
        try {
            refuseCrossOriginRequest(request({origin: BASE_URL}), recorder(), {baseUrl: undefined});

            expect(consoleError).toHaveBeenCalledTimes(1);
        } finally {
            consoleError.mockRestore();
        }
    });

    it('keeps the setting name out of the body the caller receives', () => {
        const response = recorder();

        refuseCrossOriginRequest(
            request({origin: BASE_URL}),
            response,
            {baseUrl: undefined, baseUrlSetting: 'PUBLIC_BASE_URL', log: () => undefined}
        );

        expect(JSON.stringify(response.recorded.body)).not.toContain('PUBLIC_BASE_URL');
    });
});

describe('a refused request is not a configuration error', () => {
    // The log line is reserved for the 503. A 403 that also logged would bury
    // the one line an operator needs under one per rejected request.

    it('writes no log line for another origin', () => {
        const log = vi.fn();

        refuseCrossOriginRequest(request({origin: 'https://evil.example'}), recorder(), {baseUrl: BASE_URL, log});

        expect(log).not.toHaveBeenCalled();
    });

    it('writes no log line for a request carrying neither header', () => {
        const log = vi.fn();

        refuseCrossOriginRequest(request({}), recorder(), {baseUrl: BASE_URL, log});

        expect(log).not.toHaveBeenCalled();
    });
});

describe('which headers the route-level origin check reads', () => {
    it('falls back to Referer for a same-origin post that carries no Origin', () => {
        const response = recorder();

        const refused = refuseCrossOriginRequest(
            request({referer: `${BASE_URL}/login`}),
            response,
            {baseUrl: BASE_URL}
        );

        expect(refused).toBe(false);
        expect(response.recorded.status).toBeNull();
    });

    // `GuardRequest['headers']` is a structural record, not Node's
    // `IncomingHttpHeaders`, so a caller can hand over `Origin` or `Referer` as
    // spelled on the wire. Reading those as absent would refuse every post with
    // a 403 that blames the caller for an integration mismatch.
    it('reads an Origin key spelled with a capital letter', () => {
        const response = recorder();

        const refused = refuseCrossOriginRequest(
            request({Origin: BASE_URL}),
            response,
            {baseUrl: BASE_URL}
        );

        expect(refused).toBe(false);
        expect(response.recorded.status).toBeNull();
    });

    it('reads a Referer key spelled with a capital letter', () => {
        expect(originVerdictFor(request({Referer: `${BASE_URL}/login`}), BASE_URL)).toEqual({ok: true});
    });

    it('still refuses another origin whatever the key is spelled', () => {
        // Matching the key is not matching the value: a found Origin goes
        // through the same comparison as a lower-cased one.
        expect(originVerdictFor(request({ORIGIN: 'https://evil.example'}), BASE_URL))
            .toEqual({ok: false, reason: 'mismatched-origin'});
    });

    it('still refuses a capitalised but empty Origin as carrying no origin', () => {
        expect(originVerdictFor(request({Origin: '', Referer: '   '}), BASE_URL))
            .toEqual({ok: false, reason: 'missing-origin'});
    });

    it('prefers the exact lower-case spelling, which is the one Node produces', () => {
        expect(originVerdictFor(request({origin: 'https://evil.example', Origin: BASE_URL}), BASE_URL))
            .toEqual({ok: false, reason: 'mismatched-origin'});
    });

    it('does not let a lower-case key with no value hide the capitalised one', () => {
        // A merged bag — defaults spread under the wire's headers — can carry
        // the key with nothing in it. Stopping there would answer a same-origin
        // post with a 403 that blames the caller for the bag's shape.
        const response = recorder();

        const refused = refuseCrossOriginRequest(
            request({origin: undefined, Origin: BASE_URL}),
            response,
            {baseUrl: BASE_URL}
        );

        expect(refused).toBe(false);
        expect(response.recorded.status).toBeNull();
        expect(originVerdictFor(request({referer: undefined, Referer: `${BASE_URL}/login`}), BASE_URL))
            .toEqual({ok: true});
    });

    it('does not let one capitalised key with no value hide another', () => {
        // The scan skips an empty key for the same reason the direct lookup
        // does; otherwise key order alone would decide whether the header is seen.
        expect(originVerdictFor(request({Origin: undefined, ORIGIN: BASE_URL}), BASE_URL))
            .toEqual({ok: true});
    });

    it('still refuses another origin found behind a key with no value', () => {
        // Finding the value is not accepting it. This is `mismatched-origin`,
        // not the `missing-origin` the empty key used to produce.
        expect(originVerdictFor(request({origin: undefined, Origin: 'https://evil.example'}), BASE_URL))
            .toEqual({ok: false, reason: 'mismatched-origin'});
    });
});

describe('refuseIfLimited', () => {
    it('lets an allowed decision through', () => {
        const response = recorder();

        expect(refuseIfLimited(response, {allowed: true, retryAfterSeconds: 0}, 'slow down')).toBe(false);
        expect(response.recorded.status).toBeNull();
    });

    it('answers 429 with Retry-After in both the header and the body', () => {
        const limiter = new RateLimiter({limit: 1, windowMs: 60_000});
        const now = 1_700_000_000_000;
        limiter.consume('203.0.113.7', now);
        const response = recorder();

        const refused = refuseIfLimited(
            response,
            limiter.consume('203.0.113.7', now + 15_000),
            'Too many attempts. Try again shortly.'
        );

        expect(refused).toBe(true);
        expect(response.recorded.status).toBe(429);
        expect(response.recorded.headers['Retry-After']).toBe('45');
        expect(response.recorded.body?.retryAfterSeconds).toBe(45);
    });
});

describe('stringField', () => {
    it('reads a string field', () => {
        expect(stringField({username: 'alice'}, 'username')).toBe('alice');
    });

    it('answers an empty string rather than throwing on anything unexpected', () => {
        expect(stringField(null, 'username')).toBe('');
        expect(stringField('a string body', 'username')).toBe('');
        expect(stringField({username: 42}, 'username')).toBe('');
        expect(stringField({}, 'username')).toBe('');
    });

    it('answers an empty string for an array body', () => {
        expect(stringField(['alice'], 'username')).toBe('');
    });

    it('answers an empty string for a property inherited from Object.prototype', () => {
        // `toString` and `constructor` are present on every object. They are
        // functions, not strings, so they come back empty rather than forwarded.
        expect(stringField({}, 'toString')).toBe('');
        expect(stringField({}, 'constructor')).toBe('');
        expect(stringField({}, '__proto__')).toBe('');
    });

    it('truncates rather than forwarding an unbounded string upstream', () => {
        expect(stringField({bio: 'x'.repeat(10_000)}, 'bio')).toHaveLength(512);
        expect(stringField({bio: 'x'.repeat(10_000)}, 'bio', 8)).toHaveLength(8);
    });
});
