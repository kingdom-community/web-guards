import {describe, expect, it, vi} from 'vitest';

import {
    methodNotAllowed,
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

    it('truncates rather than forwarding an unbounded string upstream', () => {
        expect(stringField({bio: 'x'.repeat(10_000)}, 'bio')).toHaveLength(512);
        expect(stringField({bio: 'x'.repeat(10_000)}, 'bio', 8)).toHaveLength(8);
    });
});
