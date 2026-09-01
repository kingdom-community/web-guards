// The route-level wrappers: method, origin, and rate limit, applied to a request
// and an answer written to a response.
//
// They live in one module rather than in each route because they are the three
// checks that are easy to add to the first route and forget on the fourth, and
// because "which routes enforce the origin check" is a question that should have
// one answer to read rather than four to compare.
//
// NOT BOUND TO A FRAMEWORK. The request and response below are structural types
// describing the two or three members these functions actually touch. A Next.js
// `NextApiRequest`/`NextApiResponse` pair satisfies them as-is, with no import
// from `next` and no adapter; so does anything else shaped like them. Nothing in
// this package reads `process.env`, so the base URL and the limits are passed in
// by the caller that knows them.

import {checkRequestOrigin, type OriginVerdict} from './csrf.js';
import {clientAddress} from './clientAddress.js';
import type {Decision} from './rateLimit.js';

export interface ApiError {
    error: string;
    message: string;
    // Present on a 429, mirroring the Retry-After header, so a fetch caller that
    // only reads JSON still gets the number.
    retryAfterSeconds?: number;
}

// The parts of an incoming request these guards read, and no more.
export interface GuardRequest {
    headers: Record<string, string | string[] | undefined>;
    socket?: {remoteAddress?: string | null | undefined} | null | undefined;
}

// The parts of a response these guards write, and no more.
export interface GuardResponse {
    setHeader(name: string, value: string): unknown;
    status(code: number): {json(body: ApiError): unknown};
}

export const methodNotAllowed = (response: GuardResponse, allowed: string[]): void => {
    response.setHeader('Allow', allowed.join(', '));
    response.status(405).json({error: 'method_not_allowed', message: `Use ${allowed.join(' or ')}.`});
};

// The address a per-address budget is keyed on. Read from the proxy's forwarded
// header, never from the socket — see `clientAddress.ts`, which is where the
// reasoning and the failure mode live.
export const requestAddress = (request: GuardRequest): string =>
    clientAddress({headers: request.headers, socketAddress: request.socket?.remoteAddress ?? null});

export interface OriginGuardOptions {
    // The site's own base URL, raw. Undefined is a MISCONFIGURATION, not a
    // request to skip the check — see `csrf.ts`.
    baseUrl?: string | undefined;
    // The name of the setting that supplies `baseUrl`, used only to make the log
    // line greppable by the operator who has to fix it. Give it whatever your
    // deployment actually calls the variable.
    baseUrlSetting?: string;
    // Where the misconfiguration is reported. Defaults to `console.error`.
    // Replace it to route the line into whatever collects your logs — but do not
    // replace it with a no-op: silence is the failure mode this whole branch
    // exists to prevent.
    log?: (message: string) => void;
}

export const originVerdictFor = (
    request: GuardRequest,
    baseUrl: string | undefined
): OriginVerdict =>
    checkRequestOrigin({
        origin: request.headers.origin,
        referer: request.headers.referer,
        baseUrl
    });

// Enforce the origin check on a state-changing route. Returns true when the
// request was refused and the route must stop.
//
// The three outcomes answer differently on purpose:
//   * `not-configured` is 503 and is OURS: the site was deployed without its own
//     base URL, so the control cannot be applied and the route is disabled
//     rather than left unguarded. The log line names the setting, because a
//     misconfiguration that removes a security control has to be loud.
//   * `missing-origin` is 403: a state-changing request carrying neither Origin
//     nor Referer is rejected rather than waved through. That is the standard
//     way around this control, and every real browser sends Origin.
//   * `mismatched-origin` is 403: somebody else's page tried to post here.
export const refuseCrossOriginRequest = (
    request: GuardRequest,
    response: GuardResponse,
    options: OriginGuardOptions
): boolean => {
    const verdict = originVerdictFor(request, options.baseUrl);
    if (verdict.ok) {
        return false;
    }
    if (verdict.reason === 'not-configured') {
        const setting = options.baseUrlSetting ?? 'the site base URL';
        (options.log ?? console.error)(
            `${setting} is not set, so the origin check cannot be applied and state-changing `
            + 'routes are disabled. Set it and redeploy. If your framework inlines it at BUILD '
            + 'time, rebuild the image with it set rather than restarting the container.'
        );
        response.status(503).json({
            error: 'not_configured',
            message: 'This site is not configured to accept that request right now.'
        });
        return true;
    }
    response.status(403).json({
        error: 'forbidden_origin',
        message: 'That request did not come from this site.'
    });
    return true;
};

// Answer a rate-limited caller. Returns true when the request was refused.
export const refuseIfLimited = (
    response: GuardResponse,
    decision: Decision,
    message: string
): boolean => {
    if (decision.allowed) {
        return false;
    }
    response.setHeader('Retry-After', String(decision.retryAfterSeconds));
    response.status(429).json({
        error: 'rate_limited',
        message,
        retryAfterSeconds: decision.retryAfterSeconds
    });
    return true;
};

// Read a string field out of a JSON body without trusting that the body is an
// object, that the field is a string, or that it is a sane length. An unbounded
// string forwarded to an upstream service is a request this site chose to send.
export const stringField = (body: unknown, field: string, maxLength = 512): string => {
    if (!body || typeof body !== 'object') {
        return '';
    }
    const value = (body as Record<string, unknown>)[field];
    return typeof value === 'string' ? value.slice(0, maxLength) : '';
};
