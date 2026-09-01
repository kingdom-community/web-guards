import {describe, expect, it} from 'vitest';

import {refuseCrossOriginRequest, type GuardRequest, type GuardResponse} from '../src/guards.js';

// The claim in `guards.ts` is that a Next.js API route's request and response
// satisfy `GuardRequest` and `GuardResponse` with no adapter and no import from
// `next`. This file holds that claim to a compile-time check without taking a
// dependency on the framework: the two declarations below reproduce the
// signatures Next's types inherit from Node's `IncomingMessage` and
// `ServerResponse`, which are the wider ones — a `setHeader` that also accepts
// numbers and arrays, a `status` that returns the response itself.
//
// If a future change to `GuardRequest`/`GuardResponse` narrows past what those
// signatures provide, `npm run typecheck` fails here rather than in somebody's
// application.

interface NodeLikeRequest {
    headers: {[header: string]: string | string[] | undefined};
    socket: {remoteAddress?: string | undefined};
}

interface NodeLikeResponse {
    setHeader(name: string, value: number | string | readonly string[]): this;
    status(code: number): this;
    json(body: unknown): void;
}

describe('framework compatibility', () => {
    it('accepts a Node-shaped request and response without an adapter', () => {
        const headers: {[header: string]: string | string[] | undefined} = {};
        const written: {status: number | null; body: unknown} = {status: null, body: null};

        const nodeResponse: NodeLikeResponse = {
            setHeader() {
                return this;
            },
            status(code: number) {
                written.status = code;
                return this;
            },
            json(body: unknown) {
                written.body = body;
            }
        };
        const nodeRequest: NodeLikeRequest = {headers, socket: {remoteAddress: '172.18.0.4'}};

        // The assignments are the assertion; the call is there so the test also
        // proves the shapes work at runtime.
        const request: GuardRequest = nodeRequest;
        const response: GuardResponse = nodeResponse;

        expect(refuseCrossOriginRequest(request, response, {baseUrl: 'https://harborlight.example'}))
            .toBe(true);
        expect(written.status).toBe(403);
    });
});
