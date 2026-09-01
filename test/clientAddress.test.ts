import {describe, expect, it} from 'vitest';

import {clientAddress, UNKNOWN_CLIENT_ADDRESS} from '../src/clientAddress.js';

// Which end of X-Forwarded-For gets read is the whole of the rate-limiting
// control, so it is tested as an attack rather than as a parse.
//
// Both failure modes are common in shipped code: a throttle keyed on the socket
// peer buckets every visitor together behind a proxy, and a throttle keyed on
// the FIRST X-Forwarded-For entry keys on a value the client writes.

describe('clientAddress', () => {
    it('prefers X-Real-Ip, which the proxy sets to the address it saw', () => {
        expect(clientAddress({headers: {'x-real-ip': '203.0.113.7'}, socketAddress: '172.18.0.4'}))
            .toBe('203.0.113.7');
    });

    it('takes the LAST X-Forwarded-For entry, not the first', () => {
        // The list is appended to by each proxy, and the client writes the
        // beginning of it. The last entry is the one the nearest proxy appended.
        expect(clientAddress({headers: {'x-forwarded-for': '203.0.113.7'}}))
            .toBe('203.0.113.7');
        expect(clientAddress({headers: {'x-forwarded-for': '198.51.100.9, 203.0.113.7'}}))
            .toBe('203.0.113.7');
    });

    it('gives an attacker who forges the list no new identity', () => {
        // THE TEST THIS FILE EXISTS FOR. `xff.split(',')[0]` would return
        // "1.2.3.4" here, and a different fabricated value on every request —
        // defeating the registration limit, the posting limit and the failed-login
        // lockout in one line of code. Reading the last entry pins every one of
        // these to the same bucket.
        const forged = ['1.2.3.4', '5.6.7.8', 'not-even-an-address', '::1'];

        const keys = forged.map((claimed) =>
            clientAddress({headers: {'x-forwarded-for': `${claimed}, 203.0.113.7`}}));

        expect(new Set(keys)).toEqual(new Set(['203.0.113.7']));
    });

    it('does not let a forged X-Forwarded-For override X-Real-Ip', () => {
        expect(clientAddress({
            headers: {'x-forwarded-for': '1.2.3.4', 'x-real-ip': '203.0.113.7'}
        })).toBe('203.0.113.7');
    });

    it('falls back to the socket only when no forwarded header is present', () => {
        // Which is the DIRECT-CONNECTION case — local development, or a request
        // that somehow reached the container without passing the proxy. Behind a
        // proxy this value is the proxy, which is why it is last rather than
        // first.
        expect(clientAddress({headers: {}, socketAddress: '172.18.0.4'})).toBe('172.18.0.4');
    });

    it('still produces a key when there is nothing to key on', () => {
        // A shared bucket for unidentifiable requests: rate-limited together,
        // which is the conservative direction to fail in. Returning null and
        // skipping the limit would make "send no headers" the way around it.
        expect(clientAddress({headers: {}})).toBe(UNKNOWN_CLIENT_ADDRESS);
        expect(clientAddress({headers: {'x-forwarded-for': '  '}, socketAddress: ''}))
            .toBe(UNKNOWN_CLIENT_ADDRESS);
        expect(clientAddress({headers: {'x-forwarded-for': ' , , '}})).toBe(UNKNOWN_CLIENT_ADDRESS);
    });

    it('reads the last hop when a header arrives more than once', () => {
        // Node hands a repeated header up as an array. The last element of the
        // last one is still the last hop.
        expect(clientAddress({headers: {'x-forwarded-for': ['1.2.3.4', '198.51.100.9, 203.0.113.7']}}))
            .toBe('203.0.113.7');
    });
});
