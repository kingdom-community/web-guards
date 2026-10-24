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

    it('produces a key rather than throwing when a header arrives as an empty array', () => {
        // Nothing in the array to be the last hop, so it is the same case as an
        // absent header — the socket, and failing that the shared bucket.
        expect(clientAddress({headers: {'x-forwarded-for': []}, socketAddress: '172.18.0.4'}))
            .toBe('172.18.0.4');
        expect(clientAddress({headers: {'x-real-ip': [], 'x-forwarded-for': []}}))
            .toBe(UNKNOWN_CLIENT_ADDRESS);
    });

    it('treats a present but blank X-Real-Ip as absent rather than as the answer', () => {
        // A proxy that sets the header unconditionally sets it empty when it has
        // nothing to put there. Keying on '' would bucket those requests
        // together under a name that looks like an address.
        expect(clientAddress({
            headers: {'x-real-ip': '   ', 'x-forwarded-for': '198.51.100.9, 203.0.113.7'}
        })).toBe('203.0.113.7');
    });
});

// Every source this module reads can be present and still carry nothing: a key
// with no value, a value of whitespace, a repeated header whose last copy is
// blank, a socket address the runtime could not fill in. Each has to land on
// the next source down, and the bottom of the list has to be the shared bucket
// rather than an empty key.
//
// The case that matters most is the repeated header. Its earlier copies are the
// ones the client could have written, so a blank last copy must fall through to
// the next source — never reach back for the element before it.
describe('a source that is present but carries nothing', () => {
    it('falls through an X-Real-Ip key that has no value', () => {
        expect(clientAddress({
            headers: {'x-real-ip': undefined, 'x-forwarded-for': '198.51.100.9, 203.0.113.7'},
            socketAddress: '172.18.0.4'
        })).toBe('203.0.113.7');
    });

    it('does not reach back past a blank last copy of a repeated X-Real-Ip', () => {
        expect(clientAddress({
            headers: {'x-real-ip': ['1.2.3.4', '  '], 'x-forwarded-for': '198.51.100.9, 203.0.113.7'},
            socketAddress: '172.18.0.4'
        })).toBe('203.0.113.7');
    });

    it('does not reach back past a blank last copy of a repeated X-Forwarded-For', () => {
        // `1.2.3.4` is in the first copy, which is the one a client can send.
        expect(clientAddress({
            headers: {'x-forwarded-for': ['1.2.3.4', '']},
            socketAddress: '172.18.0.4'
        })).toBe('172.18.0.4');
    });

    it('keys a whitespace-only or null socket address on the shared bucket', () => {
        // An empty string is never a key: it would bucket these requests
        // together under a name that looks like an address but names nothing.
        expect(clientAddress({headers: {}, socketAddress: '   '})).toBe(UNKNOWN_CLIENT_ADDRESS);
        expect(clientAddress({headers: {}, socketAddress: null})).toBe(UNKNOWN_CLIENT_ADDRESS);
    });
});

// Padding is not part of an address. A proxy, or a hand-written header bag, that
// pads the value must not split one visitor into two buckets, one per spelling.
describe('one visitor, one bucket, however the value is padded', () => {
    it('trims X-Real-Ip', () => {
        expect(clientAddress({headers: {'x-real-ip': ' 203.0.113.7 '}})).toBe('203.0.113.7');
    });

    it('trims the last X-Forwarded-For entry', () => {
        expect(clientAddress({headers: {'x-forwarded-for': '198.51.100.9 ,  203.0.113.7  '}}))
            .toBe('203.0.113.7');
    });

    it('trims the socket address', () => {
        expect(clientAddress({headers: {}, socketAddress: ' 172.18.0.4 '})).toBe('172.18.0.4');
    });
});

// The header bag this module takes is a structural record, not Node's
// `IncomingHttpHeaders`. Node lower-cases what it hands up; a caller that does
// not — another framework, an edge runtime, a hand-built test double — spells
// the header the way the wire did.
//
// The consequence of missing it is not "no address". It is the socket peer,
// which behind a proxy is the proxy: every visitor on the internet in one
// bucket, and the first abuser to spend the budget locks out the site. So the
// assertions below all carry a socket address, and the point of each is that the
// socket address is NOT what comes back.
describe('a header name spelled the way the wire spelled it', () => {
    it('is read whatever its capitalisation, rather than falling through to the socket', () => {
        expect(clientAddress({headers: {'X-Real-Ip': '203.0.113.7'}, socketAddress: '172.18.0.4'}))
            .toBe('203.0.113.7');
        expect(clientAddress({headers: {'X-REAL-IP': '203.0.113.7'}, socketAddress: '172.18.0.4'}))
            .toBe('203.0.113.7');
    });

    it('still gets the LAST X-Forwarded-For entry, not the first', () => {
        // The capitalised spelling must not quietly become a second, weaker
        // implementation of the one rule this file exists to hold.
        expect(clientAddress({
            headers: {'X-Forwarded-For': '1.2.3.4, 203.0.113.7'},
            socketAddress: '172.18.0.4'
        })).toBe('203.0.113.7');
    });

    it('keeps X-Real-Ip ahead of X-Forwarded-For however either is spelled', () => {
        expect(clientAddress({
            headers: {'X-Forwarded-For': '1.2.3.4', 'x-real-ip': '203.0.113.7'}
        })).toBe('203.0.113.7');
        expect(clientAddress({
            headers: {'x-forwarded-for': '1.2.3.4', 'X-Real-Ip': '203.0.113.7'}
        })).toBe('203.0.113.7');
    });

    it('prefers the exact lower-case spelling, which is the one Node produces', () => {
        // Both spellings present is not a request any proxy makes; it is pinned
        // so the resolution is a decision rather than an accident of key order.
        expect(clientAddress({
            headers: {'x-real-ip': '203.0.113.7', 'X-Real-Ip': '1.2.3.4'}
        })).toBe('203.0.113.7');
    });

    it('does not let a lower-case key with no value hide the capitalised one', () => {
        // A merged bag — defaults spread under the wire's headers — can carry
        // the key with nothing in it. Stopping there would hand back the socket
        // peer, which behind a proxy is the proxy: one bucket for every visitor.
        expect(clientAddress({
            headers: {'x-real-ip': undefined, 'X-Real-Ip': '203.0.113.7'},
            socketAddress: '172.18.0.4'
        })).toBe('203.0.113.7');
        expect(clientAddress({
            headers: {'x-forwarded-for': undefined, 'X-Forwarded-For': '1.2.3.4, 203.0.113.7'},
            socketAddress: '172.18.0.4'
        })).toBe('203.0.113.7');
    });

    it('does not let one capitalised key with no value hide another', () => {
        // The scan skips an empty key for the same reason the direct lookup
        // does; otherwise key order alone would decide whether the header is seen.
        expect(clientAddress({
            headers: {'X-Real-Ip': undefined, 'X-REAL-IP': '203.0.113.7'},
            socketAddress: '172.18.0.4'
        })).toBe('203.0.113.7');
    });
});
