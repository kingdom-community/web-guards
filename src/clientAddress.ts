// Which address a rate limit is keyed on. A dozen lines, and the single easiest
// thing in a web application to get wrong in a way nothing reports.
//
// A community site almost always sits behind a reverse proxy — Traefik, nginx,
// Caddy, a cloud load balancer — which terminates TLS and forwards to the
// application. So:
//
//   * The socket peer is THE PROXY. Keying on it — `req.socket.remoteAddress` —
//     collapses every visitor on the internet into one bucket, so the first
//     abuser to exhaust the budget locks out the whole site. This is not a
//     hypothetical: it is the default behaviour of every throttle written
//     against the socket address, and it looks completely correct in review.
//   * `X-Forwarded-For` is a LIST that each proxy APPENDS to, and the client
//     writes the beginning of it. `xff.split(',')[0]` — the spelling most
//     examples use — hands an attacker a fresh identity on every request by
//     sending one header, defeating the registration limit, the posting limit
//     and the failed-login lockout in a single line of code.
//
// So: read `X-Real-Ip`, which a proxy sets to the address it saw; failing that,
// the LAST entry of `X-Forwarded-For`, which is the one the nearest proxy
// appended and the only one the client could not choose. Failing both, the
// socket peer, and failing that a shared `unknown` key — never nothing, because
// an unkeyed request is an unlimited one.
//
// Both header names are matched WITHOUT REGARD TO CASE. Node lower-cases them,
// but the header bag this module takes is a structural record rather than
// Node's, and a caller that spells one `X-Real-Ip` must not silently drop
// through to the socket peer for it.
//
// TWO DEPENDENCIES THIS FILE CANNOT CHECK FOR ITSELF
//
//   * The proxy must be configured to trust only itself for forwarded headers
//     (Traefik's `forwardedHeaders.trustedIPs`, nginx's `set_real_ip_from`, and
//     so on). Without that, the proxy passes a client-supplied
//     `X-Forwarded-For` through and appends to it, so even reading the last
//     entry is only correct because the proxy put it there.
//   * If you run MORE than one proxy hop, the last entry is the address the
//     innermost proxy saw — which is the outer proxy, not the visitor. Reading
//     the last entry is right for exactly one trusted hop; with two you want the
//     second-to-last, and with a variable number you want your proxy to
//     normalise it into `X-Real-Ip` and to read that.
//
// Both are settings outside the application, invisible from this package, and
// they should be verified rather than assumed. A rate limiter keyed on the wrong
// value is not a weaker limiter; it is a limiter that either does nothing or
// takes the site down, and it reports neither.

export interface AddressSource {
    headers: Record<string, string | string[] | undefined>;
    socketAddress?: string | null;
}

// Returned when nothing usable was found. A real key rather than null, so a
// request with no identifiable address is still rate-limited — together with
// every other such request, which is the conservative direction to fail in.
export const UNKNOWN_CLIENT_ADDRESS = 'unknown';

// `name` is given already lower-cased. The direct lookup answers every request
// that arrived through Node, which lower-cases incoming header names, so the
// common path costs one property read. The scan behind it is for a caller whose
// framework or test harness did not: `headers` here is a structural record
// rather than Node's `IncomingHttpHeaders`, so `X-Real-Ip` is a spelling this
// module can be handed. Not finding it would not read as an error — it would
// fall through to the socket peer below, which behind a proxy is the proxy, and
// that is the whole-site outage described at the top of this file arriving
// silently.
const rawHeaderValue = (
    headers: AddressSource['headers'],
    name: string
): string | string[] | undefined => {
    if (name in headers) {
        return headers[name];
    }
    for (const key of Object.keys(headers)) {
        if (key.toLowerCase() === name) {
            return headers[key];
        }
    }
    return undefined;
};

const headerValue = (headers: AddressSource['headers'], name: string): string | null => {
    const raw = rawHeaderValue(headers, name);
    if (raw === undefined) {
        return null;
    }
    // Node joins repeats for most headers, but a header that appears more than
    // once can arrive as an array. The last element of the last one is still the
    // last hop.
    const value = Array.isArray(raw) ? raw[raw.length - 1] : raw;
    const trimmed = (value ?? '').trim();
    return trimmed === '' ? null : trimmed;
};

export const clientAddress = (source: AddressSource): string => {
    const realIp = headerValue(source.headers, 'x-real-ip');
    if (realIp) {
        return realIp;
    }

    const forwardedFor = headerValue(source.headers, 'x-forwarded-for');
    if (forwardedFor) {
        const entries = forwardedFor
            .split(',')
            .map((entry) => entry.trim())
            .filter((entry) => entry !== '');
        // THE LAST ENTRY. Never entries[0]. See the note above; which end of this
        // list is read is the whole of the control.
        if (entries.length > 0) {
            return entries[entries.length - 1] as string;
        }
    }

    const socketAddress = (source.socketAddress ?? '').trim();
    return socketAddress === '' ? UNKNOWN_CLIENT_ADDRESS : socketAddress;
};
