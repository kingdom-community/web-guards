// The origin check every state-changing route should run before doing anything.
//
// Cookie-based sessions mean the browser attaches credentials to cross-origin
// requests automatically. `SameSite=Lax` on the session cookie blocks the
// cross-site POST case, which covers the realistic attack — but it does not
// cover a same-site subdomain attacker, and leaning on one flag for every
// state-changing route is thin. So routes additionally check `Origin` (and
// `Referer` where `Origin` is absent) against the site's own base URL.
//
// Two edges fail OPEN in the natural implementation, and both are closed here
// explicitly, because both are the kind of thing that reads as correct:
//
//   1. NEITHER HEADER PRESENT. "Reject a mismatch" says nothing about the case
//      where there is nothing to mismatch, and an absent Origin with an absent
//      Referer is the standard way around exactly this control. Such a request
//      is REJECTED. The cost is real and accepted: a client that strips both
//      cannot post here. Every browser sends `Origin` on a cross-origin
//      state-changing request, so no legitimate user is in that set — but a
//      hand-written API client might be, and that is a trade to make knowingly.
//
//   2. BASE URL UNSET. A site that reads its own base URL from configuration can
//      be deployed without it — and in a framework that inlines public
//      environment variables at BUILD time, that misconfiguration is baked into
//      an image rather than fixable with a restart. Such a build would compare
//      every incoming Origin against `undefined` and either pass nothing or —
//      depending on how the comparison is written — pass everything. Neither is
//      acceptable, so an unset base URL DISABLES state-changing routes rather
//      than disabling the check. The site still reads; posting answers 503 with
//      a configuration error in the logs. A misconfiguration that removes a
//      security control has to be loud, and there is no third option where it is
//      silently ignored.
//
// Note the deliberate asymmetry with everything else that reads the same
// setting. Somewhere else in your codebase, the base URL probably falls back to
// `http://localhost:3000` — for canonical link tags, say. That is correct there
// and wrong here: a wrong canonical URL in a meta tag is cosmetic, a wrong
// origin allowlist is not. So this module reads the raw value and refuses rather
// than inventing one. In local development that means the base URL has to be set
// before login works, which is the intended loudness.

export type OriginVerdict =
    | {ok: true}
    | {ok: false; reason: 'not-configured' | 'missing-origin' | 'mismatched-origin'};

export interface OriginCheckInput {
    origin?: string | string[] | undefined;
    referer?: string | string[] | undefined;
    // The site's own base URL, raw and unvalidated. Passed in rather than read
    // from the environment here so the rule stays pure and the "unset" case is
    // testable.
    baseUrl?: string | undefined;
}

const first = (value: string | string[] | undefined): string | undefined =>
    Array.isArray(value) ? value[0] : value;

const originOf = (url: string | undefined): string | null => {
    if (!url || url.trim() === '') {
        return null;
    }
    try {
        return new URL(url.trim()).origin;
    } catch {
        return null;
    }
};

export const checkRequestOrigin = (input: OriginCheckInput): OriginVerdict => {
    const expected = originOf(input.baseUrl);
    if (!expected) {
        return {ok: false, reason: 'not-configured'};
    }

    // `Origin` is the header to trust: browsers send it on every state-changing
    // cross-origin request and it cannot be set by page script. `Referer` is the
    // fallback for the same-origin form post, where some browsers omit Origin.
    const declared = originOf(first(input.origin)) ?? originOf(first(input.referer));
    if (!declared) {
        return {ok: false, reason: 'missing-origin'};
    }
    return declared === expected ? {ok: true} : {ok: false, reason: 'mismatched-origin'};
};

// What the caller is told. Deliberately three different status codes, because
// they are three different problems: 503 is ours to fix, 403 is theirs.
export const originVerdictStatus = (verdict: OriginVerdict): number => {
    if (verdict.ok) {
        return 200;
    }
    return verdict.reason === 'not-configured' ? 503 : 403;
};
