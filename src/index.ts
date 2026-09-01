export {
    clientAddress,
    UNKNOWN_CLIENT_ADDRESS,
    type AddressSource
} from './clientAddress.js';

export {
    checkRequestOrigin,
    originVerdictStatus,
    type OriginCheckInput,
    type OriginVerdict
} from './csrf.js';

export {
    RateLimiter,
    type Decision,
    type LimiterConfig
} from './rateLimit.js';

export {
    ASSUMED_UPSTREAM_REQUESTS_PER_MINUTE,
    recommendedAuthLimits,
    type AuthLimitPresets
} from './recommendedAuthLimits.js';

export {
    createSessionCookieRules,
    HOST_COOKIE_PREFIX,
    maxAgeFor,
    readCookie,
    type IssuedSession,
    type MaxAgeOptions,
    type SessionCookieOptions,
    type SessionCookieRules
} from './session.js';

export {
    issueState,
    STATE_TTL_MS,
    verifyState,
    type StateVerdict
} from './oauthState.js';

export {
    methodNotAllowed,
    originVerdictFor,
    refuseCrossOriginRequest,
    refuseIfLimited,
    requestAddress,
    stringField,
    type ApiError,
    type GuardRequest,
    type GuardResponse,
    type OriginGuardOptions
} from './guards.js';
