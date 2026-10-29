/**
 * ==============================================================================
 * FILE: functions/api/v1/_middleware.js
 * DESCRIPTION: Cloudflare Pages Functions authentication and CORS middleware.
 * 
 * WHAT THIS FILE DOES:
 * 1. Intercepts all requests targeting '/api/v1/*'.
 * 2. Handles CORS preflight (OPTIONS) requests with standard permissive headers.
 * 3. Enforces HTTP GET and HEAD methods (rejects POST, PUT, DELETE with 405).
 * 4. Authenticates incoming requests against the secret key stored in the
 *    Cloudflare Pages environment variable: API_SECRET_KEY.
 *    Supports 3 authentication methods:
 *      - Header: Authorization: Bearer <API_SECRET_KEY>
 *      - Header: X-API-Key: <API_SECRET_KEY>
 *      - Query Param: ?key=<API_SECRET_KEY> or ?api_key=<API_SECRET_KEY>
 * 5. Performs timing-safe comparison to prevent side-channel timing attacks.
 * 6. Returns standard JSON error payloads (401 Unauthorized, 405 Method Not Allowed,
 *    500 Server Misconfiguration).
 * 7. Proxies authorized requests to static files in public/api/v1/* and attaches:
 *      - CORS headers (Access-Control-Allow-*)
 *      - Security headers (nosniff, frame protection)
 *      - Route-optimized Cache-Control headers (60s for version metadata,
 *        1 year immutable for release snapshots).
 * ==============================================================================
 */

/**
 * Constant-time string comparison to prevent timing attacks.
 * @param {string} a 
 * @param {string} b 
 * @returns {boolean}
 */
function timingSafeEqual(a, b) {
  if (typeof a !== 'string' || typeof b !== 'string') return false;
  if (a.length !== b.length) return false;

  let mismatch = 0;
  for (let i = 0; i < a.length; i++) {
    mismatch |= a.charCodeAt(i) ^ b.charCodeAt(i);
  }
  return mismatch === 0;
}

/**
 * Standard CORS and security headers applied to all responses.
 */
const BASE_HEADERS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET, HEAD, OPTIONS',
  'Access-Control-Allow-Headers': 'Authorization, X-API-Key, Content-Type',
  'Access-Control-Max-Age': '86400',
  'X-Content-Type-Options': 'nosniff',
  'X-Frame-Options': 'DENY'
};

/**
 * Extracts the API secret key from Bearer token, X-API-Key header, or query param.
 * @param {Request} request 
 * @returns {string|null}
 */
function extractApiKey(request) {
  // 1. Authorization: Bearer <key>
  const authHeader = request.headers.get('Authorization') || request.headers.get('authorization');
  if (authHeader) {
    const parts = authHeader.trim().split(/\s+/);
    if (parts.length === 2 && parts[0].toLowerCase() === 'bearer') {
      return parts[1];
    }
  }

  // 2. X-API-Key: <key>
  const xApiKey = request.headers.get('X-API-Key') || request.headers.get('x-api-key');
  if (xApiKey) {
    return xApiKey.trim();
  }

  // 3. Query parameter ?key=... or ?api_key=...
  try {
    const url = new URL(request.url);
    const keyParam = url.searchParams.get('key') || url.searchParams.get('api_key');
    if (keyParam) {
      return keyParam.trim();
    }
  } catch {
    // Silently continue if URL parsing fails
  }

  return null;
}

/**
 * Determines optimal Cache-Control directive based on requested path.
 * @param {string} pathname 
 * @returns {string}
 */
function getCacheControlHeader(pathname) {
  if (pathname.includes('/releases/')) {
    // Immutable versioned snapshots can be cached indefinitely
    return 'public, max-age=31536000, immutable';
  }
  if (pathname.endsWith('/version.json')) {
    // Fast revalidation for version metadata so apps detect updates promptly
    return 'public, max-age=60, s-maxage=60, must-revalidate';
  }
  // Default for domains.json convenience copy
  return 'public, max-age=300, must-revalidate';
}

/**
 * Cloudflare Pages middleware entry point.
 */
export async function onRequest(context) {
  const { request, env, next } = context;
  const url = new URL(request.url);

  // 1. Handle CORS Preflight requests
  if (request.method === 'OPTIONS') {
    return new Response(null, {
      status: 204,
      headers: BASE_HEADERS
    });
  }

  // 2. Reject non-GET / non-HEAD methods
  if (request.method !== 'GET' && request.method !== 'HEAD') {
    return new Response(
      JSON.stringify(
        {
          error: 'Method Not Allowed',
          message: `HTTP method '${request.method}' is not supported. Use GET or HEAD.`
        },
        null,
        2
      ),
      {
        status: 405,
        headers: {
          'Content-Type': 'application/json; charset=utf-8',
          'Allow': 'GET, HEAD, OPTIONS',
          ...BASE_HEADERS
        }
      }
    );
  }

  // 3. Validate Cloudflare Environment Configuration
  const expectedSecret = env.API_SECRET_KEY;
  if (!expectedSecret) {
    return new Response(
      JSON.stringify(
        {
          error: 'Server Misconfiguration',
          message:
            'API_SECRET_KEY is not configured in Cloudflare Pages environment variables. Please set it in Settings -> Environment variables.'
        },
        null,
        2
      ),
      {
        status: 500,
        headers: {
          'Content-Type': 'application/json; charset=utf-8',
          ...BASE_HEADERS
        }
      }
    );
  }

  // 4. Authenticate Request
  const providedKey = extractApiKey(request);

  if (!providedKey || !timingSafeEqual(providedKey, expectedSecret)) {
    return new Response(
      JSON.stringify(
        {
          error: 'Unauthorized',
          message:
            'Invalid or missing API secret key. Provide it via Authorization: Bearer, X-API-Key header, or ?key= query parameter.'
        },
        null,
        2
      ),
      {
        status: 401,
        headers: {
          'Content-Type': 'application/json; charset=utf-8',
          'WWW-Authenticate': 'Bearer error="invalid_token"',
          ...BASE_HEADERS
        }
      }
    );
  }

  // 5. Forward to static asset handler
  let response = await next();

  // If the uncompressed .json asset is not found (because files > 25MB are stored as .gz),
  // redirect transparently to the corresponding .gz snapshot asset.
  if (response.status === 404 && url.pathname.endsWith('.json')) {
    const gzUrl = new URL(request.url);
    gzUrl.pathname += '.gz';
    return Response.redirect(gzUrl.toString(), 307);
  }

  // 6. Augment response with security, CORS, and tailored caching headers
  const newHeaders = new Headers(response.headers);
  for (const [key, value] of Object.entries(BASE_HEADERS)) {
    newHeaders.set(key, value);
  }
  newHeaders.set('Cache-Control', getCacheControlHeader(url.pathname));
  if (url.pathname.endsWith('.gz')) {
    newHeaders.set('Content-Type', 'application/gzip');
  }

  return new Response(response.body, {
    status: response.status,
    statusText: response.statusText,
    headers: newHeaders
  });
}
