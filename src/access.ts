import { createRemoteJWKSet, jwtVerify } from "jose";
import type { MiddlewareHandler } from "hono";
import type { AppEnv } from "./env";

// One JWKS fetcher per team domain; jose caches the keys and refetches on rotation.
const jwksByTeam = new Map<string, ReturnType<typeof createRemoteJWKSet>>();

function jwksFor(teamDomain: string) {
  let jwks = jwksByTeam.get(teamDomain);
  if (!jwks) {
    jwks = createRemoteJWKSet(new URL(`https://${teamDomain}/cdn-cgi/access/certs`));
    jwksByTeam.set(teamDomain, jwks);
  }
  return jwks;
}

function isLocalRequest(url: string): boolean {
  const { hostname } = new URL(url);
  return hostname === "localhost" || hostname === "127.0.0.1";
}

/**
 * Verifies the Cloudflare Access JWT on every request. Access already blocks
 * unauthenticated traffic at the edge; this check covers any route that
 * reaches the Worker without passing through Access.
 *
 * Fails closed: if Access isn't configured, every request is rejected.
 */
export const requireAccess: MiddlewareHandler<AppEnv> = async (c, next) => {
  const { ACCESS_TEAM_DOMAIN, ACCESS_AUD, DEV_BYPASS_ACCESS } = c.env;

  if (DEV_BYPASS_ACCESS === "true" && isLocalRequest(c.req.url)) {
    c.set("userEmail", "dev@localhost");
    return next();
  }

  if (!ACCESS_TEAM_DOMAIN || !ACCESS_AUD) {
    console.error("Cloudflare Access is not configured (ACCESS_TEAM_DOMAIN / ACCESS_AUD)");
    return c.text("Access not configured", 500);
  }

  const token = c.req.header("Cf-Access-Jwt-Assertion");
  if (!token) return c.text("Forbidden", 403);

  try {
    const { payload } = await jwtVerify(token, jwksFor(ACCESS_TEAM_DOMAIN), {
      issuer: `https://${ACCESS_TEAM_DOMAIN}`,
      audience: ACCESS_AUD,
    });
    c.set("userEmail", typeof payload.email === "string" ? payload.email : undefined);
  } catch {
    return c.text("Forbidden", 403);
  }

  return next();
};
