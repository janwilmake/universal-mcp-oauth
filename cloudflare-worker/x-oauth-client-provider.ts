import { DurableObject } from "cloudflare:workers";

export interface Env {
  X_CLIENT_ID: string;
  X_CLIENT_SECRET: string;
  UserDO: DurableObjectNamespace<UserDO>;
}

interface OAuthState {
  redirectTo?: string;
  codeVerifier: string;
  resource?: string;
}

export interface XUser {
  id: string;
  name: string;
  username: string;
  profile_image_url?: string;
  verified?: boolean;
  [key: string]: any;
}

export class UserDO extends DurableObject {
  private storage: DurableObjectStorage;

  constructor(state: DurableObjectState, env: Env) {
    super(state, env);
    this.storage = state.storage;
    // Set alarm for 10 minutes from now
    this.storage.setAlarm(Date.now() + 10 * 60 * 1000);
  }

  async alarm() {
    // Only self-delete if this is not a user storage (auth codes expire, users don't)
    const user = await this.storage.get("user");
    if (!user) {
      await this.storage.deleteAll();
    }
  }

  async setAuthData(
    xAccessToken: string,
    encryptedAccessToken: string,
    clientId: string,
    redirectUri: string,
    resource?: string,
  ) {
    await this.storage.put("data", {
      x_access_token: xAccessToken,
      access_token: encryptedAccessToken,
      clientId,
      redirectUri,
      resource,
    });
  }

  async getAuthData() {
    return this.storage.get<{
      x_access_token: string;
      access_token: string;
      clientId: string;
      redirectUri: string;
      resource?: string;
    }>("data");
  }

  async setUser(
    user: XUser,
    xAccessToken: string,
    encryptedAccessToken: string,
  ) {
    await this.storage.put("user", user);
    await this.storage.put("x_access_token", xAccessToken);
    await this.storage.put("access_token", encryptedAccessToken);
  }

  async getUser(): Promise<{
    user: XUser;
    xAccessToken: string;
    accessToken: string;
  }> {
    const user = await this.storage.get<XUser>("user");
    const xAccessToken = await this.storage.get<string>("x_access_token");
    const accessToken = await this.storage.get<string>("access_token");

    if (!user || !xAccessToken || !accessToken) {
      return null;
    }

    return { user, xAccessToken, accessToken };
  }

  async setMetadata<T>(metadata: T) {
    await this.storage.put("metadata", metadata);
  }

  async getMetadata<T>(): Promise<T | null> {
    const metadata = await this.storage.get<T>("metadata");
    if (!metadata) {
      return null;
    }
    return metadata;
  }
}

/**
 * Handle OAuth requests including MCP-required metadata endpoints.
 * Handles /authorize, /token, /callback, /logout, /me, and metadata endpoints.
 */
export async function handleOAuth(
  request: Request,
  env: Env,
  scope = "users.read tweet.read offline.access",
  sameSite: "Strict" | "Lax" = "Lax",
): Promise<Response | null> {
  const url = new URL(request.url);
  const path = url.pathname;

  if (!env.X_CLIENT_ID || !env.X_CLIENT_SECRET || !env.UserDO) {
    return new Response(
      `Environment misconfigured. Ensure to have X_CLIENT_ID or X_CLIENT_SECRET secrets set, as well as the Durable Object, with:

[[durable_objects.bindings]]
name = "UserDO"
class_name = "UserDO"

[[migrations]]
new_sqlite_classes = ["UserDO"]
tag = "v1"

      `,
      { status: 500 },
    );
  }

  // MCP Required: OAuth 2.0 Authorization Server Metadata (RFC8414)
  if (path === "/.well-known/oauth-authorization-server") {
    return handleAuthorizationServerMetadata(request, env, scope);
  }

  // MCP Required: OAuth 2.0 Protected Resource Metadata (RFC9728)
  if (path === "/.well-known/oauth-protected-resource") {
    return handleProtectedResourceMetadata(request, env);
  }

  if (path === "/token") {
    return handleToken(request, env, scope);
  }

  if (path === "/authorize") {
    return handleAuthorize(request, env, scope, sameSite);
  }

  if (path === "/callback") {
    return handleCallback(request, env, sameSite);
  }

  if (path === "/me") {
    return handleMe(request, env);
  }

  if (path === "/logout") {
    const url = new URL(request.url);
    const redirectTo = url.searchParams.get("redirect_to") || "/";
    return new Response(null, {
      status: 302,
      headers: {
        Location: redirectTo,
        "Set-Cookie": `access_token=; HttpOnly; Secure; SameSite=${sameSite}; Max-Age=0; Path=/`,
      },
    });
  }

  return null; // Not an OAuth route, let other handlers take over
}

// Handle /me endpoint to return current user information
async function handleMe(request: Request, env: Env): Promise<Response> {
  // Handle preflight OPTIONS request
  if (request.method === "OPTIONS") {
    return new Response(null, {
      status: 204,
      headers: {
        "Access-Control-Allow-Origin": "*",
        "Access-Control-Allow-Methods": "GET, OPTIONS",
        "Access-Control-Allow-Headers": "Content-Type, Authorization",
      },
    });
  }

  if (request.method !== "GET") {
    return new Response(JSON.stringify({ error: "method_not_allowed" }), {
      status: 405,
      headers: {
        "Content-Type": "application/json",
        "Access-Control-Allow-Origin": "*",
      },
    });
  }

  const headers = {
    "Content-Type": "application/json",
    "Access-Control-Allow-Origin": "*",
  };

  // Get access token from request
  const accessToken = getAccessToken(request);
  if (!accessToken) {
    return new Response(
      JSON.stringify({
        error: "unauthorized",
        error_description: "Access token required",
      }),
      {
        status: 401,
        headers: {
          ...headers,
          "WWW-Authenticate": 'Bearer realm="main"',
        },
      },
    );
  }

  try {
    // Get user data from Durable Object
    const userDOId = env.UserDO.idFromName(`user:${accessToken}`);
    const userDO = env.UserDO.get(userDOId);
    const userData = await userDO.getUser();

    if (!userData) {
      return new Response(
        JSON.stringify({
          error: "invalid_token",
          error_description: "Token not found or expired",
        }),
        {
          status: 401,
          headers: {
            ...headers,
            "WWW-Authenticate": 'Bearer realm="main", error="invalid_token"',
          },
        },
      );
    }

    // Return user information
    return new Response(
      JSON.stringify({
        data: userData.user,
      }),
      { headers },
    );
  } catch (error) {
    console.error("Error retrieving user data:", error);
    return new Response(
      JSON.stringify({
        error: "server_error",
        error_description: "Internal server error",
      }),
      {
        status: 500,
        headers,
      },
    );
  }
}

// MCP Required: OAuth 2.0 Authorization Server Metadata (RFC8414)
function handleAuthorizationServerMetadata(
  request: Request,
  env: Env,
  scope: string,
): Response {
  const url = new URL(request.url);
  const baseUrl = `${url.protocol}//${url.host}`;

  const metadata = {
    issuer: baseUrl,
    authorization_endpoint: `${baseUrl}/authorize`,
    token_endpoint: `${baseUrl}/token`,
    response_types_supported: ["code"],
    grant_types_supported: ["authorization_code"],
    code_challenge_methods_supported: ["S256"],
    scopes_supported: scope.split(" "),
    token_endpoint_auth_methods_supported: ["none"], // Public client support
  };

  return new Response(JSON.stringify(metadata), {
    headers: {
      "Content-Type": "application/json",
      "Access-Control-Allow-Origin": "*",
      "Access-Control-Allow-Methods": "GET, OPTIONS",
      "Access-Control-Allow-Headers": "Content-Type, Authorization",
    },
  });
}

// MCP Required: OAuth 2.0 Protected Resource Metadata (RFC9728)
function handleProtectedResourceMetadata(request: Request, env: Env): Response {
  const url = new URL(request.url);
  const baseUrl = `${url.protocol}//${url.host}`;

  const metadata = {
    resource: baseUrl,
    authorization_servers: [baseUrl],
    bearer_methods_supported: ["header"],
    resource_documentation: `${baseUrl}`,
  };

  return new Response(JSON.stringify(metadata), {
    headers: {
      "Content-Type": "application/json",
      "Access-Control-Allow-Origin": "*",
      "Access-Control-Allow-Methods": "GET, OPTIONS",
      "Access-Control-Allow-Headers": "Content-Type, Authorization",
    },
  });
}

async function handleAuthorize(
  request: Request,
  env: Env,
  scope: string,
  sameSite: string,
): Promise<Response> {
  const url = new URL(request.url);
  const clientId = url.searchParams.get("client_id");
  let redirectUri = url.searchParams.get("redirect_uri");
  const responseType = url.searchParams.get("response_type") || "code";
  const state = url.searchParams.get("state");
  const resource = url.searchParams.get("resource"); // MCP Required: Resource parameter

  // If no client_id, this is a direct login request
  if (!clientId) {
    const url = new URL(request.url);
    const redirectTo = url.searchParams.get("redirect_to") || "/";
    const resource = url.searchParams.get("resource");
    const requestedScope = url.searchParams.get("scope") || scope;

    // Generate PKCE code verifier and challenge
    const codeVerifier = generateCodeVerifier();
    const codeChallenge = await generateCodeChallenge(codeVerifier);

    // Create state with redirect info, code verifier, and resource
    const state: OAuthState = { redirectTo, codeVerifier, resource };
    const stateString = btoa(JSON.stringify(state));

    // Build X OAuth URL
    const xUrl = new URL("https://x.com/i/oauth2/authorize");
    xUrl.searchParams.set("response_type", "code");
    xUrl.searchParams.set("client_id", env.X_CLIENT_ID);
    xUrl.searchParams.set("redirect_uri", `${url.origin}/callback`);
    xUrl.searchParams.set("scope", requestedScope);
    xUrl.searchParams.set("state", stateString);
    xUrl.searchParams.set("code_challenge", codeChallenge);
    xUrl.searchParams.set("code_challenge_method", "S256");

    return new Response(null, {
      status: 302,
      headers: {
        Location: xUrl.toString(),
        "Set-Cookie": `oauth_state=${encodeURIComponent(
          stateString,
        )}; HttpOnly; Secure; SameSite=${sameSite}; Max-Age=600; Path=/`,
      },
    });
  }

  // Validate that client_id looks like a domain
  if (!isValidDomain(clientId) && clientId !== "localhost") {
    return new Response("Invalid client_id: must be a valid domain", {
      status: 400,
    });
  }

  // If no redirect_uri provided, use default pattern
  if (!redirectUri) {
    redirectUri = `https://${clientId}/callback`;
  }

  // Validate redirect_uri is HTTPS and on same origin as client_id
  try {
    const redirectUrl = new URL(redirectUri);

    if (redirectUrl.protocol !== "https:" && clientId !== "localhost") {
      return new Response("Invalid redirect_uri: must use HTTPS", {
        status: 400,
      });
    }

    if (redirectUrl.hostname !== clientId) {
      return new Response(
        "Invalid redirect_uri: must be on same origin as client_id",
        { status: 400 },
      );
    }
  } catch {
    return new Response("Invalid redirect_uri format", { status: 400 });
  }

  // Only support authorization code flow
  if (responseType !== "code") {
    return new Response("Unsupported response_type", { status: 400 });
  }

  // Check if user is already authenticated
  const accessToken = getAccessToken(request);
  if (accessToken) {
    // User is already authenticated, create auth code and redirect
    return await createAuthCodeAndRedirect(
      env,
      clientId,
      redirectUri,
      state,
      accessToken,
      resource,
    );
  }

  // User not authenticated, redirect to X OAuth with our callback
  // Store the OAuth provider request details for after X auth
  const providerState = {
    clientId,
    redirectUri,
    state,
    originalState: state,
    resource, // MCP: Store resource parameter
  };

  const providerStateString = btoa(JSON.stringify(providerState));

  // Generate PKCE for X OAuth
  const codeVerifier = generateCodeVerifier();
  const codeChallenge = await generateCodeChallenge(codeVerifier);

  const xState: OAuthState = {
    redirectTo: url.pathname + url.search, // Return to this authorize request after X auth
    codeVerifier,
    resource,
  };

  const xStateString = btoa(JSON.stringify(xState));

  // Build X OAuth URL
  const xUrl = new URL("https://x.com/i/oauth2/authorize");
  xUrl.searchParams.set("response_type", "code");
  xUrl.searchParams.set("client_id", env.X_CLIENT_ID);
  xUrl.searchParams.set("redirect_uri", `${url.origin}/callback`);
  xUrl.searchParams.set("scope", scope);
  xUrl.searchParams.set("state", xStateString);
  xUrl.searchParams.set("code_challenge", codeChallenge);
  xUrl.searchParams.set("code_challenge_method", "S256");

  const headers = new Headers({ Location: xUrl.toString() });
  headers.append(
    "Set-Cookie",
    `oauth_state=${encodeURIComponent(
      xStateString,
    )}; HttpOnly; Secure; SameSite=${sameSite}; Max-Age=600; Path=/`,
  );
  headers.append(
    "Set-Cookie",
    `provider_state=${encodeURIComponent(
      providerStateString,
    )}; HttpOnly; Secure; SameSite=${sameSite}; Max-Age=600; Path=/`,
  );

  return new Response(null, { status: 302, headers });
}

async function createAuthCodeAndRedirect(
  env: Env,
  clientId: string,
  redirectUri: string,
  state: string | null,
  encryptedAccessToken: string,
  resource?: string,
): Promise<Response> {
  // Generate auth code
  const authCode = generateCodeVerifier(); // Reuse the same random generation

  // Decrypt to get X access token
  const xAccessToken = await decrypt(encryptedAccessToken, env.X_CLIENT_SECRET);

  // Create Durable Object for this auth code with "code:" prefix
  const id = env.UserDO.idFromName(`code:${authCode}`);
  const authCodeDO = env.UserDO.get(id);

  await authCodeDO.setAuthData(
    xAccessToken,
    encryptedAccessToken,
    clientId,
    redirectUri,
    resource, // MCP: Store resource parameter
  );

  // Redirect back to client with auth code
  const redirectUrl = new URL(redirectUri);
  redirectUrl.searchParams.set("code", authCode);
  if (state) {
    redirectUrl.searchParams.set("state", state);
  }

  return new Response(null, {
    status: 302,
    headers: { Location: redirectUrl.toString() },
  });
}

async function handleToken(
  request: Request,
  env: Env,
  scope: string,
): Promise<Response> {
  // Handle preflight OPTIONS request
  if (request.method === "OPTIONS") {
    return new Response(null, {
      status: 204,
      headers: {
        "Access-Control-Allow-Origin": "*",
        "Access-Control-Allow-Methods": "POST, OPTIONS",
        "Access-Control-Allow-Headers": "Content-Type, Authorization",
      },
    });
  }

  if (request.method !== "POST") {
    return new Response("Method not allowed", {
      status: 405,
      headers: {
        "Access-Control-Allow-Origin": "*",
      },
    });
  }

  const headers = {
    "Content-Type": "application/json",
    "Access-Control-Allow-Origin": "*",
  };
  const formData = await request.formData();
  const grantType = formData.get("grant_type");
  const code = formData.get("code");
  const clientId = formData.get("client_id");
  const redirectUri = formData.get("redirect_uri");
  const resource = formData.get("resource"); // MCP Required: Resource parameter

  if (grantType !== "authorization_code") {
    return new Response(JSON.stringify({ error: "unsupported_grant_type" }), {
      status: 400,
      headers,
    });
  }

  if (!code || !clientId) {
    return new Response(JSON.stringify({ error: "invalid_request" }), {
      status: 400,
      headers,
    });
  }

  // Validate client_id is a valid domain
  if (
    !isValidDomain(clientId.toString()) &&
    clientId.toString() !== "localhost"
  ) {
    console.log(clientId.toString(), "invalid_client");
    return new Response(JSON.stringify({ error: "invalid_client" }), {
      status: 400,
      headers,
    });
  }

  // Get auth code data from Durable Object with "code:" prefix
  const id = env.UserDO.idFromName(`code:${code.toString()}`);
  const authCodeDO = env.UserDO.get(id);
  const authData = await authCodeDO.getAuthData();

  if (!authData) {
    return new Response(JSON.stringify({ error: "invalid_grant" }), {
      status: 400,
      headers,
    });
  }

  // Validate client_id and redirect_uri match
  if (
    authData.clientId !== clientId ||
    (redirectUri && authData.redirectUri !== redirectUri)
  ) {
    return new Response(JSON.stringify({ error: "invalid_grant" }), {
      status: 400,
      headers,
    });
  }

  // MCP Required: Validate resource parameter matches if provided
  if (resource && authData.resource !== resource) {
    return new Response(JSON.stringify({ error: "invalid_grant" }), {
      status: 400,
      headers,
    });
  }

  // Return the encrypted access token
  return new Response(
    JSON.stringify({
      access_token: authData.access_token,
      token_type: "bearer",
      scope,
    }),
    { headers },
  );
}

async function handleCallback(
  request: Request,
  env: Env,
  sameSite: string,
): Promise<Response> {
  const url = new URL(request.url);
  const code = url.searchParams.get("code");
  const stateParam = url.searchParams.get("state");

  if (!code || !stateParam) {
    return new Response("Missing code or state parameter", { status: 400 });
  }

  // Get state from cookie
  const cookies = parseCookies(request.headers.get("Cookie") || "");
  const stateCookie = cookies.oauth_state;
  const providerStateCookie = cookies.provider_state;

  if (!stateCookie || stateCookie !== stateParam) {
    return new Response("Invalid state parameter", { status: 400 });
  }

  // Parse state
  let state: OAuthState;
  try {
    state = JSON.parse(atob(stateParam));
  } catch {
    return new Response("Invalid state format", { status: 400 });
  }

  // Exchange code for token with X
  const tokenResponse = await fetch("https://api.x.com/2/oauth2/token", {
    method: "POST",
    headers: {
      "Content-Type": "application/x-www-form-urlencoded",
      Authorization: `Basic ${btoa(
        `${env.X_CLIENT_ID}:${env.X_CLIENT_SECRET}`,
      )}`,
    },
    body: new URLSearchParams({
      code: code,
      redirect_uri: `${url.origin}/callback`,
      grant_type: "authorization_code",
      code_verifier: state.codeVerifier,
    }),
  });

  if (!tokenResponse.ok) {
    return new Response(
      `X API responded with ${
        tokenResponse.status
      } - ${await tokenResponse.text()}`,
      { status: 400 },
    );
  }

  const tokenData = (await tokenResponse.json()) as any;

  if (!tokenData.access_token) {
    return new Response("Failed to get access token", { status: 400 });
  }

  // Get user info from X API
  const userResponse = await fetch(
    "https://api.x.com/2/users/me?user.fields=profile_image_url,verified",
    {
      headers: {
        Authorization: `Bearer ${tokenData.access_token}`,
      },
    },
  );

  if (!userResponse.ok) {
    return new Response("Failed to get user info", { status: 400 });
  }

  const userData = (await userResponse.json()) as any;
  const user = userData.data as XUser;
  user.profile_image_url = user.profile_image_url?.replace(
    "_normal",
    "_400x400",
  );
  // Encrypt the X access token
  const encryptedAccessToken = await encrypt(
    tokenData.access_token,
    env.X_CLIENT_SECRET,
  );

  // Store user data in Durable Object with "user:" prefix
  const userDOId = env.UserDO.idFromName(`user:${encryptedAccessToken}`);
  const userDO = env.UserDO.get(userDOId);

  await userDO.setUser(user, tokenData.access_token, encryptedAccessToken);

  // Check if this was part of an OAuth provider flow
  if (providerStateCookie) {
    try {
      const providerState = JSON.parse(atob(providerStateCookie));

      // Create auth code and redirect back to client
      const response = await createAuthCodeAndRedirect(
        env,
        providerState.clientId,
        providerState.redirectUri,
        providerState.state,
        encryptedAccessToken,
        providerState.resource, // MCP: Pass through resource parameter
      );

      // Set access token cookie and clear state cookies
      const headers = new Headers(response.headers);
      headers.append(
        "Set-Cookie",
        `oauth_state=; HttpOnly; Secure; SameSite=${sameSite}; Max-Age=0; Path=/`,
      );
      headers.append(
        "Set-Cookie",
        `provider_state=; HttpOnly; Secure; SameSite=${sameSite}; Max-Age=0; Path=/`,
      );
      headers.append(
        "Set-Cookie",
        `access_token=${encryptedAccessToken}; HttpOnly; Secure; Max-Age=34560000; SameSite=${sameSite}; Path=/`,
      );

      return new Response(response.body, { status: response.status, headers });
    } catch {
      // Fall through to normal redirect
    }
  }

  // Normal redirect (direct login)
  const headers = new Headers({ Location: state.redirectTo || "/" });
  headers.append(
    "Set-Cookie",
    `oauth_state=; HttpOnly; Secure; SameSite=${sameSite}; Max-Age=0; Path=/`,
  );
  headers.append(
    "Set-Cookie",
    `access_token=${encryptedAccessToken}; HttpOnly; Secure; Max-Age=34560000; SameSite=${sameSite}; Path=/`,
  );

  return new Response(null, { status: 302, headers });
}

/**
 * Extract access token from request cookies or Authorization header.
 * Use this to check if a user is authenticated.
 */
export function getAccessToken(request: Request): string | null {
  // Check Authorization header first (MCP clients may use this)
  const authHeader = request.headers.get("Authorization");
  if (authHeader?.startsWith("Bearer ")) {
    return authHeader.substring(7);
  }

  // Fallback to cookie for browser clients
  const cookies = parseCookies(request.headers.get("Cookie") || "");
  return cookies.access_token || null;
}

/**
 * Validate that an access token is intended for this resource server.
 * MCP servers MUST validate token audience.
 */
export function validateTokenAudience(
  request: Request,
  expectedResource: string,
): boolean {
  // For this simple implementation, we assume tokens encrypted with our secret
  // are valid for our resource. In a production system, you would decode
  // the token and check the 'aud' claim or resource parameter.
  const token = getAccessToken(request);
  return token !== null;
}

// Utility functions
function parseCookies(cookieHeader: string): Record<string, string> {
  const cookies: Record<string, string> = {};

  cookieHeader.split(";").forEach((cookie) => {
    const [name, value] = cookie.trim().split("=");
    if (name && value) {
      cookies[name] = decodeURIComponent(value);
    }
  });

  return cookies;
}

function isValidDomain(domain: string): boolean {
  // Basic domain validation - must contain at least one dot and valid characters
  const domainRegex =
    /^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$/;
  return (
    domainRegex.test(domain) && domain.includes(".") && domain.length <= 253
  );
}

function generateCodeVerifier(): string {
  const array = new Uint8Array(32);
  crypto.getRandomValues(array);
  return btoa(String.fromCharCode.apply(null, Array.from(array)))
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=/g, "");
}

async function generateCodeChallenge(verifier: string): Promise<string> {
  const encoder = new TextEncoder();
  const data = encoder.encode(verifier);
  const digest = await crypto.subtle.digest("SHA-256", data);

  return btoa(
    String.fromCharCode.apply(null, Array.from(new Uint8Array(digest))),
  )
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=/g, "");
}

// Encryption utilities
async function encrypt(text: string, secret: string): Promise<string> {
  const encoder = new TextEncoder();
  const data = encoder.encode(text);
  const keyMaterial = await crypto.subtle.importKey(
    "raw",
    encoder.encode(secret),
    { name: "PBKDF2" },
    false,
    ["deriveKey"],
  );

  const salt = crypto.getRandomValues(new Uint8Array(16));
  const key = await crypto.subtle.deriveKey(
    {
      name: "PBKDF2",
      salt: salt,
      iterations: 100000,
      hash: "SHA-256",
    },
    keyMaterial,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt"],
  );

  const iv = crypto.getRandomValues(new Uint8Array(12));
  const encrypted = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv: iv },
    key,
    data,
  );

  // Combine salt + iv + encrypted data
  const combined = new Uint8Array(
    salt.length + iv.length + encrypted.byteLength,
  );
  combined.set(salt, 0);
  combined.set(iv, salt.length);
  combined.set(new Uint8Array(encrypted), salt.length + iv.length);

  return btoa(String.fromCharCode.apply(null, Array.from(combined)))
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=/g, "");
}

async function decrypt(encrypted: string, secret: string): Promise<string> {
  const encoder = new TextEncoder();
  const decoder = new TextDecoder();

  // Decode the base64url
  const combined = new Uint8Array(
    atob(encrypted.replace(/-/g, "+").replace(/_/g, "/"))
      .split("")
      .map((c) => c.charCodeAt(0)),
  );

  // Extract salt, iv, and encrypted data
  const salt = combined.slice(0, 16);
  const iv = combined.slice(16, 28);
  const data = combined.slice(28);

  const keyMaterial = await crypto.subtle.importKey(
    "raw",
    encoder.encode(secret),
    { name: "PBKDF2" },
    false,
    ["deriveKey"],
  );

  const key = await crypto.subtle.deriveKey(
    {
      name: "PBKDF2",
      salt: salt,
      iterations: 100000,
      hash: "SHA-256",
    },
    keyMaterial,
    { name: "AES-GCM", length: 256 },
    false,
    ["decrypt"],
  );

  const decrypted = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: iv },
    key,
    data,
  );

  return decoder.decode(decrypted);
}

export interface UserContext<T = { [key: string]: any }>
  extends ExecutionContext {
  /** Should contain authenticated X User */
  user: XUser | undefined;
  /** X Access token */
  xAccessToken: string | undefined;
  /** Access token. Can be decrypted with client secret to retrieve X access token */
  accessToken: string | undefined;
  registered: boolean;
  getMetadata?: () => Promise<T>;
  setMetadata?: (metadata: T) => Promise<void>;
}

interface UserFetchHandler<TEnv = {}, TMetadata = { [key: string]: any }> {
  (request: Request, env: Env & TEnv, ctx: UserContext<TMetadata>):
    | Response
    | Promise<Response>;
}

/** Easiest way to add oauth with required login! */
export function withSimplerAuth<TEnv = {}, TMetadata = { [key: string]: any }>(
  handler: UserFetchHandler<TEnv, TMetadata>,
  config?: {
    /** If true, login will be forced and user will always be present */
    isLoginRequired?: boolean;
    /** Defaults to "users.read tweet.read offline.access" meaning you get the user info and can read tweets */
    scope?: string;
    /** Defaults to 'Lax' meaning subdomains are also valid to use the cookies */
    sameSite?: "Strict" | "Lax";
  },
): ExportedHandlerFetchHandler<Env & TEnv> {
  const { scope, sameSite } = config || {};

  return async (
    request: Request,
    env: TEnv & Env,
    ctx: ExecutionContext,
  ): Promise<Response> => {
    const oauth = await handleOAuth(request, env, scope, sameSite);
    if (oauth) {
      return oauth;
    }

    // Get user from access token
    let userDO: DurableObjectStub<UserDO>;

    let user: XUser | undefined = undefined;
    let registered = false;
    let xAccessToken: string | undefined = undefined;
    const accessToken = getAccessToken(request);
    if (accessToken) {
      try {
        // Get user data from Durable Object
        const userDOId = env.UserDO.idFromName(`user:${accessToken}`);
        userDO = env.UserDO.get(userDOId);
        const userData = await userDO.getUser();

        if (userData) {
          user = userData.user as unknown as XUser;
          registered = true;
          xAccessToken = userData.xAccessToken;
        }
      } catch (error) {
        console.error("Error getting user data:", error);
      }
    }

    if (!user && config?.isLoginRequired) {
      const isBrowser = request.headers.get("accept")?.includes("text/html");
      const url = new URL(request.url);
      const resourceMetadataUrl = `${url.origin}/.well-known/oauth-protected-resource`;

      // Require login
      const Location = `${
        new URL(request.url).origin
      }/authorize?redirect_to=${encodeURIComponent(request.url)}`;

      return new Response(
        `"access_token" Cookie or "Authorization" header required. User must login at ${Location}.`,
        {
          status: isBrowser ? 302 : 401,
          headers: {
            Location,
            "X-Login-URL": Location,
            // MCP Required: WWW-Authenticate header with resource metadata URL (RFC9728)
            "WWW-Authenticate": `Bearer realm="main", login_url="${Location}", resource_metadata="${resourceMetadataUrl}"`,
          },
        },
      );
    }

    // Create enhanced context with user and registered status
    const enhancedCtx: UserContext<TMetadata> = {
      passThroughOnException: () => ctx.passThroughOnException(),
      props: ctx.props,
      waitUntil: (promise: Promise<any>) => ctx.waitUntil(promise),
      user,
      registered,
      xAccessToken,
      accessToken,
      setMetadata: userDO ? userDO.setMetadata : undefined,
      getMetadata: userDO
        ? () => userDO.getMetadata() as Promise<TMetadata>
        : undefined,
    };

    // Call the user's fetch handler
    const response = await handler(request, env, enhancedCtx);

    // Merge any headers from middleware (like Set-Cookie) with the response
    const newHeaders = new Headers(response.headers);

    return new Response(response.body, {
      status: response.status,
      statusText: response.statusText,
      headers: newHeaders,
    });
  };
}
