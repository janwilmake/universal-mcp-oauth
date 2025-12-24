/// <reference types="@cloudflare/workers-types" />
/// <reference lib="esnext" />
import { DurableObject } from "cloudflare:workers";

export interface UniversalOAuthEnv {
  OAuthProviders: DurableObjectNamespace<OAuthProviders>;
}

export interface OAuthProvider extends Record<string, SqlStorageValue> {
  id: string;
  /** The resource URL pattern this auth applies to (e.g., "https://api.example.com" or "https://api.example.com/v1") */
  resource_url: string;
  /** Human-readable name for the provider */
  name: string;
  client_id?: string;
  client_secret?: string;
  access_token?: string;
  refresh_token?: string;
  token_endpoint?: string;
  token_type?: "Bearer" | string;
  expires_in?: number;
  scope?: string;
  created_at: string;
  updated_at: string;
  /** Whether this resource requires no auth (public) */
  public?: 0 | 1;
  /** Additional metadata as JSON */
  metadata?: string;
}

export class OAuthProviders extends DurableObject {
  sql: SqlStorage;

  constructor(state: DurableObjectState, env: any) {
    super(state, env);
    this.sql = state.storage.sql;
    this.migrate();
  }

  migrate() {
    this.sql.exec(`
      CREATE TABLE IF NOT EXISTS providers (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        resource_url TEXT NOT NULL UNIQUE,
        name TEXT NOT NULL,
        client_id TEXT,
        client_secret TEXT,
        access_token TEXT,
        refresh_token TEXT,
        token_endpoint TEXT,
        token_type TEXT DEFAULT 'Bearer',
        expires_in INTEGER,
        scope TEXT,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        public BOOLEAN DEFAULT 0,
        metadata TEXT
      )
    `);

    // Add new columns if they don't exist
    const columnsToAdd = ["metadata", "scope"];
    for (const column of columnsToAdd) {
      try {
        this.sql.exec(`ALTER TABLE providers ADD COLUMN ${column} TEXT`);
      } catch (e) {
        // Column already exists
      }
    }
  }

  async addProvider(
    resourceUrl: string,
    name: string,
    options: {
      clientId?: string;
      clientSecret?: string;
      accessToken?: string;
      refreshToken?: string;
      tokenEndpoint?: string;
      expiresIn?: number;
      scope?: string;
      isPublic?: boolean;
      metadata?: Record<string, unknown>;
    } = {},
  ) {
    const metadataJson = options.metadata
      ? JSON.stringify(options.metadata)
      : null;

    this.sql.exec(
      `
      INSERT OR REPLACE INTO providers 
      (resource_url, name, client_id, client_secret, access_token, refresh_token, token_endpoint, expires_in, scope, updated_at, public, metadata)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP, ?, ?)
    `,
      resourceUrl,
      name,
      options.clientId || null,
      options.clientSecret || null,
      options.accessToken || null,
      options.refreshToken || null,
      options.tokenEndpoint || null,
      options.expiresIn || null,
      options.scope || null,
      options.isPublic ? 1 : 0,
      metadataJson,
    );
  }

  async updateTokens(
    resourceUrl: string,
    accessToken: string,
    refreshToken?: string,
    expiresIn?: number,
  ) {
    this.sql.exec(
      `UPDATE providers SET access_token = ?, refresh_token = ?, expires_in = ?, updated_at = CURRENT_TIMESTAMP WHERE resource_url = ?`,
      accessToken,
      refreshToken || null,
      expiresIn || null,
      resourceUrl,
    );
  }

  async getProvider(resourceUrl: string): Promise<OAuthProvider | null> {
    const result = this.sql
      .exec<OAuthProvider>(
        `SELECT * FROM providers WHERE resource_url = ? LIMIT 1`,
        resourceUrl,
      )
      .toArray()[0];

    return result || null;
  }

  /**
   * Find the most specific provider that matches a URL.
   * E.g., for "https://api.example.com/v1/users/123", it would match:
   * - "https://api.example.com/v1/users/123" (exact)
   * - "https://api.example.com/v1/users"
   * - "https://api.example.com/v1"
   * - "https://api.example.com"
   */
  async findProviderForUrl(url: string): Promise<OAuthProvider | null> {
    const urlObj = new URL(url);
    const baseUrl = `${urlObj.protocol}//${urlObj.host}`;
    const pathSegments = urlObj.pathname.split("/").filter(Boolean);

    // Try from most specific to least specific
    const candidates = [url];

    // Add path-based candidates
    for (let i = pathSegments.length; i >= 0; i--) {
      const path = i > 0 ? "/" + pathSegments.slice(0, i).join("/") : "";
      candidates.push(baseUrl + path);
    }

    for (const candidate of candidates) {
      const provider = await this.getProvider(candidate);
      if (provider) {
        return provider;
      }
    }

    return null;
  }

  async getProviders(resourceUrls: string[]): Promise<OAuthProvider[]> {
    if (resourceUrls.length === 0) return [];

    const placeholders = resourceUrls.map(() => "?").join(",");
    return this.sql
      .exec<OAuthProvider>(
        `SELECT * FROM providers WHERE resource_url IN (${placeholders}) ORDER BY created_at DESC`,
        ...resourceUrls,
      )
      .toArray();
  }

  async getAllProviders(): Promise<OAuthProvider[]> {
    return this.sql
      .exec<OAuthProvider>(`SELECT * FROM providers ORDER BY created_at DESC`)
      .toArray();
  }

  async removeProvider(resourceUrl: string) {
    this.sql.exec(`DELETE FROM providers WHERE resource_url = ?`, resourceUrl);
  }
}

// --- Authorization Flow Types ---

export interface AuthorizationFlowData {
  authorizationUrl?: string;
  codeVerifier?: string;
  state?: string;
  tokenEndpoint?: string;
  clientId?: string;
  clientSecret?: string;
  resourceUrl: string;
  scope?: string;
  noAuthRequired?: boolean;
  accessToken?: string;
}

export interface AuthServerMetadata {
  authorization_endpoint: string;
  token_endpoint: string;
  registration_endpoint?: string;
  code_challenge_methods_supported?: string[];
  scopes_supported?: string[];
  [key: string]: unknown;
}

export interface ClientInfo {
  name: string;
  version: string;
}

// --- PKCE Helpers ---

function generateCodeVerifier(): string {
  const array = new Uint8Array(32);
  crypto.getRandomValues(array);
  return btoa(String.fromCharCode(...array))
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=/g, "");
}

async function generateCodeChallenge(codeVerifier: string): Promise<string> {
  const encoder = new TextEncoder();
  const data = encoder.encode(codeVerifier);
  const digest = await crypto.subtle.digest("SHA-256", data);
  const base64 = btoa(String.fromCharCode(...new Uint8Array(digest)));
  return base64.replace(/\+/g, "-").replace(/\//g, "_").replace(/=/g, "");
}

function generateRandomState(): string {
  const array = new Uint8Array(16);
  crypto.getRandomValues(array);
  return btoa(String.fromCharCode(...array))
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=/g, "");
}

// --- WWW-Authenticate Parser ---

export interface WWWAuthenticateInfo {
  scheme: string;
  realm?: string;
  resourceMetadataUrl?: string;
  scope?: string;
  error?: string;
  errorDescription?: string;
}

export function parseWWWAuthenticate(header: string): WWWAuthenticateInfo {
  const result: WWWAuthenticateInfo = { scheme: "" };

  // Extract scheme (first word)
  const schemeMatch = header.match(/^(\w+)\s*/);
  if (schemeMatch) {
    result.scheme = schemeMatch[1];
  }

  // Extract parameters
  const paramRegex = /(\w+)="([^"]+)"/g;
  let match;
  while ((match = paramRegex.exec(header)) !== null) {
    const [, key, value] = match;
    switch (key) {
      case "realm":
        result.realm = value;
        break;
      case "resource_metadata":
        result.resourceMetadataUrl = value;
        break;
      case "scope":
        result.scope = value;
        break;
      case "error":
        result.error = value;
        break;
      case "error_description":
        result.errorDescription = value;
        break;
    }
  }

  return result;
}

// --- Authorization Server Discovery ---

async function discoverAuthServerMetadata(
  issuerUrl: string,
): Promise<AuthServerMetadata> {
  const url = new URL(issuerUrl);
  const basePath = url.pathname === "/" ? "" : url.pathname;

  const endpoints: string[] = [];

  if (basePath && basePath !== "") {
    endpoints.push(
      `/.well-known/oauth-authorization-server${basePath}`,
      `/.well-known/openid-configuration${basePath}`,
      `${basePath}/.well-known/openid-configuration`,
    );
  }

  endpoints.push(
    `/.well-known/oauth-authorization-server`,
    `/.well-known/openid-configuration`,
  );

  const discoveryErrors: string[] = [];

  for (const endpoint of endpoints) {
    try {
      const metadataUrl = new URL(endpoint, url.origin);
      const response = await fetch(metadataUrl);
      if (response.ok) {
        const metadata = (await response.json()) as AuthServerMetadata;

        if (metadata.authorization_endpoint && metadata.token_endpoint) {
          return metadata;
        }

        discoveryErrors.push(`${endpoint}: Missing required endpoints`);
      } else {
        discoveryErrors.push(`${endpoint}: ${response.status}`);
      }
    } catch (error) {
      discoveryErrors.push(`${endpoint}: ${(error as Error).message}`);
    }
  }

  throw new Error(
    `Could not discover authorization server metadata for ${issuerUrl}. Tried: ${discoveryErrors.join(
      ", ",
    )}`,
  );
}

// --- Generic Authorization URL Construction ---

/**
 * Constructs an OAuth2 authorization URL for any protected resource.
 * Handles WWW-Authenticate header parsing, auth server discovery, and dynamic client registration.
 */
export async function constructAuthorizationUrl(
  resourceUrl: string,
  callbackUrl: string,
  clientInfo: ClientInfo,
  options: {
    /** Pre-parsed WWW-Authenticate info if available */
    wwwAuthenticateInfo?: WWWAuthenticateInfo;
    /** Scope to request */
    scope?: string;
    /** Test request to check if auth is required */
    testRequest?: () => Promise<Response>;
  } = {},
): Promise<AuthorizationFlowData> {
  let resourceMetadataUrl: string | undefined;
  let scope = options.scope;

  // If we have WWW-Authenticate info, extract what we need
  if (options.wwwAuthenticateInfo) {
    resourceMetadataUrl = options.wwwAuthenticateInfo.resourceMetadataUrl;
    scope = scope || options.wwwAuthenticateInfo.scope;
  }

  // If a test request function is provided, check if auth is required
  if (options.testRequest) {
    try {
      const testResponse = await options.testRequest();

      if (testResponse.ok) {
        // No authentication required
        return {
          resourceUrl,
          noAuthRequired: true,
          accessToken: undefined,
        };
      }

      if (testResponse.status === 401) {
        const wwwAuth = testResponse.headers.get("WWW-Authenticate");
        if (wwwAuth) {
          const parsed = parseWWWAuthenticate(wwwAuth);
          resourceMetadataUrl =
            resourceMetadataUrl || parsed.resourceMetadataUrl;
          scope = scope || parsed.scope;
        }
      }
    } catch (error) {
      // Continue with auth discovery
    }
  }

  // Discover authorization servers
  let authorizationServers: string[] = [];

  // Try protected resource metadata first
  if (resourceMetadataUrl) {
    try {
      const resourceResponse = await fetch(resourceMetadataUrl);
      if (resourceResponse.ok) {
        const resourceMetadata = (await resourceResponse.json()) as {
          authorization_servers?: string[];
        };
        if (resourceMetadata.authorization_servers?.length) {
          authorizationServers = resourceMetadata.authorization_servers;
        }
      }
    } catch (error) {
      // Continue to fallback
    }
  }

  // Fallback: .well-known/oauth-protected-resource on resource host
  if (authorizationServers.length === 0) {
    try {
      const resourceUrlObj = new URL(resourceUrl);
      const fallbackUrl = new URL(
        "/.well-known/oauth-protected-resource",
        `${resourceUrlObj.protocol}//${resourceUrlObj.host}`,
      );

      const resourceResponse = await fetch(fallbackUrl);
      if (resourceResponse.ok) {
        const resourceMetadata = (await resourceResponse.json()) as {
          authorization_servers?: string[];
        };
        if (resourceMetadata.authorization_servers?.length) {
          authorizationServers = resourceMetadata.authorization_servers;
        }
      }
    } catch (error) {
      // Continue to next fallback
    }
  }

  // Final fallback: assume auth server is on same host
  if (authorizationServers.length === 0) {
    const resourceUrlObj = new URL(resourceUrl);
    authorizationServers = [
      `${resourceUrlObj.protocol}//${resourceUrlObj.host}`,
    ];
  }

  // Try each authorization server
  let authMetadata: AuthServerMetadata | undefined;
  let selectedAuthServer: string | undefined;
  const discoveryErrors: string[] = [];

  for (const authServerUrl of authorizationServers) {
    try {
      authMetadata = await discoverAuthServerMetadata(authServerUrl);
      selectedAuthServer = authServerUrl;
      break;
    } catch (error) {
      discoveryErrors.push(`${authServerUrl}: ${(error as Error).message}`);
    }
  }

  if (!authMetadata || !selectedAuthServer) {
    throw new Error(
      `Could not discover authorization server metadata. Tried: ${discoveryErrors.join(
        ", ",
      )}`,
    );
  }

  // Dynamic client registration
  let clientId: string;
  let clientSecret: string | undefined;

  if (authMetadata.registration_endpoint) {
    try {
      const regResponse = await fetch(authMetadata.registration_endpoint, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          redirect_uris: [callbackUrl],
          grant_types: ["authorization_code"],
          response_types: ["code"],
          client_name: clientInfo.name,
          application_type: "native",
        }),
      });

      if (!regResponse.ok) {
        const errorText = await regResponse.text().catch(() => "Unknown error");
        throw new Error(
          `Client registration failed: ${regResponse.status} - ${errorText}`,
        );
      }

      const registrationResponse = (await regResponse.json()) as {
        client_id: string;
        client_secret?: string;
      };
      clientId = registrationResponse.client_id;
      clientSecret = registrationResponse.client_secret;
    } catch (error) {
      throw new Error(
        `Dynamic client registration failed: ${(error as Error).message}`,
      );
    }
  } else {
    throw new Error(
      "Authorization server does not support dynamic client registration",
    );
  }

  // Generate PKCE parameters
  const codeVerifier = generateCodeVerifier();
  const codeChallenge = await generateCodeChallenge(codeVerifier);
  const state = generateRandomState();

  // Construct authorization URL
  const authUrl = new URL(authMetadata.authorization_endpoint);
  const params: Record<string, string> = {
    response_type: "code",
    client_id: clientId,
    redirect_uri: callbackUrl,
    code_challenge: codeChallenge,
    code_challenge_method: "S256",
    state: state,
  };

  // Add resource parameter if PKCE is supported (per OAuth 2.0 Resource Indicators)
  if (authMetadata.code_challenge_methods_supported?.includes("S256")) {
    params.resource = resourceUrl;
  }

  if (scope) {
    params.scope = scope;
  }

  Object.entries(params).forEach(([key, value]) => {
    authUrl.searchParams.set(key, value);
  });

  return {
    authorizationUrl: authUrl.toString(),
    codeVerifier,
    state,
    tokenEndpoint: authMetadata.token_endpoint,
    clientId,
    clientSecret,
    resourceUrl,
    scope,
    noAuthRequired: false,
  };
}

// --- Token Exchange ---

export async function exchangeCodeForToken(
  code: string,
  authFlowData: AuthorizationFlowData,
  redirectUri: string,
): Promise<{
  access_token: string;
  refresh_token?: string;
  expires_in?: number;
  scope?: string;
}> {
  const tokenRequestBody = new URLSearchParams({
    grant_type: "authorization_code",
    code,
    redirect_uri: redirectUri,
    client_id: authFlowData.clientId!,
    code_verifier: authFlowData.codeVerifier!,
  });

  if (authFlowData.resourceUrl) {
    tokenRequestBody.append("resource", authFlowData.resourceUrl);
  }

  if (authFlowData.clientSecret) {
    tokenRequestBody.append("client_secret", authFlowData.clientSecret);
  }

  const tokenResponse = await fetch(authFlowData.tokenEndpoint!, {
    method: "POST",
    headers: {
      "Content-Type": "application/x-www-form-urlencoded",
      Accept: "application/json",
    },
    body: tokenRequestBody,
  });

  if (!tokenResponse.ok) {
    const errorText = await tokenResponse.text();
    throw new Error(
      `Token exchange failed: ${tokenResponse.status} ${errorText}`,
    );
  }

  return tokenResponse.json();
}

export async function refreshAccessToken(
  refreshToken: string,
  clientId?: string,
  clientSecret?: string,
  tokenEndpoint?: string,
): Promise<{
  access_token: string;
  refresh_token?: string;
  expires_in?: number;
}> {
  if (!tokenEndpoint) {
    throw new Error("Token endpoint is required for token refresh");
  }

  const tokenRequestBody = new URLSearchParams({
    grant_type: "refresh_token",
    refresh_token: refreshToken,
  });

  if (clientId) {
    tokenRequestBody.append("client_id", clientId);
  }

  if (clientSecret) {
    tokenRequestBody.append("client_secret", clientSecret);
  }

  const tokenResponse = await fetch(tokenEndpoint, {
    method: "POST",
    headers: {
      "Content-Type": "application/x-www-form-urlencoded",
      Accept: "application/json",
    },
    body: tokenRequestBody,
  });

  if (!tokenResponse.ok) {
    const errorText = await tokenResponse.text();
    throw new Error(
      `Token refresh failed: ${tokenResponse.status} ${errorText}`,
    );
  }

  return tokenResponse.json();
}

// --- OAuth Handler ---

export interface UniversalOAuthConfig {
  userId: string;
  clientInfo: ClientInfo;
  baseUrl?: string;
  pathPrefix?: string;
  /** Called when auth is successful to extract provider name and metadata */
  onAuthSuccess?: (
    resourceUrl: string,
    accessToken: string,
  ) => Promise<{ name: string; metadata?: Record<string, unknown> }>;
}

const VERSION = "v1:";

export interface UniversalOAuthHandlers {
  middleware: (
    request: Request,
    env: UniversalOAuthEnv,
    ctx: ExecutionContext,
  ) => Promise<Response | null>;
  removeProvider: (resourceUrl: string) => Promise<void>;
  getProviders: () => Promise<
    (OAuthProvider & {
      metadata: Record<string, unknown> | null;
      reauthorizeUrl: string;
    })[]
  >;
  refreshProviders: (urls: string[]) => Promise<void>;
  /** Get authorization header for a URL, finding the most specific matching provider */
  getAuthorizationForUrl: (
    url: string,
  ) => Promise<{ Authorization: string } | null>;
  /** Get the stub for direct access */
  getStub: () => DurableObjectStub<OAuthProviders>;
}

export function createUniversalOAuthHandler(
  config: UniversalOAuthConfig,
  env: UniversalOAuthEnv,
): UniversalOAuthHandlers | null {
  const {
    userId,
    baseUrl,
    clientInfo,
    pathPrefix = "/oauth",
    onAuthSuccess,
  } = config;

  if (!userId) {
    return null;
  }

  const getStub = () => {
    return env.OAuthProviders.get(
      env.OAuthProviders.idFromName(VERSION + userId),
    );
  };

  const middleware = async (
    request: Request,
    env: UniversalOAuthEnv,
    ctx: ExecutionContext,
  ): Promise<Response | null> => {
    const url = new URL(request.url);
    const path = url.pathname;

    if (!path.startsWith(pathPrefix + "/")) {
      return null;
    }

    const origin = baseUrl || url.origin;
    const oauthProviders = getStub();

    if (path === `${pathPrefix}/login`) {
      return handleLogin(
        request,
        oauthProviders,
        origin,
        clientInfo,
        pathPrefix,
        onAuthSuccess,
      );
    }

    if (path.startsWith(`${pathPrefix}/callback/`)) {
      const hostname = path.split(`${pathPrefix}/callback/`)[1];
      return handleCallback(
        request,
        oauthProviders,
        hostname,
        origin,
        clientInfo,
        pathPrefix,
        onAuthSuccess,
      );
    }

    return null;
  };

  const removeProvider = async (resourceUrl: string): Promise<void> => {
    const stub = getStub();
    await stub.removeProvider(resourceUrl);
  };

  const getProviders = async () => {
    const stub = getStub();
    const providers = await stub.getAllProviders();

    return providers.map((provider) => ({
      ...provider,
      metadata: provider.metadata ? JSON.parse(provider.metadata) : null,
      reauthorizeUrl: `${
        baseUrl || "https://example.com"
      }${pathPrefix}/login?url=${encodeURIComponent(provider.resource_url)}`,
    }));
  };

  const refreshProviders = async (urls: string[]): Promise<void> => {
    const stub = getStub();
    const providers = await stub.getProviders(urls);
    const now = Math.floor(Date.now() / 1000);

    const expiredProviders = providers.filter((provider) => {
      if (
        !provider.refresh_token ||
        !provider.token_endpoint ||
        !provider.expires_in
      ) {
        return false;
      }

      const updatedAtSeconds = Math.floor(
        new Date(provider.updated_at).getTime() / 1000,
      );
      const expirationTime = updatedAtSeconds + provider.expires_in;

      // Refresh if expired or within 5 minutes of expiry
      return now >= expirationTime - 300;
    });

    const refreshPromises = expiredProviders.map(async (provider) => {
      try {
        const tokenData = await refreshAccessToken(
          provider.refresh_token!,
          provider.client_id,
          provider.client_secret,
          provider.token_endpoint!,
        );

        await stub.updateTokens(
          provider.resource_url,
          tokenData.access_token,
          tokenData.refresh_token || provider.refresh_token,
          tokenData.expires_in,
        );
      } catch (error) {
        console.error(
          `Failed to refresh token for ${provider.resource_url}:`,
          error,
        );
      }
    });

    await Promise.all(refreshPromises);
  };

  const getAuthorizationForUrl = async (
    url: string,
  ): Promise<{ Authorization: string } | null> => {
    const stub = getStub();
    const provider = await stub.findProviderForUrl(url);

    if (provider?.access_token) {
      return {
        Authorization: `${provider.token_type || "Bearer"} ${
          provider.access_token
        }`,
      };
    }

    return null;
  };

  return {
    middleware,
    removeProvider,
    getProviders,
    refreshProviders,
    getAuthorizationForUrl,
    getStub,
  };
}

// --- Request Handlers ---

function createSuccessHTML(
  providerName: string,
  autoClose: boolean = false,
): string {
  return `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Authentication Success</title>
    <style>
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            margin: 0;
            padding: 20px;
            background: #f5f5f5;
            display: flex;
            justify-content: center;
            align-items: center;
            min-height: 100vh;
        }
        .card {
            background: white;
            border-radius: 12px;
            padding: 32px;
            box-shadow: 0 4px 16px rgba(0, 0, 0, 0.1);
            text-align: center;
            max-width: 400px;
            width: 100%;
        }
        .success-icon {
            width: 48px;
            height: 48px;
            background: #10B981;
            border-radius: 50%;
            display: flex;
            align-items: center;
            justify-content: center;
            margin: 0 auto 20px;
        }
        .success-icon svg {
            width: 24px;
            height: 24px;
            stroke: white;
            stroke-width: 3;
        }
        h1 { color: #111827; font-size: 20px; font-weight: 600; margin: 0 0 12px 0; }
        p { color: #6B7280; font-size: 16px; margin: 0 0 24px 0; line-height: 1.5; }
        .provider-name { color: #10B981; font-weight: 600; }
        .close-note { font-size: 14px; color: #9CA3AF; margin: 0; }
    </style>
    ${
      autoClose
        ? "<script>setTimeout(() => window.close(), 1000);</script>"
        : ""
    }
</head>
<body>
    <div class="card">
        <div class="success-icon">
            <svg fill="none" viewBox="0 0 24 24"><polyline points="20,6 9,17 4,12"></polyline></svg>
        </div>
        <h1>Authentication Successful!</h1>
        <p>Successfully authenticated with <span class="provider-name">${providerName}</span>.</p>
        <p class="close-note">You can close this page.</p>
    </div>
</body>
</html>`;
}

async function handleLogin(
  request: Request,
  oauthProviders: DurableObjectStub<OAuthProviders>,
  origin: string,
  clientInfo: ClientInfo,
  pathPrefix: string,
  onAuthSuccess?: (
    resourceUrl: string,
    accessToken: string,
  ) => Promise<{ name: string; metadata?: Record<string, unknown> }>,
): Promise<Response> {
  const url = new URL(request.url);
  const resourceUrl = url.searchParams.get("url");
  const scope = url.searchParams.get("scope") || undefined;

  if (!resourceUrl) {
    return new Response("Missing url parameter", { status: 400 });
  }

  try {
    const resourceUrlObj = new URL(resourceUrl);
    const hostname = resourceUrlObj.hostname;
    const callbackUrl = `${origin}${pathPrefix}/callback/${hostname}`;

    const authFlowData = await constructAuthorizationUrl(
      resourceUrl,
      callbackUrl,
      clientInfo,
      {
        scope,
        testRequest: async () => {
          return fetch(resourceUrl, {
            method: "HEAD",
            headers: { Accept: "*/*" },
          });
        },
      },
    );

    // If no auth is required, add the provider immediately
    if (authFlowData.noAuthRequired) {
      let name = hostname;
      let metadata: Record<string, unknown> | undefined;

      if (onAuthSuccess) {
        try {
          const result = await onAuthSuccess(resourceUrl, "");
          name = result.name;
          metadata = result.metadata;
        } catch (e) {
          // Use default name
        }
      }

      await oauthProviders.addProvider(resourceUrl, name, {
        isPublic: true,
        metadata,
      });

      return new Response(createSuccessHTML(name, true), {
        headers: { "Content-Type": "text/html" },
      });
    }

    // Store auth flow data in cookie
    const authFlowCookie = encodeURIComponent(
      btoa(JSON.stringify({ ...authFlowData, hostname })),
    );

    return new Response(null, {
      status: 302,
      headers: {
        Location: authFlowData.authorizationUrl!,
        "Set-Cookie": `oauth_auth_${hostname}=${authFlowCookie}; HttpOnly; Secure; SameSite=Lax; Max-Age=600; Path=/`,
      },
    });
  } catch (error) {
    return new Response(`Authorization failed: ${(error as Error).message}`, {
      status: 400,
    });
  }
}

async function handleCallback(
  request: Request,
  oauthProviders: DurableObjectStub<OAuthProviders>,
  hostname: string,
  origin: string,
  clientInfo: ClientInfo,
  pathPrefix: string,
  onAuthSuccess?: (
    resourceUrl: string,
    accessToken: string,
  ) => Promise<{ name: string; metadata?: Record<string, unknown> }>,
): Promise<Response> {
  const url = new URL(request.url);
  const code = url.searchParams.get("code");
  const stateParam = url.searchParams.get("state");

  if (!code || !stateParam) {
    return new Response("Missing code or state", { status: 400 });
  }

  // Get auth flow data from cookie
  const cookieName = `oauth_auth_${hostname}`;
  const cookieHeader = request.headers.get("Cookie");
  let authFlowData: (AuthorizationFlowData & { hostname: string }) | undefined;

  if (cookieHeader) {
    const cookies = Object.fromEntries(
      cookieHeader.split("; ").map((c) => c.split("=")),
    );
    if (cookies[cookieName]) {
      try {
        authFlowData = JSON.parse(
          atob(decodeURIComponent(cookies[cookieName])),
        );
      } catch (error) {
        return new Response("Invalid auth flow data", { status: 400 });
      }
    }
  }

  if (!authFlowData) {
    return new Response("Missing auth flow data", { status: 400 });
  }

  if (stateParam !== authFlowData.state) {
    return new Response("Invalid state parameter", { status: 400 });
  }

  if (!authFlowData.clientId || !authFlowData.tokenEndpoint) {
    return new Response("Missing client credentials or token endpoint", {
      status: 400,
    });
  }

  try {
    const tokenData = await exchangeCodeForToken(
      code,
      authFlowData,
      `${origin}${pathPrefix}/callback/${hostname}`,
    );

    if (!tokenData.access_token) {
      return new Response("No access token received", { status: 400 });
    }

    let name = hostname;
    let metadata: Record<string, unknown> | undefined;

    if (onAuthSuccess) {
      try {
        const result = await onAuthSuccess(
          authFlowData.resourceUrl,
          tokenData.access_token,
        );
        name = result.name;
        metadata = result.metadata;
      } catch (e) {
        // Use default name
      }
    }

    await oauthProviders.addProvider(authFlowData.resourceUrl, name, {
      clientId: authFlowData.clientId,
      clientSecret: authFlowData.clientSecret,
      accessToken: tokenData.access_token,
      refreshToken: tokenData.refresh_token,
      tokenEndpoint: authFlowData.tokenEndpoint,
      expiresIn: tokenData.expires_in,
      scope: tokenData.scope || authFlowData.scope,
      isPublic: false,
      metadata,
    });

    return new Response(createSuccessHTML(name, false), {
      headers: {
        "Content-Type": "text/html",
        "Set-Cookie": `oauth_auth_${hostname}=; HttpOnly; Secure; SameSite=Lax; Max-Age=0; Path=/`,
      },
    });
  } catch (error) {
    return new Response(`Token exchange failed: ${(error as Error).message}`, {
      status: 400,
    });
  }
}

// --- Utility Functions ---

/**
 * Get authorization header for a URL, finding the most specific matching provider
 */
export async function getAuthorizationForUrl(
  env: UniversalOAuthEnv,
  userId: string,
  url: string,
): Promise<{ Authorization: string } | null> {
  try {
    const stub = env.OAuthProviders.get(
      env.OAuthProviders.idFromName(VERSION + userId),
    );
    const provider = await stub.findProviderForUrl(url);

    if (provider?.access_token) {
      return {
        Authorization: `${provider.token_type || "Bearer"} ${
          provider.access_token
        }`,
      };
    }

    return null;
  } catch (error) {
    return null;
  }
}
