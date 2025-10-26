/// <reference types="@cloudflare/workers-types" />
/// <reference lib="esnext" />
import { DurableObject } from "cloudflare:workers";
import { getMultiStub } from "multistub";
import {
  Queryable,
  QueryableHandler,
  studioMiddleware,
} from "queryable-object";

const USER_DO_PREFIX = "user-v6:";

export interface Env {
  SELF_CLIENT_ID: string;
  GITHUB_CLIENT_ID: string;
  GITHUB_CLIENT_SECRET: string;
  ENCRYPTION_SECRET: string;
  ADMIN_GITHUB_USERNAME: string;
  UserDO: DurableObjectNamespace<UserDO & QueryableHandler>;
}

interface OAuthState {
  redirectTo?: string;
  codeVerifier: string;
  resource?: string;
}

export interface GitHubUser {
  id: number;
  login: string;
  name: string | null;
  avatar_url: string;
  [key: string]: any;
}

export interface User {
  id: string;
  name: string;
  username: string;
  profile_image_url?: string | undefined;
}

const isQueryReadOnly = (query: string) => {
  return query.toLowerCase().startsWith("select ");
};

// Helper function for CORS headers
function getCorsHeaders(
  allowedMethods: string[] = ["GET", "OPTIONS"]
): Record<string, string> {
  return {
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Methods": allowedMethods.join(", "),
    "Access-Control-Allow-Headers":
      "Content-Type, Authorization, MCP-Protocol-Version",
  };
}

// Helper function for OPTIONS responses
function handleOptionsRequest(
  allowedMethods: string[] = ["GET", "OPTIONS"]
): Response {
  return new Response(null, {
    status: 204,
    headers: getCorsHeaders(allowedMethods),
  });
}

@Queryable()
export class UserDO extends DurableObject {
  private storage: DurableObjectStorage;
  public sql: SqlStorage;
  public env: Env;

  constructor(state: DurableObjectState, env: Env) {
    super(state, env);
    this.storage = state.storage;
    this.sql = state.storage.sql;
    this.env = env;

    // Initialize users table
    this.sql.exec(`
      CREATE TABLE IF NOT EXISTS users (
        user_id TEXT PRIMARY KEY,
        login TEXT NOT NULL,
        name TEXT,
        avatar_url TEXT,
        github_access_token TEXT NOT NULL,
        created_at INTEGER DEFAULT (unixepoch()),
        updated_at INTEGER DEFAULT (unixepoch()),
        last_active_at INTEGER DEFAULT (unixepoch()),
        session_count INTEGER DEFAULT 1,
        additional_data TEXT DEFAULT '{}'
      )
    `);

    // Initialize logins table
    this.sql.exec(`
      CREATE TABLE IF NOT EXISTS logins (
        access_token TEXT PRIMARY KEY,
        user_id TEXT NOT NULL,
        client_id TEXT NOT NULL,
        created_at INTEGER DEFAULT (unixepoch()),
        last_active_at INTEGER DEFAULT (unixepoch()),
        session_count INTEGER DEFAULT 1,
        FOREIGN KEY (user_id) REFERENCES users (user_id)
      )
    `);
  }

  async setAuthData(
    githubAccessToken: string,
    userId: string,
    clientId: string,
    redirectUri: string,
    resource: string
  ) {
    await this.storage.put("data", {
      github_access_token: githubAccessToken,
      userId,
      clientId,
      redirectUri,
      resource,
    });
  }

  async getAuthData() {
    return this.storage.get<{
      github_access_token: string;
      userId: string;
      clientId: string;
      redirectUri: string;
      resource?: string;
    }>("data");
  }

  async getUserWithAccessToken(userId: string): Promise<{
    user: GitHubUser;
    githubAccessToken: string;
  } | null> {
    const result = this.sql
      .exec(`SELECT * FROM users WHERE user_id = ?`, userId)
      .toArray()[0];

    if (!result) {
      return null;
    }

    // Reconstruct user object
    const additionalData = JSON.parse(
      (result.additional_data as string) || "{}"
    );
    const user: GitHubUser = {
      id: parseInt(result.user_id as string),
      login: result.login as string,
      name: result.name as string | null,
      avatar_url: result.avatar_url as string,
      ...additionalData,
    };

    return {
      user,
      githubAccessToken: result.github_access_token as string,
    };
  }

  async setUser(user: GitHubUser, githubAccessToken: string) {
    const now = Math.floor(Date.now() / 1000);

    // Extract standard fields
    const { id, login, name, avatar_url, ...additionalData } = user;

    // Store user in SQLite with last_active_at set to now
    this.sql.exec(
      `INSERT OR REPLACE INTO users 
       (user_id, login, name, avatar_url, github_access_token, updated_at, last_active_at, session_count, additional_data)
       VALUES (?, ?, ?, ?, ?, ?, ?, COALESCE((SELECT session_count FROM users WHERE user_id = ?), 1), ?)`,
      id.toString(),
      login,
      name,
      avatar_url,
      githubAccessToken,
      now,
      now,
      id.toString(),
      JSON.stringify(additionalData)
    );
  }

  async createLogin(
    userId: string,
    clientId: string,
    accessToken: string
  ): Promise<void> {
    const now = Math.floor(Date.now() / 1000);

    this.sql.exec(
      `INSERT OR REPLACE INTO logins (access_token, user_id, client_id, last_active_at, session_count)
       VALUES (?, ?, ?, ?, COALESCE((SELECT session_count FROM logins WHERE access_token = ?), 1))`,
      accessToken,
      userId,
      clientId,
      now,
      accessToken
    );
  }

  async updateActivity(accessToken: string): Promise<void> {
    const now = Math.floor(Date.now() / 1000);
    const oneHourAgo = now - 3600;
    const fourHoursAgo = now - 14400;

    // Get current last_active_at for both login and user
    const loginResult = this.sql
      .exec(
        `SELECT user_id, last_active_at FROM logins WHERE access_token = ?`,
        accessToken
      )
      .toArray()[0];

    if (!loginResult) {
      return;
    }

    const userId = loginResult.user_id as string;
    const loginLastActive = loginResult.last_active_at as number;

    const userResult = this.sql
      .exec(`SELECT last_active_at FROM users WHERE user_id = ?`, userId)
      .toArray()[0];

    if (!userResult) {
      return;
    }

    const userLastActive = userResult.last_active_at as number;

    // Update login activity
    if (loginLastActive < fourHoursAgo) {
      this.sql.exec(
        `UPDATE logins SET last_active_at = ?, session_count = session_count + 1 WHERE access_token = ?`,
        now,
        accessToken
      );
    } else if (loginLastActive < oneHourAgo) {
      this.sql.exec(
        `UPDATE logins SET last_active_at = ? WHERE access_token = ?`,
        now,
        accessToken
      );
    }

    // Update user activity
    if (userLastActive < fourHoursAgo) {
      this.sql.exec(
        `UPDATE users SET last_active_at = ?, session_count = session_count + 1 WHERE user_id = ?`,
        now,
        userId
      );
    } else if (userLastActive < oneHourAgo) {
      this.sql.exec(
        `UPDATE users SET last_active_at = ? WHERE user_id = ?`,
        now,
        userId
      );
    }
  }

  async getUser(): Promise<{
    user: GitHubUser;
    githubAccessToken: string;
    accessToken?: string;
  } | null> {
    const result = this.sql.exec(`SELECT * FROM users LIMIT 1`).toArray()[0];

    if (!result) {
      return null;
    }

    const additionalData = JSON.parse(
      (result.additional_data as string) || "{}"
    );
    const user: GitHubUser = {
      id: parseInt(result.user_id as string),
      login: result.login as string,
      name: result.name as string | null,
      avatar_url: result.avatar_url as string,
      ...additionalData,
    };

    return {
      user,
      githubAccessToken: result.github_access_token as string,
    };
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
 */
export async function handleOAuth(
  request: Request,
  env: Env,
  ctx: ExecutionContext,
  scope = "user:email",
  sameSite: "Strict" | "Lax" = "Lax",
  allowedClients: string[] | undefined
): Promise<Response | null> {
  const url = new URL(request.url);
  const path = url.pathname;

  if (
    !env.GITHUB_CLIENT_ID ||
    !env.GITHUB_CLIENT_SECRET ||
    !env.ADMIN_GITHUB_USERNAME ||
    !env.SELF_CLIENT_ID ||
    !env.UserDO
  ) {
    return new Response(
      `Environment misconfigured. Ensure to have GITHUB_CLIENT_ID, GITHUB_CLIENT_SECRET, SELF_CLIENT_ID, and ADMIN_GITHUB_USERNAME secrets set, as well as the Durable Object.`,
      { status: 500 }
    );
  }

  if (path === "/admin") {
    if (request.method === "OPTIONS") {
      return handleOptionsRequest(["GET", "POST", "OPTIONS"]);
    }

    const corsHeaders = getCorsHeaders(["GET", "POST", "OPTIONS"]);
    const accessToken = getAccessToken(request);
    const resourceMetadataUrl = `${url.origin}/.well-known/oauth-protected-resource`;

    if (!accessToken) {
      return new Response(
        JSON.stringify({
          error: "unauthorized",
          error_description: "Access token required",
        }),
        {
          status: 401,
          headers: {
            ...corsHeaders,
            "Content-Type": "application/json",
            "WWW-Authenticate": `Bearer realm="main", resource_metadata="${resourceMetadataUrl}"`,
          },
        }
      );
    }

    try {
      if (!accessToken.startsWith("simple_")) {
        throw new Error("Invalid access token format");
      }

      const encryptedData = accessToken.substring(7);
      const decryptedData = await decrypt(encryptedData, env.ENCRYPTION_SECRET);
      const [userId] = decryptedData.split(";");

      const userDO = getMultiStub(
        env.UserDO,
        [
          { name: `${USER_DO_PREFIX}${userId}` },
          { name: `${USER_DO_PREFIX}aggregate:` },
        ],
        ctx
      );
      const userData = await userDO.getUser();
      if (userData?.user?.login !== env.ADMIN_GITHUB_USERNAME) {
        return new Response("Only admin can view DB", {
          status: 401,
          headers: corsHeaders,
        });
      }

      const stub = getMultiStub(
        env.UserDO,
        [{ name: `${USER_DO_PREFIX}aggregate:` }],
        ctx
      );
      return studioMiddleware(
        request,
        async (query: string, ...bindings: any[]) => {
          if (isQueryReadOnly(query)) {
            return stub.raw(query, ...bindings);
          }
          return { rowsRead: 0, rowsWritten: 0, raw: [], columnNames: [] };
        },
        { dangerouslyDisableAuth: true }
      );
    } catch (error) {
      return new Response("Invalid access token", {
        status: 401,
        headers: corsHeaders,
      });
    }
  }

  if (path === "/.well-known/oauth-authorization-server") {
    if (request.method === "OPTIONS") {
      return handleOptionsRequest();
    }

    const metadata = {
      issuer: url.origin,
      authorization_endpoint: `${url.origin}/authorize`,
      token_endpoint: `${url.origin}/token`,
      token_endpoint_auth_methods_supported: ["none"],
      registration_endpoint: `${url.origin}/register`,
      response_types_supported: ["code"],
      grant_types_supported: ["authorization_code"],
      code_challenge_methods_supported: ["S256"],
      scopes_supported: ["user:email"],
    };

    return new Response(JSON.stringify(metadata, null, 2), {
      headers: {
        ...getCorsHeaders(),
        "Content-Type": "application/json",
      },
    });
  }

  if (path === "/.well-known/oauth-protected-resource") {
    if (request.method === "OPTIONS") {
      return handleOptionsRequest();
    }

    const metadata = {
      resource: url.origin,
      authorization_servers: [url.origin],
      scopes_supported: ["user:email"],
      bearer_methods_supported: ["header"],
      resource_documentation: url.origin,
    };

    return new Response(JSON.stringify(metadata, null, 2), {
      headers: {
        ...getCorsHeaders(),
        "Content-Type": "application/json",
      },
    });
  }

  if (path === "/register") {
    if (request.method === "OPTIONS") {
      return handleOptionsRequest(["POST", "OPTIONS"]);
    }

    const corsHeaders = getCorsHeaders(["POST", "OPTIONS"]);

    if (request.method !== "POST") {
      return new Response("Method not allowed", {
        status: 405,
        headers: corsHeaders,
      });
    }

    try {
      const body = await request.json();

      if (
        !body.redirect_uris ||
        !Array.isArray(body.redirect_uris) ||
        body.redirect_uris.length === 0
      ) {
        return new Response(
          JSON.stringify({
            error: "invalid_client_metadata",
            error_description: "redirect_uris must be a non-empty array",
          }),
          {
            status: 400,
            headers: {
              ...corsHeaders,
              "Content-Type": "application/json",
            },
          }
        );
      }

      const hostnames = new Set();
      for (const uri of body.redirect_uris) {
        try {
          const url = new URL(uri);
          hostnames.add(url.hostname);
        } catch (e) {
          return new Response(
            JSON.stringify({
              error: "invalid_redirect_uri",
              error_description: `Invalid redirect URI: ${uri}`,
            }),
            {
              status: 400,
              headers: {
                ...corsHeaders,
                "Content-Type": "application/json",
              },
            }
          );
        }
      }

      if (hostnames.size < 1) {
        return new Response(
          JSON.stringify({
            error: "invalid_client_metadata",
            error_description: "Less than 1 redirect uri",
          }),
          {
            status: 400,
            headers: {
              ...corsHeaders,
              "Content-Type": "application/json",
            },
          }
        );
      }

      const clientHost = Array.from(hostnames)[0];

      const response = {
        client_id: clientHost,
        redirect_uris: body.redirect_uris,
        token_endpoint_auth_method: "none",
        grant_types: ["authorization_code"],
        response_types: ["code"],
      };

      return new Response(JSON.stringify(response, null, 2), {
        status: 201,
        headers: {
          ...corsHeaders,
          "Content-Type": "application/json",
          "Cache-Control": "no-store",
          Pragma: "no-cache",
        },
      });
    } catch (error) {
      return new Response(
        JSON.stringify({
          error: "invalid_client_metadata",
          error_description: "Invalid JSON in request body",
        }),
        {
          status: 400,
          headers: {
            ...corsHeaders,
            "Content-Type": "application/json",
          },
        }
      );
    }
  }

  if (path === "/token") {
    return handleToken(request, env, ctx, scope);
  }

  if (path === "/authorize") {
    return handleAuthorize(request, env, scope, sameSite, allowedClients);
  }

  if (path === "/callback") {
    return handleCallback(request, env, ctx, sameSite);
  }

  if (path === "/me") {
    return handleMe(request, env, ctx);
  }

  if (path === "/logout") {
    if (request.method === "OPTIONS") {
      return handleOptionsRequest();
    }

    const url = new URL(request.url);
    const redirectTo = url.searchParams.get("redirect_to") || "/";
    const secureFlag = isLocalhost(request) ? "" : " Secure;";

    return new Response(null, {
      status: 302,
      headers: {
        ...getCorsHeaders(),
        Location: redirectTo,
        "Set-Cookie": `access_token=; HttpOnly;${secureFlag} SameSite=${sameSite}; Max-Age=0; Path=/`,
      },
    });
  }

  return null;
}

async function handleMe(
  request: Request,
  env: Env,
  ctx: ExecutionContext
): Promise<Response> {
  const url = new URL(request.url);

  if (request.method === "OPTIONS") {
    return handleOptionsRequest();
  }

  const corsHeaders = getCorsHeaders();

  if (request.method !== "GET") {
    return new Response(JSON.stringify({ error: "method_not_allowed" }), {
      status: 405,
      headers: {
        ...corsHeaders,
        "Content-Type": "application/json",
      },
    });
  }

  const resourceMetadataUrl = `${url.origin}/.well-known/oauth-protected-resource`;
  const loginUrl = `${url.origin}/authorize?redirect_to=${encodeURIComponent(
    request.url
  )}`;

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
          ...corsHeaders,
          "Content-Type": "application/json",
          "WWW-Authenticate": `Bearer realm="main", login_url="${loginUrl}", resource_metadata="${resourceMetadataUrl}"`,
        },
      }
    );
  }

  try {
    if (!accessToken.startsWith("simple_")) {
      throw new Error("Invalid access token format");
    }

    const encryptedData = accessToken.substring(7);
    const decryptedData = await decrypt(encryptedData, env.ENCRYPTION_SECRET);
    const [userId] = decryptedData.split(";");

    const userDO = getMultiStub(
      env.UserDO,
      [
        { name: `${USER_DO_PREFIX}${userId}` },
        { name: `${USER_DO_PREFIX}aggregate:` },
      ],
      ctx
    );

    await userDO.updateActivity(accessToken);

    const userData = await userDO.getUserWithAccessToken(userId);

    if (!userData) {
      return new Response(
        JSON.stringify({
          error: "invalid_token",
          error_description: "Token not found or expired",
        }),
        {
          status: 401,
          headers: {
            ...corsHeaders,
            "Content-Type": "application/json",
            "WWW-Authenticate": `Bearer realm="main", error="invalid_token", login_url="${loginUrl}", resource_metadata="${resourceMetadataUrl}"`,
          },
        }
      );
    }

    const user: User = {
      id: userData.user.id.toString(),
      name: userData.user.name || userData.user.login,
      username: userData.user.login,
      profile_image_url: userData.user.avatar_url || undefined,
    };

    return new Response(JSON.stringify(user), {
      headers: {
        ...corsHeaders,
        "Content-Type": "application/json",
      },
    });
  } catch (error) {
    console.error("Error retrieving user data:", error);
    return new Response(
      JSON.stringify({
        error: "server_error",
        error_description: "Internal server error",
      }),
      {
        status: 500,
        headers: {
          ...corsHeaders,
          "Content-Type": "application/json",
        },
      }
    );
  }
}

async function handleAuthorize(
  request: Request,
  env: Env,
  scope: string,
  sameSite: string,
  allowedClients: string[] | undefined
): Promise<Response> {
  if (request.method === "OPTIONS") {
    return handleOptionsRequest();
  }

  const url = new URL(request.url);
  const clientId = url.searchParams.get("client_id");
  let redirectUri = url.searchParams.get("redirect_uri");
  const responseType = url.searchParams.get("response_type") || "code";
  const state = url.searchParams.get("state");
  const resource = url.searchParams.get("resource");
  const secureFlag = isLocalhost(request) ? "" : " Secure;";

  // Direct login request
  if (!clientId) {
    const redirectTo = url.searchParams.get("redirect_to") || "/";
    const resource = url.searchParams.get("resource");
    const requestedScope = url.searchParams.get("scope") || scope;

    const codeVerifier = generateCodeVerifier();
    const codeChallenge = await generateCodeChallenge(codeVerifier);

    const state: OAuthState = { codeVerifier, resource };
    const stateString = btoa(JSON.stringify(state));

    const githubUrl = new URL("https://github.com/login/oauth/authorize");
    githubUrl.searchParams.set("client_id", env.GITHUB_CLIENT_ID);
    githubUrl.searchParams.set("redirect_uri", `${url.origin}/callback`);
    githubUrl.searchParams.set("scope", requestedScope);
    githubUrl.searchParams.set("state", stateString);
    githubUrl.searchParams.set("code_challenge", codeChallenge);
    githubUrl.searchParams.set("code_challenge_method", "S256");

    const headers = new Headers({
      ...getCorsHeaders(),
      Location: githubUrl.toString(),
    });

    headers.append(
      "Set-Cookie",
      `oauth_state=${encodeURIComponent(
        stateString
      )}; HttpOnly;${secureFlag} SameSite=${sameSite}; Max-Age=600; Path=/`
    );
    headers.append(
      "Set-Cookie",
      `redirect_to=${encodeURIComponent(
        redirectTo
      )}; HttpOnly;${secureFlag} SameSite=${sameSite}; Max-Age=600; Path=/`
    );

    return new Response(null, { status: 302, headers });
  }

  if (!isValidDomain(clientId) && clientId !== "localhost") {
    return new Response("Invalid client_id: must be a valid domain", {
      status: 400,
      headers: getCorsHeaders(),
    });
  }

  if (allowedClients !== undefined && !allowedClients.includes(clientId)) {
    return new Response(
      `This provider restricts client_ids that can be used, and ${clientId} is not one of them. Allowed client_ids: ${allowedClients.join(
        ", "
      )}`,
      {
        status: 400,
        headers: getCorsHeaders(),
      }
    );
  }

  if (!redirectUri) {
    redirectUri = `https://${clientId}/callback`;
  }

  try {
    const redirectUrl = new URL(redirectUri);

    if (
      redirectUrl.protocol === "http:" &&
      redirectUrl.hostname !== "localhost" &&
      redirectUrl.hostname !== "127.0.0.1"
    ) {
      return new Response(
        "Invalid redirect_uri: must use HTTPS unless localhost/127.0.0.1",
        {
          status: 400,
          headers: getCorsHeaders(),
        }
      );
    }
  } catch {
    return new Response("Invalid redirect_uri format", {
      status: 400,
      headers: getCorsHeaders(),
    });
  }

  if (responseType !== "code") {
    return new Response("Unsupported response_type", {
      status: 400,
      headers: getCorsHeaders(),
    });
  }

  // Check if user is already authenticated
  const accessToken = getAccessToken(request);
  if (accessToken) {
    try {
      if (!accessToken.startsWith("simple_")) {
        throw new Error("Invalid access token format");
      }

      const encryptedData = accessToken.substring(7);
      const decryptedData = await decrypt(encryptedData, env.ENCRYPTION_SECRET);
      const [userId] = decryptedData.split(";");

      return await createAuthCodeAndRedirect(
        env,
        clientId,
        redirectUri,
        state,
        userId,
        resource
      );
    } catch (error) {
      // Invalid token, continue to GitHub OAuth
    }
  }

  // User not authenticated, redirect to GitHub OAuth
  const providerState = {
    clientId,
    redirectUri,
    state,
    originalState: state,
    resource,
  };

  const providerStateString = btoa(JSON.stringify(providerState));

  const codeVerifier = generateCodeVerifier();
  const codeChallenge = await generateCodeChallenge(codeVerifier);

  const githubState: OAuthState = {
    codeVerifier,
    resource,
  };

  const githubStateString = btoa(JSON.stringify(githubState));

  const githubUrl = new URL("https://github.com/login/oauth/authorize");
  githubUrl.searchParams.set("client_id", env.GITHUB_CLIENT_ID);
  githubUrl.searchParams.set("redirect_uri", `${url.origin}/callback`);
  githubUrl.searchParams.set("scope", scope);
  githubUrl.searchParams.set("state", githubStateString);
  githubUrl.searchParams.set("code_challenge", codeChallenge);
  githubUrl.searchParams.set("code_challenge_method", "S256");

  const headers = new Headers({
    ...getCorsHeaders(),
    Location: githubUrl.toString(),
  });

  headers.append(
    "Set-Cookie",
    `oauth_state=${encodeURIComponent(
      githubStateString
    )}; HttpOnly;${secureFlag} SameSite=${sameSite}; Max-Age=600; Path=/`
  );
  headers.append(
    "Set-Cookie",
    `provider_state=${encodeURIComponent(
      providerStateString
    )}; HttpOnly;${secureFlag} SameSite=${sameSite}; Max-Age=600; Path=/`
  );

  const redirectTo = url.pathname + url.search;
  headers.append(
    "Set-Cookie",
    `redirect_to=${encodeURIComponent(
      redirectTo
    )}; HttpOnly;${secureFlag} SameSite=${sameSite}; Max-Age=600; Path=/`
  );

  return new Response(null, { status: 302, headers });
}

async function createAuthCodeAndRedirect(
  env: Env,
  clientId: string,
  redirectUri: string,
  state: string | null,
  userId: string,
  resource: string
): Promise<Response> {
  const authCode = generateCodeVerifier();

  const userDO = env.UserDO.get(
    env.UserDO.idFromName(`${USER_DO_PREFIX}${userId}`)
  );
  const userData = await userDO.getUserWithAccessToken(userId);

  if (!userData) {
    throw new Error("User not found");
  }

  const id = env.UserDO.idFromName(`code:${authCode}`);
  const authCodeDO = env.UserDO.get(id);

  await authCodeDO.setAuthData(
    userData.githubAccessToken,
    userId,
    clientId,
    redirectUri,
    resource
  );

  const redirectUrl = new URL(redirectUri);
  redirectUrl.searchParams.set("code", authCode);
  if (state) {
    redirectUrl.searchParams.set("state", state);
  }

  return new Response(null, {
    status: 302,
    headers: {
      ...getCorsHeaders(),
      Location: redirectUrl.toString(),
    },
  });
}

async function handleToken(
  request: Request,
  env: Env,
  ctx: ExecutionContext,
  scope: string
): Promise<Response> {
  if (request.method === "OPTIONS") {
    return handleOptionsRequest(["POST", "OPTIONS"]);
  }

  const corsHeaders = getCorsHeaders(["POST", "OPTIONS"]);

  if (request.method !== "POST") {
    return new Response("Method not allowed", {
      status: 405,
      headers: corsHeaders,
    });
  }

  const formData = await request.formData();
  const grantType = formData.get("grant_type");
  const code = formData.get("code");
  const clientId = formData.get("client_id");
  const redirectUri = formData.get("redirect_uri");
  const resource = formData.get("resource");

  if (grantType !== "authorization_code") {
    return new Response(JSON.stringify({ error: "unsupported_grant_type" }), {
      status: 400,
      headers: {
        ...corsHeaders,
        "Content-Type": "application/json",
      },
    });
  }

  if (!code || !clientId) {
    return new Response(JSON.stringify({ error: "invalid_request" }), {
      status: 400,
      headers: {
        ...corsHeaders,
        "Content-Type": "application/json",
      },
    });
  }

  if (
    !isValidDomain(clientId.toString()) &&
    clientId.toString() !== "localhost"
  ) {
    return new Response(JSON.stringify({ error: "invalid_client" }), {
      status: 400,
      headers: {
        ...corsHeaders,
        "Content-Type": "application/json",
      },
    });
  }

  const id = env.UserDO.idFromName(`code:${code.toString()}`);
  const authCodeDO = env.UserDO.get(id);
  const authData = await authCodeDO.getAuthData();

  if (!authData) {
    return new Response(
      JSON.stringify({
        error: "invalid_grant",
        message: "Auth data not found",
      }),
      {
        status: 400,
        headers: {
          ...corsHeaders,
          "Content-Type": "application/json",
        },
      }
    );
  }

  if (
    authData.clientId !== clientId ||
    (redirectUri && authData.redirectUri !== redirectUri)
  ) {
    return new Response(
      JSON.stringify({
        error: "invalid_grant",
        message: "Invalid client_id or redirect_uri",
      }),
      {
        status: 400,
        headers: {
          ...corsHeaders,
          "Content-Type": "application/json",
        },
      }
    );
  }

  if (!resource || authData.resource !== resource) {
    return new Response(
      JSON.stringify({
        error: "invalid_grant",
        message: `Invalid resource`,
      }),
      {
        status: 400,
        headers: {
          ...corsHeaders,
          "Content-Type": "application/json",
        },
      }
    );
  }

  const userDO = env.UserDO.get(
    env.UserDO.idFromName(`${USER_DO_PREFIX}${authData.userId}`)
  );
  const userData = await userDO.getUserWithAccessToken(authData.userId);

  if (!userData) {
    return new Response(
      JSON.stringify({
        error: "invalid_grant",
        message: "User not found",
      }),
      {
        status: 400,
        headers: {
          ...corsHeaders,
          "Content-Type": "application/json",
        },
      }
    );
  }

  // Create encrypted access token in worker (deterministic)
  const tokenData = `${authData.userId};${authData.resource};${userData.githubAccessToken}`;
  const encryptedData = await encrypt(tokenData, env.ENCRYPTION_SECRET);
  const accessToken = `simple_${encryptedData}`;

  // Store login in aggregate DO
  const multistub = getMultiStub(
    env.UserDO,
    [
      { name: `${USER_DO_PREFIX}${authData.userId}` },
      { name: `${USER_DO_PREFIX}aggregate:` },
    ],
    ctx
  );

  await multistub.createLogin(
    authData.userId,
    clientId.toString(),
    accessToken
  );

  return new Response(
    JSON.stringify({
      access_token: accessToken,
      token_type: "bearer",
      scope,
    }),
    {
      headers: {
        ...corsHeaders,
        "Content-Type": "application/json",
      },
    }
  );
}

async function handleCallback(
  request: Request,
  env: Env,
  ctx: ExecutionContext,
  sameSite: string
): Promise<Response> {
  if (request.method === "OPTIONS") {
    return handleOptionsRequest();
  }

  const url = new URL(request.url);
  const code = url.searchParams.get("code");
  const stateParam = url.searchParams.get("state");
  const secureFlag = isLocalhost(request) ? "" : " Secure;";

  if (!code || !stateParam) {
    return new Response("Missing code or state parameter", {
      status: 400,
      headers: getCorsHeaders(),
    });
  }

  const cookies = parseCookies(request.headers.get("Cookie") || "");
  const stateCookie = cookies.oauth_state;
  const providerStateCookie = cookies.provider_state;
  const redirectToCookie = cookies.redirect_to;

  if (!stateCookie) {
    return new Response("Missing state cookie", {
      status: 400,
      headers: getCorsHeaders(),
    });
  }

  let state: OAuthState;
  try {
    state = JSON.parse(atob(stateCookie));
  } catch {
    return new Response("Invalid state format", {
      status: 400,
      headers: getCorsHeaders(),
    });
  }

  if (stateCookie !== stateParam) {
    return new Response("Invalid state parameter", {
      status: 400,
      headers: getCorsHeaders(),
    });
  }

  // Exchange code for token with GitHub
  const tokenResponse = await fetch(
    "https://github.com/login/oauth/access_token",
    {
      method: "POST",
      headers: {
        Accept: "application/json",
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        client_id: env.GITHUB_CLIENT_ID,
        client_secret: env.GITHUB_CLIENT_SECRET,
        code,
        redirect_uri: `${url.origin}/callback`,
        code_verifier: state.codeVerifier,
      }),
    }
  );

  const tokenData = (await tokenResponse.json()) as any;

  if (!tokenData.access_token) {
    return new Response("Failed to get access token", {
      status: 400,
      headers: getCorsHeaders(),
    });
  }

  // Get user info from GitHub
  const userResponse = await fetch("https://api.github.com/user", {
    headers: {
      Authorization: `Bearer ${tokenData.access_token}`,
      "User-Agent": "SimplerAuth",
    },
  });

  if (!userResponse.ok) {
    return new Response("Failed to get user info", {
      status: 400,
      headers: getCorsHeaders(),
    });
  }

  const user = (await userResponse.json()) as GitHubUser;

  const userDO = getMultiStub(
    env.UserDO,
    [
      { name: `${USER_DO_PREFIX}${user.id}` },
      { name: `${USER_DO_PREFIX}aggregate:` },
    ],
    ctx
  );
  await userDO.setUser(user, tokenData.access_token);

  // Check if this was part of an OAuth provider flow
  if (providerStateCookie) {
    try {
      const providerState = JSON.parse(atob(providerStateCookie));

      const response = await createAuthCodeAndRedirect(
        env,
        providerState.clientId,
        providerState.redirectUri,
        providerState.state,
        user.id.toString(),
        providerState.resource
      );

      // Create access token for this client (deterministic)
      const newTokenData = `${user.id};${providerState.resource};${tokenData.access_token}`;
      const encryptedData = await encrypt(newTokenData, env.ENCRYPTION_SECRET);
      const accessToken = `simple_${encryptedData}`;

      await userDO.createLogin(
        user.id.toString(),
        providerState.clientId,
        accessToken
      );

      const headers = new Headers(response.headers);
      headers.append(
        "Set-Cookie",
        `oauth_state=; HttpOnly;${secureFlag} SameSite=${sameSite}; Max-Age=0; Path=/`
      );
      headers.append(
        "Set-Cookie",
        `provider_state=; HttpOnly;${secureFlag} SameSite=${sameSite}; Max-Age=0; Path=/`
      );
      headers.append(
        "Set-Cookie",
        `redirect_to=; HttpOnly;${secureFlag} SameSite=${sameSite}; Max-Age=0; Path=/`
      );
      headers.append(
        "Set-Cookie",
        `access_token=${accessToken}; HttpOnly;${secureFlag} Max-Age=34560000; SameSite=${sameSite}; Path=/`
      );

      return new Response(response.body, { status: response.status, headers });
    } catch {
      // Fall through to normal redirect
    }
  }

  // Normal redirect (direct login) - create access token for browser client (deterministic)
  const browserTokenData = `${user.id};https://${env.SELF_CLIENT_ID};${tokenData.access_token}`;
  const browserEncryptedData = await encrypt(
    browserTokenData,
    env.ENCRYPTION_SECRET
  );
  const browserAccessToken = `simple_${browserEncryptedData}`;

  await userDO.createLogin(
    user.id.toString(),
    env.SELF_CLIENT_ID,
    browserAccessToken
  );

  const redirectTo = redirectToCookie
    ? decodeURIComponent(redirectToCookie)
    : "/";

  const headers = new Headers({
    ...getCorsHeaders(),
    Location: redirectTo,
  });

  headers.append(
    "Set-Cookie",
    `oauth_state=; HttpOnly;${secureFlag} SameSite=${sameSite}; Max-Age=0; Path=/`
  );
  headers.append(
    "Set-Cookie",
    `redirect_to=; HttpOnly;${secureFlag} SameSite=${sameSite}; Max-Age=0; Path=/`
  );
  headers.append(
    "Set-Cookie",
    `access_token=${browserAccessToken}; HttpOnly;${secureFlag} Max-Age=34560000; SameSite=${sameSite}; Path=/`
  );

  return new Response(null, { status: 302, headers });
}

export function getAccessToken(request: Request): string | null {
  const authHeader = request.headers.get("Authorization");
  if (authHeader?.startsWith("Bearer ")) {
    return authHeader.substring(7);
  }

  const cookies = parseCookies(request.headers.get("Cookie") || "");
  return cookies.access_token || null;
}

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
    String.fromCharCode.apply(null, Array.from(new Uint8Array(digest)))
  )
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=/g, "");
}

async function encrypt(text: string, secret: string): Promise<string> {
  const encoder = new TextEncoder();
  const data = encoder.encode(text);

  const salt = crypto.getRandomValues(new Uint8Array(16));
  const iv = crypto.getRandomValues(new Uint8Array(12));

  const keyMaterial = await crypto.subtle.importKey(
    "raw",
    encoder.encode(secret),
    { name: "PBKDF2" },
    false,
    ["deriveKey"]
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
    ["encrypt"]
  );

  const encrypted = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv: iv },
    key,
    data
  );

  const combined = new Uint8Array(
    salt.length + iv.length + encrypted.byteLength
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

  const combined = new Uint8Array(
    atob(encrypted.replace(/-/g, "+").replace(/_/g, "/"))
      .split("")
      .map((c) => c.charCodeAt(0))
  );

  const salt = combined.slice(0, 16);
  const iv = combined.slice(16, 28);
  const data = combined.slice(28);

  const keyMaterial = await crypto.subtle.importKey(
    "raw",
    encoder.encode(secret),
    { name: "PBKDF2" },
    false,
    ["deriveKey"]
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
    ["decrypt"]
  );

  const decrypted = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: iv },
    key,
    data
  );

  return decoder.decode(decrypted);
}

function isLocalhost(request: Request) {
  const url = new URL(request.url);
  return (
    url.hostname === "localhost" ||
    url.hostname === "127.0.0.1" ||
    request.headers.get("cf-connecting-ip") === "::1" ||
    request.headers.get("cf-connecting-ip") === "127.0.0.1"
  );
}

export interface UserContext<T = { [key: string]: any }>
  extends ExecutionContext {
  user: GitHubUser | undefined;
  githubAccessToken: string | undefined;
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

export function withSimplerAuth<TEnv = {}, TMetadata = { [key: string]: any }>(
  handler: UserFetchHandler<TEnv, TMetadata>,
  config?: {
    isLoginRequired?: boolean;
    scope?: string;
    sameSite?: "Strict" | "Lax";
    allowedClients?: string[];
  }
): ExportedHandlerFetchHandler<Env & TEnv> {
  const { scope, sameSite, allowedClients } = config || {};

  return async (
    request: Request,
    env: TEnv & Env,
    ctx: ExecutionContext
  ): Promise<Response> => {
    const oauth = await handleOAuth(
      request,
      env,
      ctx,
      scope,
      sameSite,
      allowedClients
    );
    if (oauth) {
      return oauth;
    }

    let userDO: DurableObjectStub<UserDO>;

    let user: GitHubUser | undefined = undefined;
    let registered = false;
    let githubAccessToken: string | undefined = undefined;
    const accessToken = getAccessToken(request);
    if (accessToken) {
      try {
        if (!accessToken.startsWith("simple_")) {
          throw new Error("Invalid access token format");
        }

        const encryptedData = accessToken.substring(7);
        const decryptedData = await decrypt(
          encryptedData,
          env.ENCRYPTION_SECRET
        );
        const [userId] = decryptedData.split(";");

        userDO = getMultiStub(
          env.UserDO,
          [
            { name: `${USER_DO_PREFIX}${userId}` },
            { name: `${USER_DO_PREFIX}aggregate:` },
          ],
          ctx
        );

        const url = new URL(request.url);
        if (url.pathname !== "/me") {
          await userDO.updateActivity(accessToken);
        }

        const userData = await userDO.getUserWithAccessToken(userId);

        if (userData) {
          user = userData.user as unknown as GitHubUser;
          registered = true;
          githubAccessToken = userData.githubAccessToken;
        }
      } catch (error) {
        console.error("Error getting user data:", error);
      }
    }

    if (!user && config?.isLoginRequired) {
      const isBrowser = request.headers.get("accept")?.includes("text/html");
      const url = new URL(request.url);
      const resourceMetadataUrl = `${url.origin}/.well-known/oauth-protected-resource`;

      const loginUrl = `${
        url.origin
      }/authorize?redirect_to=${encodeURIComponent(request.url)}`;

      return new Response(
        `"access_token" Cookie or "Authorization" header required. User must login at ${loginUrl}.`,
        {
          status: isBrowser ? 302 : 401,
          headers: {
            ...getCorsHeaders(),
            Location: loginUrl,
            "X-Login-URL": loginUrl,
            "WWW-Authenticate": `Bearer realm="main", login_url="${loginUrl}", resource_metadata="${resourceMetadataUrl}"`,
          },
        }
      );
    }

    const enhancedCtx: UserContext<TMetadata> = {
      passThroughOnException: () => ctx.passThroughOnException(),
      props: ctx.props,
      waitUntil: (promise: Promise<any>) => ctx.waitUntil(promise),
      user,
      registered,
      githubAccessToken,
      accessToken,
      setMetadata: userDO ? userDO.setMetadata : undefined,
      getMetadata: userDO
        ? () => userDO.getMetadata() as Promise<TMetadata>
        : undefined,
    };

    const response = await handler(request, env, enhancedCtx);

    const newHeaders = new Headers(response.headers);

    const corsHeaders = getCorsHeaders();
    Object.entries(corsHeaders).forEach(([key, value]) => {
      newHeaders.set(key, value);
    });

    return new Response(response.body, {
      status: response.status,
      statusText: response.statusText,
      headers: newHeaders,
    });
  };
}
