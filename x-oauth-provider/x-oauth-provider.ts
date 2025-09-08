/// <reference types="@cloudflare/workers-types" />
/// <reference lib="esnext" />
import { DurableObject } from "cloudflare:workers";
import { getMultiStub } from "multistub";
import {
  Queryable,
  QueryableHandler,
  studioMiddleware,
} from "queryable-object";

const USER_DO_PREFIX = "user-v5:";

export interface Env {
  SELF_CLIENT_ID: string;
  X_CLIENT_ID: string;
  X_CLIENT_SECRET: string;
  ENCRYPTION_SECRET: string;
  ADMIN_X_USERNAME: string;
  UserDO: DurableObjectNamespace<UserDO & QueryableHandler>;
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

const isQueryReadOnly = (query: string) => {
  // TODO: refine this
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
        name TEXT NOT NULL,
        username TEXT NOT NULL,
        profile_image_url TEXT,
        verified BOOLEAN DEFAULT FALSE,
        x_access_token TEXT NOT NULL,
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

    // Add columns to existing tables if they don't exist
    try {
      this.sql.exec(
        `ALTER TABLE users ADD COLUMN last_active_at INTEGER DEFAULT (unixepoch())`
      );
    } catch (e) {
      // Column already exists
    }
    try {
      this.sql.exec(
        `ALTER TABLE users ADD COLUMN session_count INTEGER DEFAULT 1`
      );
    } catch (e) {
      // Column already exists
    }
    try {
      this.sql.exec(
        `ALTER TABLE logins ADD COLUMN last_active_at INTEGER DEFAULT (unixepoch())`
      );
    } catch (e) {
      // Column already exists
    }
    try {
      this.sql.exec(
        `ALTER TABLE logins ADD COLUMN session_count INTEGER DEFAULT 1`
      );
    } catch (e) {
      // Column already exists
    }

    // Set alarm for 10 minutes from now
    this.storage.setAlarm(Date.now() + 10 * 60 * 1000);
  }

  async alarm() {
    // Only self-delete if this is not a user storage (auth codes expire, users don't)
    const hasUser = this.sql
      .exec(`SELECT COUNT(*) as count FROM users`)
      .toArray()[0];
    if (!hasUser || hasUser.count === 0) {
      await this.storage.deleteAll();
    }
  }

  async setAuthData(
    xAccessToken: string,
    userId: string,
    clientId: string,
    redirectUri: string,
    resource: string
  ) {
    // Keep auth data storage unchanged (using KV storage)
    await this.storage.put("data", {
      x_access_token: xAccessToken,
      userId,
      clientId,
      redirectUri,
      resource,
    });
  }

  async getAuthData() {
    // Keep auth data storage unchanged (using KV storage)
    return this.storage.get<{
      x_access_token: string;
      userId: string;
      clientId: string;
      redirectUri: string;
      resource?: string;
    }>("data");
  }

  // Add this new function to the UserDO class
  async getUserWithAccessToken(userId: string): Promise<{
    user: XUser;
    xAccessToken: string;
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
    const user: XUser = {
      id: result.user_id as string,
      name: result.name as string,
      username: result.username as string,
      ...(result.profile_image_url && {
        profile_image_url: result.profile_image_url as string,
      }),
      ...(result.verified && { verified: result.verified as boolean }),
      ...additionalData,
    };

    return {
      user,
      xAccessToken: result.x_access_token as string,
    };
  }

  async setUser(user: XUser, xAccessToken: string) {
    const now = Math.floor(Date.now() / 1000);

    // Extract standard fields
    const {
      id,
      name,
      username,
      profile_image_url,
      verified,
      ...additionalData
    } = user;

    // Store user in SQLite with last_active_at set to now
    this.sql.exec(
      `INSERT OR REPLACE INTO users 
       (user_id, name, username, profile_image_url, verified, x_access_token, updated_at, last_active_at, session_count, additional_data)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, COALESCE((SELECT session_count FROM users WHERE user_id = ?), 1), ?)`,
      id,
      name,
      username,
      profile_image_url || null,
      verified || false,
      xAccessToken,
      now,
      now,
      id, // for COALESCE subquery
      JSON.stringify(additionalData)
    );
  }

  // Alter the createLogin function to take the encrypted access token
  async createLogin(
    userId: string,
    clientId: string,
    accessToken: string // Now takes the pre-encrypted access token
  ): Promise<void> {
    // Validate that clientId matches resource hostname
    //const resourceUrl = new URL(resource);
    // if (resourceUrl.hostname !== clientId) {
    //   throw new Error("Client ID must match resource hostname");
    // }

    const now = Math.floor(Date.now() / 1000);

    // Store login with the provided access token
    this.sql.exec(
      `INSERT OR REPLACE INTO logins (access_token, user_id, client_id, last_active_at, session_count)
     VALUES (?, ?, ?, ?, COALESCE((SELECT session_count FROM logins WHERE access_token = ?), 1))`,
      accessToken,
      userId,
      clientId,
      now,
      accessToken // for COALESCE subquery
    );
  }

  async updateActivity(accessToken: string): Promise<void> {
    const now = Math.floor(Date.now() / 1000);
    const oneHourAgo = now - 3600; // 1 hour in seconds
    const fourHoursAgo = now - 14400; // 4 hours in seconds

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
      // More than 4 hours old - increment session_count and update last_active_at
      this.sql.exec(
        `UPDATE logins SET last_active_at = ?, session_count = session_count + 1 WHERE access_token = ?`,
        now,
        accessToken
      );
    } else if (loginLastActive < oneHourAgo) {
      // Between 1-4 hours old - only update last_active_at
      this.sql.exec(
        `UPDATE logins SET last_active_at = ? WHERE access_token = ?`,
        now,
        accessToken
      );
    }
    // Less than 1 hour old - no update needed

    // Update user activity
    if (userLastActive < fourHoursAgo) {
      // More than 4 hours old - increment session_count and update last_active_at
      this.sql.exec(
        `UPDATE users SET last_active_at = ?, session_count = session_count + 1 WHERE user_id = ?`,
        now,
        userId
      );
    } else if (userLastActive < oneHourAgo) {
      // Between 1-4 hours old - only update last_active_at
      this.sql.exec(
        `UPDATE users SET last_active_at = ? WHERE user_id = ?`,
        now,
        userId
      );
    }
    // Less than 1 hour old - no update needed
  }

  async getUser(): Promise<{
    user: XUser;
    xAccessToken: string;
    accessToken?: string;
  } | null> {
    const result = this.sql.exec(`SELECT * FROM users LIMIT 1`).toArray()[0];

    if (!result) {
      return null;
    }

    // Reconstruct user object
    const additionalData = JSON.parse(
      (result.additional_data as string) || "{}"
    );
    const user: XUser = {
      id: result.user_id as string,
      name: result.name as string,
      username: result.username as string,
      ...(result.profile_image_url && {
        profile_image_url: result.profile_image_url as string,
      }),
      ...(result.verified && { verified: result.verified as boolean }),
      ...additionalData,
    };

    return {
      user,
      xAccessToken: result.x_access_token as string,
    };
  }

  async getUserByAccessToken(accessToken: string): Promise<{
    user: XUser;
    xAccessToken: string;
    clientId: string;
  } | null> {
    try {
      // Decrypt the access token to get user_id, client_id, and x_access_token
      if (!accessToken.startsWith("simple_")) {
        return null;
      }

      const encryptedData = accessToken.substring(7); // Remove 'simple_' prefix
      const decryptedData = await decrypt(
        encryptedData,
        this.env.ENCRYPTION_SECRET
      );
      const [userId, resource, xAccessToken] = decryptedData.split(";");
      // Derive client_id from resource
      const clientId = new URL(resource).hostname;
      // Verify login exists
      const loginResult = this.sql
        .exec(
          `SELECT * FROM logins WHERE access_token = ? AND user_id = ? AND client_id = ?`,
          accessToken,
          userId,
          clientId
        )
        .toArray()[0];

      if (!loginResult) {
        console.log("no login result", { clientId, accessToken, userId });

        return null;
      }

      // Get user data
      const userResult = this.sql
        .exec(`SELECT * FROM users WHERE user_id = ?`, userId)
        .toArray()[0];

      if (!userResult) {
        console.log("no user result");
        return null;
      }

      // Reconstruct user object
      const additionalData = JSON.parse(
        (userResult.additional_data as string) || "{}"
      );
      const user: XUser = {
        id: userResult.user_id as string,
        name: userResult.name as string,
        username: userResult.username as string,
        ...(userResult.profile_image_url && {
          profile_image_url: userResult.profile_image_url as string,
        }),
        ...(userResult.verified && {
          verified: userResult.verified as boolean,
        }),
        ...additionalData,
      };

      return {
        user,
        xAccessToken,
        clientId,
      };
    } catch (error) {
      console.error("Error decrypting access token:", error);
      return null;
    }
  }

  async setMetadata<T>(metadata: T) {
    // Keep metadata storage unchanged (using KV storage)
    await this.storage.put("metadata", metadata);
  }

  async getMetadata<T>(): Promise<T | null> {
    // Keep metadata storage unchanged (using KV storage)
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
  ctx: ExecutionContext,
  scope = "users.read tweet.read offline.access",
  sameSite: "Strict" | "Lax" = "Lax",
  allowedClients: string[] | undefined
): Promise<Response | null> {
  const url = new URL(request.url);
  const path = url.pathname;

  if (
    !env.X_CLIENT_ID ||
    !env.X_CLIENT_SECRET ||
    !env.ADMIN_X_USERNAME ||
    !env.SELF_CLIENT_ID ||
    !env.UserDO
  ) {
    return new Response(
      `Environment misconfigured. Ensure to have X_CLIENT_ID, X_CLIENT_SECRET, SELF_CLIENT_ID, and ADMIN_X_USERNAME secrets set, as well as the Durable Object, with:

[[durable_objects.bindings]]
name = "UserDO"
class_name = "UserDO"

[[migrations]]
new_sqlite_classes = ["UserDO"]
tag = "v1"

      `,
      { status: 500 }
    );
  }

  if (path === "/admin") {
    // Handle OPTIONS request
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
            "WWW-Authenticate": `Bearer realm="main", resource_metadata="${resourceMetadataUrl}`,
          },
        }
      );
    }

    // Decrypt access token to get user_id
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
      if (userData?.user?.username !== env.ADMIN_X_USERNAME) {
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

  // MCP Required: OAuth 2.0 Authorization Server Metadata (RFC8414)
  if (path === "/.well-known/oauth-authorization-server") {
    // Handle OPTIONS request
    if (request.method === "OPTIONS") {
      return handleOptionsRequest();
    }

    const metadata = {
      issuer: url.origin,
      authorization_endpoint: `${url.origin}/authorize`,
      token_endpoint: `${url.origin}/token`,
      // Public client without secret
      token_endpoint_auth_methods_supported: ["none"],
      registration_endpoint: `${url.origin}/register`,
      response_types_supported: ["code"],
      grant_types_supported: ["authorization_code"],
      code_challenge_methods_supported: ["S256"],
      scopes_supported: ["users.read", "tweet.read", "offline.access"],
    };

    return new Response(JSON.stringify(metadata, null, 2), {
      headers: {
        ...getCorsHeaders(),
        "Content-Type": "application/json",
        "Cache-Control": "public, max-age=3600",
      },
    });
  }

  // Protected resource metadata endpoint
  if (path === "/.well-known/oauth-protected-resource") {
    // Handle OPTIONS request
    if (request.method === "OPTIONS") {
      return handleOptionsRequest();
    }

    const metadata = {
      resource: url.origin,
      authorization_servers: [url.origin],
      scopes_supported: ["users.read", "tweet.read", "offline.access"],
      bearer_methods_supported: ["header"],
      resource_documentation: url.origin,
    };

    return new Response(JSON.stringify(metadata, null, 2), {
      headers: {
        ...getCorsHeaders(),
        "Content-Type": "application/json",
        "Cache-Control": "public, max-age=3600",
      },
    });
  }

  if (path === "/register") {
    // Handle OPTIONS request
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

      // Validate redirect_uris is present and is an array
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

      // Extract hosts from all redirect URIs
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

      // Ensure all redirect URIs have the same host
      if (hostnames.size !== 1) {
        return new Response(
          JSON.stringify({
            error: "invalid_client_metadata",
            error_description: "All redirect URIs must have the same host",
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

      // Response with client_id as the host
      const response = {
        client_id: clientHost,
        redirect_uris: body.redirect_uris,
        token_endpoint_auth_method: "none", // Public client, no secret needed
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
    // Handle OPTIONS request
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

  return null; // Not an OAuth route, let other handlers take over
}

// Handle /me endpoint to return current user information
async function handleMe(
  request: Request,
  env: Env,
  ctx: ExecutionContext
): Promise<Response> {
  const url = new URL(request.url);

  // Handle preflight OPTIONS request
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
          ...corsHeaders,
          "Content-Type": "application/json",
          "WWW-Authenticate": `Bearer realm="main", login_url="${loginUrl}", resource_metadata="${resourceMetadataUrl}`,
        },
      }
    );
  }

  try {
    // Decrypt access token to get user_id
    if (!accessToken.startsWith("simple_")) {
      throw new Error("Invalid access token format");
    }

    const encryptedData = accessToken.substring(7);
    const decryptedData = await decrypt(encryptedData, env.ENCRYPTION_SECRET);
    const [userId] = decryptedData.split(";");

    // Get user data from Durable Object using user_id
    const userDO = getMultiStub(
      env.UserDO,
      [
        { name: `${USER_DO_PREFIX}${userId}` },
        { name: `${USER_DO_PREFIX}aggregate:` },
      ],
      ctx
    );

    // Update activity before getting user data
    await userDO.updateActivity(accessToken);

    const userData = await userDO.getUserByAccessToken(accessToken);

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
            "WWW-Authenticate": `Bearer realm="main", error="invalid_token", login_url="${loginUrl}", resource_metadata="${resourceMetadataUrl}`,
          },
        }
      );
    }

    // Return user information
    return new Response(JSON.stringify(userData.user), {
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
  // Handle OPTIONS request
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

  // If no client_id, this is a direct login request
  if (!clientId) {
    const url = new URL(request.url);
    const redirectTo = url.searchParams.get("redirect_to") || "/";
    const resource = url.searchParams.get("resource");
    const requestedScope = url.searchParams.get("scope") || scope;

    // Generate PKCE code verifier and challenge
    const codeVerifier = generateCodeVerifier();
    const codeChallenge = await generateCodeChallenge(codeVerifier);

    // Create state with code verifier and resource (no redirectTo)
    const state: OAuthState = { codeVerifier, resource };
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

    const headers = new Headers({
      ...getCorsHeaders(),
      Location: xUrl.toString(),
    });

    // Set both oauth_state and redirect_to cookies
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

  // Validate that client_id looks like a domain
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
        headers: getCorsHeaders(),
      });
    }

    if (redirectUrl.hostname !== clientId) {
      return new Response(
        "Invalid redirect_uri: must be on same origin as client_id",
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

  // Only support authorization code flow
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
      // Decrypt access token to get user_id
      if (!accessToken.startsWith("simple_")) {
        throw new Error("Invalid access token format");
      }

      const encryptedData = accessToken.substring(7);
      const decryptedData = await decrypt(encryptedData, env.ENCRYPTION_SECRET);
      const [userId] = decryptedData.split(";");

      // User is already authenticated, create auth code and redirect
      return await createAuthCodeAndRedirect(
        env,
        clientId,
        redirectUri,
        state,
        userId,
        resource
      );
    } catch (error) {
      // Invalid token, continue to X OAuth
    }
  }

  // User not authenticated, redirect to X OAuth with our callback
  // Store the OAuth provider request details for after X auth
  const providerState = {
    clientId,
    redirectUri,
    state,
    originalState: state,
    resource,
  };

  const providerStateString = btoa(JSON.stringify(providerState));

  // Generate PKCE for X OAuth
  const codeVerifier = generateCodeVerifier();
  const codeChallenge = await generateCodeChallenge(codeVerifier);

  // Create X state with only essential data (no redirectTo)
  const xState: OAuthState = {
    codeVerifier,
    resource,
  };

  const xStateString = btoa(JSON.stringify(xState));

  if (xStateString.length > 500) {
    return new Response(
      "State string too long. \n\n" + JSON.stringify(xState, undefined, 2),
      {
        status: 400,
        headers: getCorsHeaders(),
      }
    );
  }

  // Build X OAuth URL
  const xUrl = new URL("https://x.com/i/oauth2/authorize");
  xUrl.searchParams.set("response_type", "code");
  xUrl.searchParams.set("client_id", env.X_CLIENT_ID);
  xUrl.searchParams.set("redirect_uri", `${url.origin}/callback`);
  xUrl.searchParams.set("scope", scope);
  xUrl.searchParams.set("state", xStateString);
  xUrl.searchParams.set("code_challenge", codeChallenge);
  xUrl.searchParams.set("code_challenge_method", "S256");

  console.log("Authorization URL", xUrl.toString(), "xState", xState);

  const headers = new Headers({
    ...getCorsHeaders(),
    Location: xUrl.toString(),
  });

  // Set oauth_state and provider_state cookies
  headers.append(
    "Set-Cookie",
    `oauth_state=${encodeURIComponent(
      xStateString
    )}; HttpOnly;${secureFlag} SameSite=${sameSite}; Max-Age=600; Path=/`
  );
  headers.append(
    "Set-Cookie",
    `provider_state=${encodeURIComponent(
      providerStateString
    )}; HttpOnly;${secureFlag} SameSite=${sameSite}; Max-Age=600; Path=/`
  );

  // Store redirectTo in a separate cookie for OAuth provider flows
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
  // Generate auth code
  const authCode = generateCodeVerifier(); // Reuse the same random generation

  // Get user's X access token from user DO (single DO call)
  const userDO = env.UserDO.get(
    env.UserDO.idFromName(`${USER_DO_PREFIX}${userId}`)
  );
  const userData = await userDO.getUserWithAccessToken(userId);

  if (!userData) {
    throw new Error("User not found");
  }

  // Create Durable Object for this auth code with "code:" prefix
  const id = env.UserDO.idFromName(`code:${authCode}`);
  const authCodeDO = env.UserDO.get(id);

  await authCodeDO.setAuthData(
    userData.xAccessToken,
    userId, // Store user_id instead of encrypted access token
    clientId,
    redirectUri,
    resource
  );

  // Redirect back to client with auth code
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
  // Handle preflight OPTIONS request
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
  const resource = formData.get("resource"); // MCP Required: Resource parameter

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

  // Validate client_id is a valid domain
  if (
    !isValidDomain(clientId.toString()) &&
    clientId.toString() !== "localhost"
  ) {
    console.log(clientId.toString(), "invalid_client");
    return new Response(JSON.stringify({ error: "invalid_client" }), {
      status: 400,
      headers: {
        ...corsHeaders,
        "Content-Type": "application/json",
      },
    });
  }

  // Get auth code data from Durable Object with "code:" prefix
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

  // Validate client_id and redirect_uri match
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

  // MCP Required: Validate resource parameter matches if provided
  if (!resource || authData.resource !== resource) {
    console.error({ resource, authResource: authData.resource });
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

  // Get user data from single DO
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
  const tokenData = `${authData.userId};${authData.resource};${userData.xAccessToken}`;
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

  // Return the new access token
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
  // Handle OPTIONS request
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

  // Get state from cookie
  const cookies = parseCookies(request.headers.get("Cookie") || "");
  const stateCookie = cookies.oauth_state;
  const providerStateCookie = cookies.provider_state;
  const redirectToCookie = cookies.redirect_to; // Get redirectTo from cookie

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
    return new Response("Invalid state format", {
      status: 400,
      headers: getCorsHeaders(),
    });
  }

  console.log("callbackstate", { state });

  // Exchange code for token with X
  const tokenResponse = await fetch("https://api.x.com/2/oauth2/token", {
    method: "POST",
    headers: {
      "Content-Type": "application/x-www-form-urlencoded",
      Authorization: `Basic ${btoa(
        `${env.X_CLIENT_ID}:${env.X_CLIENT_SECRET}`
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
      {
        status: 400,
        headers: getCorsHeaders(),
      }
    );
  }

  const tokenData = (await tokenResponse.json()) as any;

  if (!tokenData.access_token) {
    return new Response("Failed to get access token", {
      status: 400,
      headers: getCorsHeaders(),
    });
  }

  // Get user info from X API
  const userResponse = await fetch(
    "https://api.x.com/2/users/me?user.fields=profile_image_url,verified",
    { headers: { Authorization: `Bearer ${tokenData.access_token}` } }
  );

  if (!userResponse.ok) {
    return new Response("Failed to get user info", {
      status: 400,
      headers: getCorsHeaders(),
    });
  }

  const userData = (await userResponse.json()) as any;
  const user = userData.data as XUser;
  user.profile_image_url = user.profile_image_url?.replace(
    "_normal",
    "_400x400"
  );

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

      // Create auth code and redirect back to client
      const response = await createAuthCodeAndRedirect(
        env,
        providerState.clientId,
        providerState.redirectUri,
        providerState.state,
        user.id,
        providerState.resource
      );

      // Create access token for this client for cookie-based access (deterministic)
      const newTokenData = `${user.id};${providerState.resource};${tokenData.access_token}`;
      const encryptedData = await encrypt(newTokenData, env.ENCRYPTION_SECRET);
      const accessToken = `simple_${encryptedData}`;

      // Store login in aggregate DO
      await userDO.createLogin(user.id, providerState.clientId, accessToken);

      // Set access token cookie and clear state cookies
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

  await userDO.createLogin(user.id, env.SELF_CLIENT_ID, browserAccessToken);

  // Use redirectTo from cookie, fallback to root
  const redirectTo = redirectToCookie
    ? decodeURIComponent(redirectToCookie)
    : "/";

  const headers = new Headers({
    ...getCorsHeaders(),
    Location: redirectTo,
  });

  // Clear all state cookies
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
    String.fromCharCode.apply(null, Array.from(new Uint8Array(digest)))
  )
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=/g, "");
}

// Encryption utilities
async function encrypt(text: string, secret: string): Promise<string> {
  const encoder = new TextEncoder();
  const data = encoder.encode(text);

  // Generate random salt and IV
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

  // Combine salt + iv + encrypted data
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

  // Decode the base64url
  const combined = new Uint8Array(
    atob(encrypted.replace(/-/g, "+").replace(/_/g, "/"))
      .split("")
      .map((c) => c.charCodeAt(0))
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
    // only at localhost!
    request.headers.get("cf-connecting-ip") === "::1" ||
    request.headers.get("cf-connecting-ip") === "127.0.0.1"
  );
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
    /** If provided, only clients with these hostnames will be able to use this service to retrieve profile information. If not provided, any client will be able to */
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

    // Get user from access token
    let userDO: DurableObjectStub<UserDO>;

    let user: XUser | undefined = undefined;
    let registered = false;
    let xAccessToken: string | undefined = undefined;
    const accessToken = getAccessToken(request);
    if (accessToken) {
      try {
        // Decrypt access token to get user_id
        if (!accessToken.startsWith("simple_")) {
          throw new Error("Invalid access token format");
        }

        const encryptedData = accessToken.substring(7);
        const decryptedData = await decrypt(
          encryptedData,
          env.ENCRYPTION_SECRET
        );
        const [userId] = decryptedData.split(";");

        // Get user data from Durable Object using user_id
        userDO = getMultiStub(
          env.UserDO,
          [
            { name: `${USER_DO_PREFIX}${userId}` },
            { name: `${USER_DO_PREFIX}aggregate:` },
          ],
          ctx
        );

        // Update activity before getting user data (except for /me endpoint which handles it separately)
        const url = new URL(request.url);
        if (url.pathname !== "/me") {
          await userDO.updateActivity(accessToken);
        }

        const userData = await userDO.getUserByAccessToken(accessToken);

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
            // MCP Required: WWW-Authenticate header with resource metadata URL (RFC9728)
            "WWW-Authenticate": `Bearer realm="main", login_url="${loginUrl}", resource_metadata="${resourceMetadataUrl}"`,
          },
        }
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

    // Add CORS headers to the response
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
