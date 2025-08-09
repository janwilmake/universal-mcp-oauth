import { DurableObject } from "cloudflare:workers";

type Env = {
  AuthProvider: DurableObjectNamespace;
  CLIENT_ID: string;
  CLIENT_SECRET: string;
};

interface User {
  x_user_id: string;
  username: string;
  name: string;
  profile_image_url: string | null;
  verified: boolean;
  created_at: string;
  updated_at: string;
}

interface Login {
  id: number;
  x_user_id: string;
  client_id: string;
  access_token: string;
  latest_login_code: string | null;
  created_at: string;
  updated_at: string;
}

interface UserWithLogin extends User {
  id: number;
  client_id: string;
  access_token: string;
  latest_login_code: string | null;
}

interface XUser {
  id: string;
  username: string;
  name: string;
  profile_image_url?: string;
  verified: boolean;
}

interface XTokenResponse {
  access_token: string;
  refresh_token: string;
  token_type?: string;
  expires_in?: number;
}

interface XUserResponse {
  data: XUser;
}

interface OAuthState {
  clientId: string;
  redirectUri: string;
  state: string | null;
  codeVerifier: string;
}

interface ClientRegistrationRequest {
  redirect_uris: string[];
  [key: string]: unknown;
}

interface ClientRegistrationResponse {
  client_id: string;
  redirect_uris: string[];
  token_endpoint_auth_method: string;
  grant_types: string[];
  response_types: string[];
}

interface TokenRequest {
  grant_type: string;
  code: string;
  client_id: string;
  [key: string]: string;
}

interface TokenResponse {
  access_token: string;
  token_type: string;
}

interface ErrorResponse {
  error: string;
  error_description?: string;
}

export const oauthEndpoints = [
  "/.well-known/oauth-authorization-server",
  "/.well-known/oauth-protected-resource",
  "/register",
  "/authorize",
  "/callback",
  "/token",
] as const;

export class AuthProvider extends DurableObject {
  sql: SqlStorage;
  env: Env;

  constructor(ctx: DurableObjectState, env: Env) {
    super(ctx, env);
    this.sql = ctx.storage.sql;
    this.env = env;
    // Run migrations on startup
    this.migrate();
  }

  migrate(): void {
    // Create users table
    this.sql.exec(`
      CREATE TABLE IF NOT EXISTS users (
        x_user_id TEXT PRIMARY KEY,
        username TEXT NOT NULL,
        name TEXT NOT NULL,
        profile_image_url TEXT,
        verified BOOLEAN DEFAULT FALSE,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
      )
    `);

    // Create logins table
    this.sql.exec(`
      CREATE TABLE IF NOT EXISTS logins (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        x_user_id TEXT NOT NULL,
        client_id TEXT NOT NULL,
        access_token TEXT NOT NULL UNIQUE,
        latest_login_code TEXT,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (x_user_id) REFERENCES users(x_user_id),
        UNIQUE(x_user_id, client_id)
      )
    `);

    // Create indexes for performance
    this.sql.exec(
      `CREATE INDEX IF NOT EXISTS idx_logins_access_token ON logins(access_token)`
    );
    this.sql.exec(
      `CREATE INDEX IF NOT EXISTS idx_logins_code ON logins(latest_login_code)`
    );
    this.sql.exec(
      `CREATE INDEX IF NOT EXISTS idx_logins_client ON logins(client_id)`
    );
  }

  async fetch(request: Request): Promise<Response> {
    const url = new URL(request.url);
    const path = url.pathname;

    if (!this.env.CLIENT_ID || !this.env.CLIENT_SECRET) {
      return new Response(
        "Environment misconfigured, please add CLIENT_ID and CLIENT_SECRET",
        { status: 500 }
      );
    }

    // CORS preflight
    if (request.method === "OPTIONS") {
      return new Response(null, {
        headers: {
          "Access-Control-Allow-Origin": "*",
          "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
          "Access-Control-Allow-Headers": "Content-Type, Authorization",
          "Access-Control-Max-Age": "86400",
        },
      });
    }

    // OAuth metadata endpoint
    if (path === "/.well-known/oauth-authorization-server") {
      const metadata = {
        issuer: url.origin,
        authorization_endpoint: `${url.origin}/authorize`,
        token_endpoint: `${url.origin}/token`,
        registration_endpoint: `${url.origin}/register`,
        response_types_supported: ["code"],
        grant_types_supported: ["authorization_code"],
        code_challenge_methods_supported: ["S256"],
        scopes_supported: ["users.read", "tweet.read", "offline.access"],
      };

      return new Response(JSON.stringify(metadata, null, 2), {
        headers: {
          "Content-Type": "application/json",
          "Cache-Control": "public, max-age=3600",
        },
      });
    }

    // Protected resource metadata endpoint
    if (path === "/.well-known/oauth-protected-resource") {
      const metadata = {
        resource: url.origin,
        authorization_servers: [url.origin],
        scopes_supported: ["users.read", "tweet.read", "offline.access"],
        bearer_methods_supported: ["header"],
      };

      return new Response(JSON.stringify(metadata, null, 2), {
        headers: {
          "Content-Type": "application/json",
          "Cache-Control": "public, max-age=3600",
        },
      });
    }

    // Dynamic client registration endpoint
    if (path === "/register") {
      if (request.method !== "POST") {
        return new Response("Method not allowed", { status: 405 });
      }

      try {
        const body = (await request.json()) as ClientRegistrationRequest;

        // Validate redirect_uris is present and is an array
        if (
          !body.redirect_uris ||
          !Array.isArray(body.redirect_uris) ||
          body.redirect_uris.length === 0
        ) {
          const errorResponse: ErrorResponse = {
            error: "invalid_client_metadata",
            error_description: "redirect_uris must be a non-empty array",
          };
          return new Response(JSON.stringify(errorResponse), {
            status: 400,
            headers: { "Content-Type": "application/json" },
          });
        }

        // Extract hosts from all redirect URIs
        const hosts = new Set<string>();
        for (const uri of body.redirect_uris) {
          try {
            const parsedUrl = new URL(uri);
            hosts.add(parsedUrl.host);
          } catch (e) {
            const errorResponse: ErrorResponse = {
              error: "invalid_redirect_uri",
              error_description: `Invalid redirect URI: ${uri}`,
            };
            return new Response(JSON.stringify(errorResponse), {
              status: 400,
              headers: { "Content-Type": "application/json" },
            });
          }
        }

        // Ensure all redirect URIs have the same host
        if (hosts.size !== 1) {
          const errorResponse: ErrorResponse = {
            error: "invalid_client_metadata",
            error_description: "All redirect URIs must have the same host",
          };
          return new Response(JSON.stringify(errorResponse), {
            status: 400,
            headers: { "Content-Type": "application/json" },
          });
        }

        const clientHost = Array.from(hosts)[0];

        // Response with client_id as the host
        const response: ClientRegistrationResponse = {
          client_id: clientHost,
          redirect_uris: body.redirect_uris,
          token_endpoint_auth_method: "none", // Public client, no secret needed
          grant_types: ["authorization_code"],
          response_types: ["code"],
        };

        return new Response(JSON.stringify(response, null, 2), {
          status: 201,
          headers: {
            "Content-Type": "application/json",
            "Cache-Control": "no-store",
            Pragma: "no-cache",
          },
        });
      } catch (error) {
        const errorResponse: ErrorResponse = {
          error: "invalid_client_metadata",
          error_description: "Invalid JSON in request body",
        };
        return new Response(JSON.stringify(errorResponse), {
          status: 400,
          headers: { "Content-Type": "application/json" },
        });
      }
    }

    // Authorization endpoint
    if (path === "/authorize") {
      const clientId = url.searchParams.get("client_id");
      const redirectUri = url.searchParams.get("redirect_uri");
      const state = url.searchParams.get("state");

      if (!clientId || !redirectUri) {
        return new Response("Missing required parameters", { status: 400 });
      }

      // Validate client domain
      if (!this.isValidDomain(clientId)) {
        return new Response("Invalid client_id: must be a valid domain", {
          status: 400,
        });
      }

      // Validate redirect URI
      try {
        const redirectUrl = new URL(redirectUri);
        if (redirectUrl.hostname !== clientId) {
          return new Response(
            "Invalid redirect_uri: must be on same domain as client_id",
            {
              status: 400,
            }
          );
        }
      } catch {
        return new Response("Invalid redirect_uri format", { status: 400 });
      }

      // Check for existing session cookie for this client
      const cookies = request.headers.get("Cookie");
      const sessionCookieName = `session_${clientId.replace(
        /[^a-zA-Z0-9]/g,
        "_"
      )}`;
      let existingAccessToken: string | null = null;

      if (cookies) {
        const cookieMatch = cookies.match(
          new RegExp(`${sessionCookieName}=([^;]+)`)
        );
        if (cookieMatch) {
          existingAccessToken = cookieMatch[1];
        }
      }

      // If we have an existing session, check if it's still valid
      if (existingAccessToken) {
        const loginData = await this.getLoginByToken(existingAccessToken);

        if (loginData && loginData.client_id === clientId) {
          // Valid session exists, skip X OAuth and redirect immediately
          const authCode = this.generateCodeVerifier();

          // Update the login with new auth code
          await this.createLogin(
            loginData.x_user_id,
            clientId,
            existingAccessToken,
            authCode
          );

          // Redirect back to client immediately
          const redirectUrl = new URL(redirectUri);
          redirectUrl.searchParams.set("code", authCode);
          if (state) {
            redirectUrl.searchParams.set("state", state);
          }

          return new Response(null, {
            status: 302,
            headers: {
              Location: redirectUrl.toString(),
              // Refresh the session cookie
              "Set-Cookie": `${sessionCookieName}=${existingAccessToken}; HttpOnly; Secure; SameSite=Lax; Max-Age=2592000; Path=/; Domain=${url.hostname}`,
            },
          });
        }
      }

      // No valid session, proceed with X OAuth flow
      // Generate PKCE
      const codeVerifier = this.generateCodeVerifier();
      const codeChallenge = await this.generateCodeChallenge(codeVerifier);

      // Store OAuth state
      const oauthState: OAuthState = {
        clientId,
        redirectUri,
        state,
        codeVerifier,
      };
      const stateString = btoa(JSON.stringify(oauthState));

      // Build X OAuth URL
      const xUrl = new URL("https://x.com/i/oauth2/authorize");
      xUrl.searchParams.set("response_type", "code");
      xUrl.searchParams.set("client_id", this.env.CLIENT_ID);
      xUrl.searchParams.set("redirect_uri", `${url.origin}/callback`);
      xUrl.searchParams.set("scope", "users.read tweet.read offline.access");
      xUrl.searchParams.set("state", stateString);
      xUrl.searchParams.set("code_challenge", codeChallenge);
      xUrl.searchParams.set("code_challenge_method", "S256");
      //https://x.com/i/oauth2/authorize?response_type=code&client_id=MWlyVUFQWm5fN01qWTlnaVlBbmY6MTpjaQ&redirect_uri=https%3A%2F%2Funiversal.simplerauth.com%2Fcallback&scope=users.read+tweet.read+offline.access&state=eyJjbGllbnRJZCI6InVuaXZlcnNhbC5zaW1wbGVyYXV0aC5jb20iLCJyZWRpcmVjdFVyaSI6Imh0dHBzOi8vdW5pdmVyc2FsLnNpbXBsZXJhdXRoLmNvbS9jYWxsYmFjayIsInN0YXRlIjoiZGVtbyIsImNvZGVWZXJpZmllciI6IlFQT04yR0RIZmt6enBTa25EXzBReVZZMWdJazZPS243X1B5Mk9TZC1yOWMifQ%3D%3D&code_challenge=bHncIW3WIkKSyvQ-LOurmJl1S8YT4YqG-cfcB571h-E&code_challenge_method=S256
      return new Response(null, {
        status: 302,
        headers: {
          Location: xUrl.toString(),
          "Set-Cookie": `oauth_state=${stateString}; HttpOnly; Secure; SameSite=Lax; Max-Age=600; Path=/`,
        },
      });
    }

    // OAuth callback endpoint
    if (path === "/callback") {
      const code = url.searchParams.get("code");
      const stateParam = url.searchParams.get("state");

      if (!code || !stateParam) {
        return new Response("Missing code or state", { status: 400 });
      }

      // Read the oauth_state cookie instead of using URL state param
      const cookies = request.headers.get("Cookie");
      let oauthStateString: string | null = null;

      if (cookies) {
        const cookieMatch = cookies.match(/oauth_state=([^;]+)/);
        if (cookieMatch) {
          oauthStateString = cookieMatch[1];
        }
      }

      if (!oauthStateString) {
        return new Response("Missing OAuth state cookie", { status: 400 });
      }

      // Parse state from cookie
      let oauthState: OAuthState;
      try {
        oauthState = JSON.parse(atob(oauthStateString)) as OAuthState;
      } catch {
        return new Response("Invalid state format", { status: 400 });
      }

      // Verify the state parameter matches what we stored
      if (stateParam !== oauthState.state) {
        return new Response(`State parameter mismatch`, { status: 400 });
      }

      // Exchange code for X token
      const tokenResponse = await fetch("https://api.x.com/2/oauth2/token", {
        method: "POST",
        headers: {
          "Content-Type": "application/x-www-form-urlencoded",
          Authorization: `Basic ${btoa(
            `${this.env.CLIENT_ID}:${this.env.CLIENT_SECRET}`
          )}`,
        },
        body: new URLSearchParams({
          code,
          redirect_uri: `${url.origin}/callback`,
          grant_type: "authorization_code",
          code_verifier: oauthState.codeVerifier,
        }),
      });

      if (!tokenResponse.ok) {
        return new Response(
          `Failed to exchange code ${
            tokenResponse.status
          } - ${await tokenResponse.text()}`,
          { status: 400 }
        );
      }

      const tokenData = await tokenResponse.json<XTokenResponse>();

      // Get X user info
      const userResponse = await fetch(
        "https://api.x.com/2/users/me?user.fields=profile_image_url,verified",
        { headers: { Authorization: `Bearer ${tokenData.access_token}` } }
      );

      if (!userResponse.ok) {
        return new Response("Failed to get user info", { status: 400 });
      }

      const userData = await userResponse.json<XUserResponse>();
      const xUser: XUser = {
        ...userData.data,
        profile_image_url: userData.data.profile_image_url?.replace(
          "_normal",
          "_400x400"
        ),
      };

      // Create user and login
      const accessToken = crypto.randomUUID();
      const authCode = this.generateCodeVerifier();

      await this.createOrUpdateUser(xUser);
      await this.createLogin(
        xUser.id,
        oauthState.clientId,
        accessToken,
        authCode
      );

      // Redirect back to client
      const redirectUrl = new URL(oauthState.redirectUri);
      redirectUrl.searchParams.set("code", authCode);
      if (oauthState.state) {
        redirectUrl.searchParams.set("state", oauthState.state);
      }

      // Set session cookie for future authorization optimizations
      const sessionCookieName = `session_${oauthState.clientId.replace(
        /[^a-zA-Z0-9]/g,
        "_"
      )}`;

      return new Response(null, {
        status: 302,
        headers: {
          Location: redirectUrl.toString(),
          "Set-Cookie": `${sessionCookieName}=${accessToken}; HttpOnly; Secure; SameSite=Lax; Max-Age=2592000; Path=/; Domain=${url.hostname}`,
        },
      });
    }

    // Token endpoint
    if (path === "/token") {
      if (request.method !== "POST") {
        return new Response("Method not allowed", { status: 405 });
      }

      const formData = await request.formData();
      const grantType = formData.get("grant_type") as string | null;
      const code = formData.get("code") as string | null;
      const clientId = formData.get("client_id") as string | null;

      if (grantType !== "authorization_code" || !code || !clientId) {
        const errorResponse: ErrorResponse = { error: "invalid_request" };
        return new Response(JSON.stringify(errorResponse), {
          status: 400,
          headers: {
            "Content-Type": "application/json",
            "Access-Control-Allow-Origin": "*",
          },
        });
      }

      const loginData = await this.getLoginByCode(code);

      if (!loginData || loginData.client_id !== clientId) {
        const errorResponse: ErrorResponse = { error: "invalid_grant" };
        return new Response(JSON.stringify(errorResponse), {
          status: 400,
          headers: {
            "Content-Type": "application/json",
            "Access-Control-Allow-Origin": "*",
          },
        });
      }

      await this.clearLoginCode(code);

      const tokenResponse: TokenResponse = {
        access_token: loginData.access_token,
        token_type: "bearer",
      };

      return new Response(JSON.stringify(tokenResponse), {
        headers: {
          "Content-Type": "application/json",
          "Access-Control-Allow-Origin": "*",
        },
      });
    }

    return new Response("Not found", { status: 404 });
  }

  // Database methods
  async createOrUpdateUser(xUser: XUser): Promise<void> {
    this.sql.exec(
      `INSERT OR REPLACE INTO users 
       (x_user_id, username, name, profile_image_url, verified, updated_at)
       VALUES (?, ?, ?, ?, ?, CURRENT_TIMESTAMP)`,
      xUser.id,
      xUser.username,
      xUser.name,
      xUser.profile_image_url || null,
      xUser.verified
    );
  }

  async createLogin(
    xUserId: string,
    clientId: string,
    accessToken: string,
    authCode: string
  ): Promise<void> {
    this.sql.exec(
      `INSERT OR REPLACE INTO logins 
       (x_user_id, client_id, access_token, latest_login_code, updated_at)
       VALUES (?, ?, ?, ?, CURRENT_TIMESTAMP)`,
      xUserId,
      clientId,
      accessToken,
      authCode
    );
  }

  async getLoginByToken(accessToken: string): Promise<UserWithLogin | null> {
    const result = this.sql
      .exec(
        `SELECT u.*, l.* FROM users u 
         JOIN logins l ON u.x_user_id = l.x_user_id 
         WHERE l.access_token = ?`,
        accessToken
      )
      .toArray()[0];
    return result ? (result as unknown as UserWithLogin) : null;
  }

  async getLoginByCode(authCode: string): Promise<UserWithLogin | null> {
    const result = this.sql
      .exec(
        `SELECT u.*, l.* FROM users u 
         JOIN logins l ON u.x_user_id = l.x_user_id 
         WHERE l.latest_login_code = ?`,
        authCode
      )
      .toArray()[0];
    return result ? (result as unknown as UserWithLogin) : null;
  }

  async clearLoginCode(authCode: string): Promise<void> {
    this.sql.exec(
      `UPDATE logins SET latest_login_code = NULL, updated_at = CURRENT_TIMESTAMP 
       WHERE latest_login_code = ?`,
      authCode
    );
  }

  // Utility methods
  isValidDomain(domain: string): boolean {
    const domainRegex =
      /^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$/;
    return (
      domainRegex.test(domain) && domain.includes(".") && domain.length <= 253
    );
  }

  generateCodeVerifier(): string {
    const array = new Uint8Array(32);
    crypto.getRandomValues(array);
    return btoa(String.fromCharCode.apply(null, Array.from(array)))
      .replace(/\+/g, "-")
      .replace(/\//g, "_")
      .replace(/=/g, "");
  }

  async generateCodeChallenge(verifier: string): Promise<string> {
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
}
