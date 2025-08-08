type Env = {
  AuthProvider: DurableObjectNamespace;
  CLIENT_ID: string;
  CLIENT_SECRET: string;
};

export const oauthEndpoints = [
  "/.well-known/oauth-authorization-server",
  "/.well-known/oauth-protected-resource",
  "/register",
  "/authorize",
  "/callback",
  "/token",
];

export class AuthProvider {
  sql: SqlStorage;
  env: Env;
  constructor(ctx: DurableObjectState, env) {
    this.sql = ctx.storage.sql;
    this.env = env;
    // Run migrations on startup
    this.migrate();
  }

  migrate() {
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

  async fetch(request) {
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
              headers: { "Content-Type": "application/json" },
            }
          );
        }

        // Extract hosts from all redirect URIs
        const hosts = new Set();
        for (const uri of body.redirect_uris) {
          try {
            const url = new URL(uri);
            hosts.add(url.host);
          } catch (e) {
            return new Response(
              JSON.stringify({
                error: "invalid_redirect_uri",
                error_description: `Invalid redirect URI: ${uri}`,
              }),
              {
                status: 400,
                headers: { "Content-Type": "application/json" },
              }
            );
          }
        }

        // Ensure all redirect URIs have the same host
        if (hosts.size !== 1) {
          return new Response(
            JSON.stringify({
              error: "invalid_client_metadata",
              error_description: "All redirect URIs must have the same host",
            }),
            {
              status: 400,
              headers: { "Content-Type": "application/json" },
            }
          );
        }

        const clientHost = Array.from(hosts)[0];

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
            headers: { "Content-Type": "application/json" },
          }
        );
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
      let existingAccessToken = null;

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
      const oauthState = {
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

      // Parse state
      let oauthState;
      try {
        oauthState = JSON.parse(atob(stateParam));
      } catch {
        return new Response("Invalid state format", { status: 400 });
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
        return new Response("Failed to exchange code", { status: 400 });
      }

      const tokenData = await tokenResponse.json<{
        access_token: string;
        refresh_token: string;
      }>();

      // Get X user info
      const userResponse = await fetch(
        "https://api.x.com/2/users/me?user.fields=profile_image_url,verified",
        { headers: { Authorization: `Bearer ${tokenData.access_token}` } }
      );

      if (!userResponse.ok) {
        return new Response("Failed to get user info", { status: 400 });
      }

      const userData: any = await userResponse.json();
      const xUser = userData.data;
      xUser.profile_image_url = xUser.profile_image_url?.replace(
        "_normal",
        "_400x400"
      );

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
      const grantType = formData.get("grant_type");
      const code = formData.get("code");
      const clientId = formData.get("client_id");

      if (grantType !== "authorization_code" || !code || !clientId) {
        return new Response(JSON.stringify({ error: "invalid_request" }), {
          status: 400,
          headers: {
            "Content-Type": "application/json",
            "Access-Control-Allow-Origin": "*",
          },
        });
      }

      const loginData = await this.getLoginByCode(code);

      if (!loginData || loginData.client_id !== clientId) {
        return new Response(JSON.stringify({ error: "invalid_grant" }), {
          status: 400,
          headers: {
            "Content-Type": "application/json",
            "Access-Control-Allow-Origin": "*",
          },
        });
      }

      await this.clearLoginCode(code);

      return new Response(
        JSON.stringify({
          access_token: loginData.access_token,
          token_type: "bearer",
        }),
        {
          headers: {
            "Content-Type": "application/json",
            "Access-Control-Allow-Origin": "*",
          },
        }
      );
    }

    return new Response("Not found", { status: 404 });
  }

  // Database methods
  async createOrUpdateUser(xUser) {
    this.sql.exec(
      `INSERT OR REPLACE INTO users 
       (x_user_id, username, name, profile_image_url, verified, updated_at)
       VALUES (?, ?, ?, ?, ?, CURRENT_TIMESTAMP)`,
      xUser.id,
      xUser.username,
      xUser.name,
      xUser.profile_image_url,
      xUser.verified
    );
  }

  async createLogin(xUserId, clientId, accessToken, authCode) {
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

  async getLoginByToken(accessToken) {
    const result = this.sql
      .exec(
        `SELECT u.*, l.* FROM users u 
         JOIN logins l ON u.x_user_id = l.x_user_id 
         WHERE l.access_token = ?`,
        accessToken
      )
      .toArray()[0];
    return result || null;
  }

  async getLoginByCode(authCode) {
    const result = this.sql
      .exec(
        `SELECT u.*, l.* FROM users u 
         JOIN logins l ON u.x_user_id = l.x_user_id 
         WHERE l.latest_login_code = ?`,
        authCode
      )
      .toArray()[0];
    return result || null;
  }

  async clearLoginCode(authCode) {
    this.sql.exec(
      `UPDATE logins SET latest_login_code = NULL, updated_at = CURRENT_TIMESTAMP 
       WHERE latest_login_code = ?`,
      authCode
    );
  }

  // Utility methods
  isValidDomain(domain) {
    const domainRegex =
      /^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$/;
    return (
      domainRegex.test(domain) && domain.includes(".") && domain.length <= 253
    );
  }

  generateCodeVerifier() {
    const array = new Uint8Array(32);
    crypto.getRandomValues(array);
    return btoa(String.fromCharCode.apply(null, Array.from(array)))
      .replace(/\+/g, "-")
      .replace(/\//g, "_")
      .replace(/=/g, "");
  }

  async generateCodeChallenge(verifier) {
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
