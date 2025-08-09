/// <reference types="@cloudflare/workers-types" />
import { DurableObject } from "cloudflare:workers";
import { AuthProvider, oauthEndpoints } from "./provider";
import indexHTML from "./index.html";

export interface Env {
  AuthProvider: DurableObjectNamespace<AuthProvider>;
  MCPProviders: DurableObjectNamespace<MCPProviders>;
  CLIENT_ID: string;
  CLIENT_SECRET: string;
}

export default {
  async fetch(
    request: Request,
    env: Env,
    ctx: ExecutionContext
  ): Promise<Response> {
    const url = new URL(request.url);

    // Handle auth provider endpoints
    if (oauthEndpoints.includes(url.pathname)) {
      return env.AuthProvider.get(
        env.AuthProvider.idFromName("oauth-central")
      ).fetch(request);
    }

    // Get current user from session
    const user = await getCurrentUser(request, env);

    if (url.pathname === "/") {
      return handleLandingPage(user, env, url.origin);
    }

    if (url.pathname === "/login") {
      if (!user) {
        return new Response("Unauthorized", { status: 401 });
      }
      return handleMCPLogin(request, user, env, url.origin);
    }

    if (url.pathname.startsWith("/callback/")) {
      if (!user) {
        return new Response("Unauthorized", { status: 401 });
      }
      return handleMCPCallback(request, user, env);
    }

    return new Response("Not found", { status: 404 });
  },
} satisfies ExportedHandler<Env>;

export { AuthProvider } from "./provider";
export class MCPProviders extends DurableObject<Env> {
  sql: SqlStorage;

  constructor(state: DurableObjectState, env: Env) {
    super(state, env);
    this.sql = state.storage.sql;
    this.migrate();
  }

  migrate() {
    this.sql.exec(`
      CREATE TABLE IF NOT EXISTS providers (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        hostname TEXT NOT NULL UNIQUE,
        mcp_url TEXT NOT NULL,
        access_token TEXT NOT NULL,
        token_type TEXT DEFAULT 'bearer',
        expires_at INTEGER,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
      )
    `);
  }

  async addProvider(
    hostname: string,
    mcpUrl: string,
    accessToken: string,
    expiresIn?: number
  ) {
    const expiresAt = expiresIn ? Date.now() + expiresIn * 1000 : null;

    this.sql.exec(
      `
      INSERT OR REPLACE INTO providers 
      (hostname, mcp_url, access_token, expires_at, updated_at)
      VALUES (?, ?, ?, ?, CURRENT_TIMESTAMP)
    `,
      hostname,
      mcpUrl,
      accessToken,
      expiresAt
    );
  }

  async getProvider(hostname: string) {
    const result = this.sql
      .exec(`SELECT * FROM providers WHERE hostname = ? LIMIT 1`, hostname)
      .toArray()[0];

    return result || null;
  }

  async getAllProviders() {
    return this.sql
      .exec(`SELECT * FROM providers ORDER BY created_at DESC`)
      .toArray();
  }

  async removeProvider(hostname: string) {
    this.sql.exec(`DELETE FROM providers WHERE hostname = ?`, hostname);
  }
}

async function getCurrentUser(request: Request, env: Env) {
  const authHeader = request.headers.get("Authorization");
  if (!authHeader?.startsWith("Bearer ")) {
    return null;
  }

  const token = authHeader.substring(7);
  const authProvider = env.AuthProvider.get(
    env.AuthProvider.idFromName("oauth-central")
  );

  try {
    // Call a method on the auth provider to validate token and get user
    const user = await authProvider.getLoginByToken(token);
    return user;
  } catch {
    return null;
  }
}

async function handleLandingPage(user: any, env: Env, origin: string) {
  let html = indexHTML;

  if (user) {
    // Get user's MCP providers
    const mcpProviders = env.MCPProviders.get(
      env.MCPProviders.idFromName(user.x_user_id)
    );
    const providers = await mcpProviders.getAllProviders();

    // Build MCP servers array for the curl example
    const mcpServers = providers.map((provider: any) => ({
      type: "url",
      url: provider.mcp_url,
      name: provider.hostname,
      headers: {
        Authorization: `${provider.token_type} ${provider.access_token}`,
      },
    }));

    const userData = {
      user,
      providers,
      mcpServers,
      curlExample: generateCurlExample(mcpServers),
    };

    // Inject data into HTML
    html = html.replace(
      "</head>",
      `<script>window.userData = ${JSON.stringify(userData)};</script></head>`
    );
  }

  return new Response(html, {
    headers: { "Content-Type": "text/html" },
  });
}

async function handleMCPLogin(
  request: Request,
  user: any,
  env: Env,
  origin: string
) {
  const url = new URL(request.url);
  const mcpUrl = url.searchParams.get("url");

  if (!mcpUrl) {
    return new Response("Missing url parameter", { status: 400 });
  }

  try {
    const mcpUrlObj = new URL(mcpUrl);
    const hostname = mcpUrlObj.hostname;

    // Discover OAuth metadata
    const metadataUrl = `${mcpUrlObj.protocol}//${hostname}/.well-known/oauth-authorization-server`;
    const metadataResponse = await fetch(metadataUrl);

    if (!metadataResponse.ok) {
      return new Response(`MCP server at ${hostname} does not support OAuth`, {
        status: 400,
      });
    }

    const metadata: {
      registration_endpoint: string;
      client_id: string;
      authorization_endpoint: string;
      token_endpoint: string;
    } = await metadataResponse.json();

    // Register client if supported
    let clientId = hostname; // Default to hostname-as-client-id

    if (metadata.registration_endpoint) {
      const registrationResponse = await fetch(metadata.registration_endpoint, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          redirect_uris: [`${origin}/callback/${hostname}`],
          client_name: "Universal MCP OAuth",
          grant_types: ["authorization_code"],
          response_types: ["code"],
        }),
      });

      if (registrationResponse.ok) {
        const clientData = await registrationResponse.json();
        clientId = clientData.client_id;
      }
    }

    // Generate state
    const state = JSON.stringify({
      mcpUrl,
      hostname,
      userId: user.x_user_id,
    });

    // Build authorization URL
    const authUrl = new URL(metadata.authorization_endpoint);
    authUrl.searchParams.set("response_type", "code");
    authUrl.searchParams.set("client_id", clientId);
    authUrl.searchParams.set("redirect_uri", `${origin}/callback/${hostname}`);
    authUrl.searchParams.set("state", btoa(state));
    authUrl.searchParams.set("scope", "openid profile");

    return new Response(null, {
      status: 302,
      headers: {
        Location: authUrl.toString(),
        "Set-Cookie": `oauth_state_${hostname}=${btoa(
          state
        )}; HttpOnly; Secure; SameSite=Lax; Max-Age=600; Path=/`,
      },
    });
  } catch (error) {
    return new Response(`Invalid MCP URL: ${error.message}`, { status: 400 });
  }
}

async function handleMCPCallback(request: Request, user: any, env: Env) {
  const url = new URL(request.url);
  const hostname = url.pathname.split("/callback/")[1];
  const code = url.searchParams.get("code");
  const stateParam = url.searchParams.get("state");

  if (!code || !stateParam) {
    return new Response("Missing code or state", { status: 400 });
  }

  try {
    const state = JSON.parse(atob(stateParam));

    if (state.userId !== user.x_user_id || state.hostname !== hostname) {
      return new Response("Invalid state", { status: 400 });
    }

    // Get OAuth metadata again
    const metadataUrl = `https://${hostname}/.well-known/oauth-authorization-server`;
    const metadata = await fetch(metadataUrl).then((r) => r.json());

    // Exchange code for token
    const tokenResponse = await fetch(metadata.token_endpoint, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        grant_type: "authorization_code",
        code,
        redirect_uri: url.origin + url.pathname,
        client_id: hostname, // Using hostname-as-client-id
      }),
    });

    if (!tokenResponse.ok) {
      return new Response("Token exchange failed", { status: 400 });
    }

    const tokenData = await tokenResponse.json();

    // Store provider credentials
    const mcpProviders = env.MCPProviders.get(
      env.MCPProviders.idFromName(user.x_user_id)
    );

    await mcpProviders.addProvider(
      hostname,
      state.mcpUrl,
      tokenData.access_token,
      tokenData.expires_in
    );

    // Redirect to landing page with success
    return new Response(null, {
      status: 302,
      headers: {
        Location: "/?success=1",
        "Set-Cookie": `oauth_state_${hostname}=; HttpOnly; Secure; SameSite=Lax; Max-Age=0; Path=/`,
      },
    });
  } catch (error) {
    return new Response(`Callback failed: ${error.message}`, { status: 400 });
  }
}

export async function getAuthorization(
  env: Env,
  urlString: string,
  userId: string
): Promise<Record<string, string> | null> {
  try {
    const url = new URL(urlString);
    const hostname = url.hostname;

    const mcpProviders = env.MCPProviders.get(
      env.MCPProviders.idFromName(userId)
    );

    const provider = await mcpProviders.getProvider(hostname);

    if (!provider) {
      return null;
    }

    // Check if token is expired
    if (provider.expires_at && Date.now() > provider.expires_at) {
      return null;
    }

    return {
      Authorization: `${provider.token_type} ${provider.access_token}`,
    };
  } catch {
    return null;
  }
}

function generateCurlExample(mcpServers: any[]) {
  return `curl -X POST "https://api.parallel.ai/v1/tasks/runs" \\
  -H "x-api-key: YOUR_API_KEY" \\
  -H 'content-type: application/json' \\
  -H "parallel-beta: mcp-server-2025-07-17" \\
  --data '{
    "input": "What can you help me with?",
    "processor": "lite",
    "mcp_servers": ${JSON.stringify(mcpServers, null, 6).replace(
      /\n/g,
      "\n    "
    )}
  }'`;
}
