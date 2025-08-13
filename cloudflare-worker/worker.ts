/// <reference types="@cloudflare/workers-types" />
/// <reference lib="esnext" />
//@ts-check

import { DurableObject } from "cloudflare:workers";
import { constructMCPAuthorizationUrl } from "./mcp-client-server-registration.js";
import homepage from "./homepage.html";
import directory from "./directory-template.html";
//@ts-ignore
import sampleData from "./sample.json";

import { UserDO, withSimplerAuth } from "./x-oauth-client-provider";
export { UserDO };

export interface Env {
  UserDO: DurableObjectNamespace<UserDO>;
  MCPProviders: DurableObjectNamespace<MCPProviders>;
  CLIENT_ID: string;
  CLIENT_SECRET: string;
}

type Provider = {
  id: string;
  hostname: string;
  mcp_url: string;
  client_id?: string;
  client_secret?: string;
  access_token?: string;
  token_type?: "Bearer" | string;
  expires_at?: number;
  created_at: string;
  updated_at: string;
  public?: boolean;
};

export default {
  fetch: withSimplerAuth(async (request, env, ctx) => {
    if (!ctx.user) {
      return new Response(null, {
        status: 302,
        headers: { Location: "/authorize" },
      });
    }

    const { user } = ctx;

    const url = new URL(request.url);

    if (url.pathname === "/") {
      return handleLandingPage(user, env, url.origin);
    }
    if (url.pathname === "/directory") {
      return handleDirectory();
    }

    if (url.pathname === "/remove" && request.method === "POST") {
      if (!user) {
        return new Response("Unauthorized", { status: 401 });
      }
      return handleRemoveProvider(request, user, env);
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
  }),
} satisfies ExportedHandler<Env>;

async function handleDirectory() {
  let html = directory;

  // Inject the servers data
  html = html.replace(
    "</head>",
    `<script>window.serversData = ${JSON.stringify(
      sampleData
    )};</script></head>`
  );

  return new Response(html, {
    headers: { "Content-Type": "text/html" },
  });
}

async function handleRemoveProvider(request: Request, user: any, env: Env) {
  const url = new URL(request.url);
  const hostname = url.searchParams.get("hostname");

  if (!hostname) {
    return new Response("Missing hostname parameter", { status: 400 });
  }

  try {
    const mcpProviders = getMcpStub(env, user.x_user_id);
    await mcpProviders.removeProvider(hostname);

    return new Response(JSON.stringify({ success: true }), {
      headers: { "Content-Type": "application/json" },
    });
  } catch (error) {
    return new Response(JSON.stringify({ error: error.message }), {
      status: 500,
      headers: { "Content-Type": "application/json" },
    });
  }
}

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
        client_id TEXT,
        client_secret TEXT,
        access_token TEXT,
        token_type TEXT DEFAULT 'Bearer',
        expires_at INTEGER,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        public BOOLEAN DEFAULT 0
      )
    `);
  }

  async addProvider(
    hostname: string,
    mcpUrl: string,
    clientId?: string,
    clientSecret?: string,
    accessToken?: string,
    expiresIn?: number,
    isPublic: boolean = false
  ) {
    const expiresAt = expiresIn ? Date.now() + expiresIn * 1000 : null;

    this.sql.exec(
      `
      INSERT OR REPLACE INTO providers 
      (hostname, mcp_url, client_id, client_secret, access_token, expires_at, updated_at, public)
      VALUES (?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP, ?)
    `,
      hostname,
      mcpUrl,
      clientId || null,
      clientSecret || null,
      accessToken || null,
      expiresAt,
      isPublic ? 1 : 0
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
      .exec<Provider>(`SELECT * FROM providers ORDER BY created_at DESC`)
      .toArray();
  }

  async removeProvider(hostname: string) {
    this.sql.exec(`DELETE FROM providers WHERE hostname = ?`, hostname);
  }
}

async function handleLandingPage(user: any, env: Env, origin: string) {
  let html = homepage;

  if (user) {
    // Get user's MCP providers
    const mcpProviders = getMcpStub(env, user.x_user_id);
    const providers = await mcpProviders.getAllProviders();

    // Build MCP servers array for the curl example

    const userData = {
      user,
      providers,
      curlExample: generateCurlExample(providers),
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
    const callbackUrl = `${origin}/callback/${hostname}`;

    const authFlowData = await constructMCPAuthorizationUrl(
      mcpUrl,
      callbackUrl
    );

    // If no auth is required, add the provider immediately
    if (authFlowData.noAuthRequired) {
      const mcpProviders = getMcpStub(env, user.x_user_id);
      await mcpProviders.addProvider(
        hostname,
        mcpUrl,
        undefined, // no client_id for public servers
        undefined, // no client_secret for public servers
        undefined, // no access_token for public servers
        undefined, // no expiration
        true // mark as public
      );

      return new Response(null, {
        status: 302,
        headers: { Location: "/?success=1&public=1" },
      });
    }

    // Store auth flow data in cookie for callback
    const authFlowCookie = btoa(
      JSON.stringify({
        ...authFlowData,
        userId: user.x_user_id,
        hostname: hostname,
      })
    );

    return new Response(null, {
      status: 302,
      headers: {
        Location: authFlowData.authorizationUrl,
        "Set-Cookie": `mcp_auth_${hostname}=${authFlowCookie}; HttpOnly; Secure; SameSite=Lax; Max-Age=600; Path=/`,
      },
    });
  } catch (error) {
    return new Response(`MCP authorization failed: ${error.message}`, {
      status: 400,
    });
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

  // Get auth flow data from cookie
  const cookieName = `mcp_auth_${hostname}`;
  const cookieHeader = request.headers.get("Cookie");
  let authFlowData;

  if (cookieHeader) {
    const cookies = Object.fromEntries(
      cookieHeader.split("; ").map((c) => c.split("="))
    );

    if (cookies[cookieName]) {
      try {
        authFlowData = JSON.parse(atob(cookies[cookieName]));
      } catch (error) {
        return new Response("Invalid auth flow data", { status: 400 });
      }
    }
  }

  if (!authFlowData) {
    return new Response("Missing auth flow data", { status: 400 });
  }

  // Verify state matches
  if (stateParam !== authFlowData.state) {
    return new Response("Invalid state parameter", { status: 400 });
  }

  // Verify user matches
  if (
    authFlowData.userId !== user.x_user_id ||
    authFlowData.hostname !== hostname
  ) {
    return new Response("Invalid session", { status: 400 });
  }

  if (!authFlowData.clientId || !authFlowData.tokenEndpoint) {
    return new Response("Missing client credentials or token endpoint", {
      status: 400,
    });
  }

  try {
    // Prepare token request body
    const tokenRequestBody = new URLSearchParams({
      grant_type: "authorization_code",
      code,
      redirect_uri: `${url.origin}/callback/${hostname}`,
      client_id: authFlowData.clientId,
      code_verifier: authFlowData.codeVerifier,
      resource: authFlowData.mcpServerUrl, // Include resource parameter
    });

    // Add client_secret if available (confidential clients)
    if (authFlowData.clientSecret) {
      tokenRequestBody.append("client_secret", authFlowData.clientSecret);
    }

    // Exchange code for token
    const tokenResponse = await fetch(authFlowData.tokenEndpoint, {
      method: "POST",
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
        Accept: "application/json",
      },
      body: tokenRequestBody,
    });

    if (!tokenResponse.ok) {
      const errorText = await tokenResponse.text();
      return new Response(
        `Token exchange failed: ${tokenResponse.status} ${errorText}`,
        { status: 400 }
      );
    }

    const tokenData = await tokenResponse.json();

    if (!tokenData.access_token) {
      return new Response("No access token received", { status: 400 });
    }

    // Store provider credentials
    const mcpProviders = getMcpStub(env, user.x_user_id);

    await mcpProviders.addProvider(
      hostname,
      authFlowData.mcpServerUrl,
      authFlowData.clientId,
      authFlowData.clientSecret,
      tokenData.access_token,
      tokenData.expires_in,
      false // not a public server
    );

    // Redirect to landing page with success
    return new Response(null, {
      status: 302,
      headers: {
        Location: "/?success=1",
        "Set-Cookie": `${cookieName}=; HttpOnly; Secure; SameSite=Lax; Max-Age=0; Path=/`, // Clear auth cookie
      },
    });
  } catch (error) {
    return new Response(`Token exchange failed: ${error.message}`, {
      status: 400,
    });
  }
}

const getMcpStub = (env: Env, userId: string) => {
  return env.MCPProviders.get(env.MCPProviders.idFromName("v2" + userId));
};

function generateCurlExample(providers: Provider[]) {
  const mcpServers = providers.map((provider) => {
    const server = {
      type: "url",
      url: provider.mcp_url,
      name: provider.hostname,
    };

    // Only add headers if provider has access token (not public)
    if (provider.access_token) {
      server.headers = {
        Authorization: `${provider.token_type || "Bearer"} ${
          provider.access_token
        }`,
      };
    }

    return server;
  });

  const tools = providers.map((provider) => {
    const tool = {
      type: "mcp",
      server_label: provider.hostname,
      server_url: provider.mcp_url,
      require_approval: "never",
    };

    // Only add headers if provider has access token (not public)
    if (provider.access_token) {
      tool.headers = {
        Authorization: `${provider.token_type || "Bearer"} ${
          provider.access_token
        }`,
      };
    }

    return tool;
  });

  const stringify = (json: any) =>
    JSON.stringify(json, null, 6).replace(/\n/g, "\n    ");

  return `curl https://api.anthropic.com/v1/messages \
  -H "Content-Type: application/json" \
  -H "X-API-Key: $ANTHROPIC_API_KEY" \
  -H "anthropic-version: 2023-06-01" \
  -H "anthropic-beta: mcp-client-2025-04-04" \
  -d '{
    "model": "claude-sonnet-4-20250514",
    "max_tokens": 1000,
    "messages": [{"role": "user", "content": "What tools do you have available?"}],
    "mcp_servers": ${stringify(mcpServers)}
  }'
  
curl -X POST "https://api.parallel.ai/v1/tasks/runs" \\
  -H "x-api-key: $PARALLEL_API_KEY" \\
  -H 'content-type: application/json' \\
  -H "parallel-beta: mcp-server-2025-07-17" \\
  --data '{
    "input": "What can you help me with?",
    "mcp_servers": ${stringify(mcpServers)}
  }'
  
curl https://api.openai.com/v1/responses \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $OPENAI_API_KEY" \
  -d '{
  "model": "gpt-5",
  "tools": ${stringify(tools)},
  "input": "What transport protocols are supported in the 2025-03-26 version of the MCP spec?"
}'
`;
}
