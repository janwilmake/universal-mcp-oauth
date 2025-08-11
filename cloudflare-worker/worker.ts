/// <reference types="@cloudflare/workers-types" />
import { DurableObject } from "cloudflare:workers";
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
  client_id: string;
  client_secret?: string;
  access_token?: string;
  token_type?: "Bearer" | string;
  expires_at: number;
  created_at: string;
  updated_at: string;
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
        client_id TEXT NOT NULL,
        client_secret TEXT,
        access_token TEXT NOT NULL,
        token_type TEXT DEFAULT 'Bearer',
        expires_at INTEGER,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
      )
    `);
  }

  async addProvider(
    hostname: string,
    mcpUrl: string,
    clientId: string,
    clientSecret: string | null,
    accessToken: string,
    expiresIn?: number
  ) {
    const expiresAt = expiresIn ? Date.now() + expiresIn * 1000 : null;

    this.sql.exec(
      `
      INSERT OR REPLACE INTO providers 
      (hostname, mcp_url, client_id, client_secret, access_token, expires_at, updated_at)
      VALUES (?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
    `,
      hostname,
      mcpUrl,
      clientId,
      clientSecret,
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

    // Discover OAuth metadata
    const metadataUrl = `${mcpUrlObj.protocol}//${hostname}/.well-known/oauth-authorization-server`;
    const metadataResponse = await fetch(metadataUrl);

    if (!metadataResponse.ok) {
      return new Response(`MCP server at ${hostname} does not support OAuth`, {
        status: 400,
      });
    }

    const metadata: {
      registration_endpoint?: string;
      client_id?: string;
      authorization_endpoint: string;
      token_endpoint: string;
    } = await metadataResponse.json();

    // Dynamic client registration is required
    if (!metadata.registration_endpoint) {
      return new Response(
        `MCP server at ${hostname} does not support dynamic client registration`,
        { status: 400 }
      );
    }

    // Register client
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

    if (!registrationResponse.ok) {
      const errorText = await registrationResponse.text();
      return new Response(
        `Client registration failed for ${hostname}: ${registrationResponse.status} ${errorText}`,
        { status: 400 }
      );
    }

    const clientData = await registrationResponse.json();

    if (!clientData.client_id) {
      return new Response(
        `Client registration for ${hostname} did not return a client_id`,
        { status: 400 }
      );
    }

    // Generate state with client credentials
    const state = JSON.stringify({
      mcpUrl,
      hostname,
      userId: user.x_user_id,
      clientId: clientData.client_id,
      clientSecret: clientData.client_secret || null,
    });

    // Build authorization URL
    const authUrl = new URL(metadata.authorization_endpoint);
    authUrl.searchParams.set("response_type", "code");
    authUrl.searchParams.set("client_id", clientData.client_id);
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

    if (!state.clientId) {
      return new Response("Missing client credentials in state", {
        status: 400,
      });
    }

    // Get OAuth metadata again
    const metadataUrl = `https://${hostname}/.well-known/oauth-authorization-server`;
    const metadataResponse = await fetch(metadataUrl);

    if (!metadataResponse.ok) {
      return new Response("Failed to fetch OAuth metadata", { status: 400 });
    }

    const metadata = await metadataResponse.json();

    // Prepare token request body
    const tokenRequestBody = new URLSearchParams({
      grant_type: "authorization_code",
      code,
      redirect_uri: url.origin + url.pathname,
      client_id: state.clientId,
    });

    // Add client_secret if available
    if (state.clientSecret) {
      tokenRequestBody.append("client_secret", state.clientSecret);
    }

    // Exchange code for token
    const tokenResponse = await fetch(metadata.token_endpoint, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
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

    // Store provider credentials with proper client credentials
    const mcpProviders = getMcpStub(env, user.x_user_id);

    await mcpProviders.addProvider(
      hostname,
      state.mcpUrl,
      state.clientId,
      state.clientSecret,
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

const getMcpStub = (env: Env, userId: string) => {
  return env.MCPProviders.get(env.MCPProviders.idFromName("v2" + userId));
};

function generateCurlExample(providers: Provider[]) {
  const mcpServers = providers.map((provider) => ({
    type: "url",
    url: provider.mcp_url,
    name: provider.hostname,
    headers: {
      Authorization: `${provider.token_type} ${provider.access_token}`,
    },
  }));

  const tools = providers.map((provider) => {
    return {
      type: "mcp",
      server_label: provider.hostname,
      server_url: provider.mcp_url,
      require_approval: "never",
      headers: {
        Authorization: `${provider.token_type} ${provider.access_token}`,
      },
    };
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
