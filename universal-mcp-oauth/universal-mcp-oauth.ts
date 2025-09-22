/// <reference types="@cloudflare/workers-types" />
/// <reference lib="esnext" />
import { DurableObject } from "cloudflare:workers";
import {
  constructMCPAuthorizationUrl,
  extractMCPServerInfo,
} from "mcp-client-server-registration";

export interface MCPOAuthEnv {
  MCPProviders: DurableObjectNamespace<MCPProviders>;
}

export interface MCPProvider extends Record<string, SqlStorageValue> {
  id: string;
  hostname: string;
  name: string;
  mcp_url: string;
  client_id?: string;
  client_secret?: string;
  access_token?: string;
  token_type?: "Bearer" | string;
  expires_at?: number;
  created_at: string;
  updated_at: string;
  public?: 0 | 1;
  tools?: string; // JSON blob of tools array
}

export class MCPProviders extends DurableObject {
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
        hostname TEXT NOT NULL,
        name TEXT NOT NULL,
        mcp_url TEXT NOT NULL UNIQUE,
        client_id TEXT,
        client_secret TEXT,
        access_token TEXT,
        token_type TEXT DEFAULT 'Bearer',
        expires_at INTEGER,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        public BOOLEAN DEFAULT 0,
        tools TEXT
      )
    `);

    // Add tools column if it doesn't exist (for existing databases)
    try {
      this.sql.exec(`ALTER TABLE providers ADD COLUMN tools TEXT`);
    } catch (e) {
      // Column already exists, ignore
    }
  }

  async addProvider(
    hostname: string,
    name: string,
    mcpUrl: string,
    clientId?: string,
    clientSecret?: string,
    accessToken?: string,
    expiresIn?: number,
    isPublic: boolean = false,
    tools?: any[]
  ) {
    const expiresAt = expiresIn ? Date.now() + expiresIn * 1000 : null;
    const toolsJson = tools ? JSON.stringify(tools) : null;

    this.sql.exec(
      `
      INSERT OR REPLACE INTO providers 
      (hostname, name, mcp_url, client_id, client_secret, access_token, expires_at, updated_at, public, tools)
      VALUES (?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP, ?, ?)
    `,
      hostname,
      name,
      mcpUrl,
      clientId || null,
      clientSecret || null,
      accessToken || null,
      expiresAt,
      isPublic ? 1 : 0,
      toolsJson
    );
  }

  async getProvider(mcpUrl: string): Promise<MCPProvider | null> {
    const result = this.sql
      .exec<MCPProvider>(
        `SELECT * FROM providers WHERE mcp_url = ? LIMIT 1`,
        mcpUrl
      )
      .toArray()[0];

    return result || null;
  }

  async getAllProviders(): Promise<MCPProvider[]> {
    return this.sql
      .exec<MCPProvider>(`SELECT * FROM providers ORDER BY created_at DESC`)
      .toArray();
  }

  async removeProvider(mcpUrl: string) {
    this.sql.exec(`DELETE FROM providers WHERE mcp_url = ?`, mcpUrl);
  }

  async updateProviderTools(mcpUrl: string, tools: any[]) {
    const toolsJson = JSON.stringify(tools);
    this.sql.exec(
      `UPDATE providers SET tools = ?, updated_at = CURRENT_TIMESTAMP WHERE mcp_url = ?`,
      toolsJson,
      mcpUrl
    );
  }
}

export interface MCPOAuthConfig {
  /** Stable UserID to which the authenticated connections with MCP servers need to be saved to */
  userId: string;
  clientInfo: {
    name: string;
    title: string;
    version: string;
  };
  baseUrl?: string; // For custom callback URLs
}

const VERSION = "v5:";

export function createMCPOAuthHandler(config: MCPOAuthConfig) {
  const { userId, baseUrl, clientInfo } = config;

  return async function handleMCPOAuth(
    request: Request,
    env: MCPOAuthEnv,
    ctx: ExecutionContext
  ): Promise<Response | null> {
    const url = new URL(request.url);
    const path = url.pathname;

    // Only handle MCP OAuth routes
    if (!path.startsWith("/mcp/")) {
      return null;
    }

    const origin = baseUrl || url.origin;
    const mcpProviders = getMcpStub(env, userId, VERSION);

    if (path === "/mcp/login") {
      return handleMCPLogin(request, mcpProviders, origin, clientInfo);
    }

    if (path.startsWith("/mcp/callback/")) {
      const hostname = path.split("/mcp/callback/")[1];
      return handleMCPCallback(
        request,
        mcpProviders,
        hostname,
        origin,
        config.clientInfo
      );
    }

    if (path === "/mcp/remove" && request.method === "POST") {
      return handleRemoveProvider(request, mcpProviders);
    }

    if (path === "/mcp/providers") {
      return handleGetProviders(mcpProviders);
    }

    return null;
  };
}

async function handleMCPLogin(
  request: Request,
  mcpProviders: DurableObjectStub<MCPProviders>,
  origin: string,
  clientInfo: {
    name: string;
    title: string;
    version: string;
  }
) {
  const url = new URL(request.url);
  const mcpUrl = url.searchParams.get("url");

  if (!mcpUrl) {
    return new Response("Missing url parameter", { status: 400 });
  }

  try {
    const mcpUrlObj = new URL(mcpUrl);
    const hostname = mcpUrlObj.hostname;
    const callbackUrl = `${origin}/mcp/callback/${hostname}`;

    const { registrationResponse, authServerMetadata, ...authFlowData } =
      await constructMCPAuthorizationUrl(mcpUrl, callbackUrl, clientInfo);

    // If no auth is required, add the provider immediately
    if (authFlowData.noAuthRequired) {
      try {
        const { serverName, tools } = await extractMCPServerInfo(
          clientInfo,
          mcpUrl
        );
        await mcpProviders.addProvider(
          hostname,
          serverName,
          mcpUrl,
          undefined,
          undefined,
          undefined,
          undefined,
          true,
          tools
        );

        return new Response(null, {
          status: 302,
          headers: { Location: `${origin}?success=1` },
        });
      } catch (error) {
        return new Response(`Failed to get server info: ${error.message}`, {
          status: 400,
        });
      }
    }

    // Store auth flow data in cookie for callback
    const authFlowCookie = encodeURIComponent(
      btoa(
        JSON.stringify({
          ...authFlowData,
          hostname: hostname,
        })
      )
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

async function handleMCPCallback(
  request: Request,
  mcpProviders: DurableObjectStub<MCPProviders>,
  hostname: string,
  origin: string,
  clientInfo: {
    name: string;
    title: string;
    version: string;
  }
) {
  const url = new URL(request.url);
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
        authFlowData = JSON.parse(
          atob(decodeURIComponent(cookies[cookieName]))
        );
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

  if (!authFlowData.clientId || !authFlowData.tokenEndpoint) {
    return new Response("Missing client credentials or token endpoint", {
      status: 400,
    });
  }

  try {
    // Exchange code for token
    const tokenData = await exchangeCodeForToken(
      code,
      authFlowData,
      `${origin}/mcp/callback/${hostname}`
    );

    if (!tokenData.access_token) {
      return new Response("No access token received", { status: 400 });
    }

    // Get server name and tools
    const { serverName, tools } = await extractMCPServerInfo(
      clientInfo,
      authFlowData.mcpServerUrl,
      tokenData.access_token
    );

    await mcpProviders.addProvider(
      hostname,
      serverName,
      authFlowData.mcpServerUrl,
      authFlowData.clientId,
      authFlowData.clientSecret,
      tokenData.access_token,
      tokenData.expires_in,
      false,
      tools
    );

    // Redirect with success and clear cookie
    return new Response(null, {
      status: 302,
      headers: {
        Location: `${origin}?success=1`,
        "Set-Cookie": `mcp_auth_${hostname}=; HttpOnly; Secure; SameSite=Lax; Max-Age=0; Path=/`,
      },
    });
  } catch (error) {
    return new Response(`Token exchange failed: ${error.message}`, {
      status: 400,
    });
  }
}

async function handleRemoveProvider(
  request: Request,
  mcpProviders: DurableObjectStub<MCPProviders>
) {
  const url = new URL(request.url);
  const mcpUrl = url.searchParams.get("url");

  if (!mcpUrl) {
    return new Response("Missing url parameter", { status: 400 });
  }

  try {
    await mcpProviders.removeProvider(mcpUrl);
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

async function handleGetProviders(
  mcpProviders: DurableObjectStub<MCPProviders>
) {
  try {
    const providers = await mcpProviders.getAllProviders();
    // Parse tools JSON for each provider
    const providersWithParsedTools = providers.map((provider) => ({
      ...provider,
      tools: provider.tools ? JSON.parse(provider.tools) : null,
    }));

    return new Response(JSON.stringify(providersWithParsedTools), {
      headers: { "Content-Type": "application/json" },
    });
  } catch (error) {
    return new Response(JSON.stringify({ error: error.message }), {
      status: 500,
      headers: { "Content-Type": "application/json" },
    });
  }
}

// Helper functions
async function exchangeCodeForToken(
  code: string,
  authFlowData: any,
  redirectUri: string
) {
  const tokenRequestBody = new URLSearchParams({
    grant_type: "authorization_code",
    code,
    redirect_uri: redirectUri,
    client_id: authFlowData.clientId,
    code_verifier: authFlowData.codeVerifier,
    resource: authFlowData.mcpServerUrl,
  });

  if (authFlowData.clientSecret) {
    tokenRequestBody.append("client_secret", authFlowData.clientSecret);
  }

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
    throw new Error(`${tokenResponse.status} ${errorText}`);
  }

  return (await tokenResponse.json()) as {
    access_token: string;
    expires_in: number;
  };
}

function getMcpStub(env: MCPOAuthEnv, userId: string, versionPrefix?: string) {
  return env.MCPProviders.get(
    env.MCPProviders.idFromName(versionPrefix + userId)
  );
}

export async function getMCPProviders(
  env: MCPOAuthEnv,
  userId: string
): Promise<
  (MCPProvider & {
    tools: { name: string; inputSchema: any; description: string }[];
  })[]
> {
  const mcpProviders = env.MCPProviders.get(
    env.MCPProviders.idFromName(VERSION + userId)
  );
  const providers = await mcpProviders.getAllProviders();

  // Parse tools JSON for each provider
  return providers.map((provider) => ({
    ...provider,
    tools: provider.tools ? JSON.parse(provider.tools) : null,
  }));
}

// Utility function to get authorization for any URL
export async function getAuthorization(
  env: MCPOAuthEnv,
  userId: string,
  url: string
): Promise<{ Authorization?: string } | null> {
  try {
    const urlObj = new URL(url);
    const mcpProviders = getMcpStub(env, userId, VERSION);
    const provider = await mcpProviders.getProvider(url);

    if (provider && provider.access_token) {
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
