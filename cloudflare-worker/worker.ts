/// <reference types="@cloudflare/workers-types" />
/// <reference lib="esnext" />

import {
  createMCPOAuthHandler,
  MCPProviders,
  type MCPOAuthEnv,
  type MCPProvider,
  getMCPProviders,
} from "universal-mcp-oauth";

//@ts-ignore
import homepage from "./homepage.html";
//@ts-ignore
import directory from "./directory-template.html";
//@ts-ignore
import sampleData from "./sample.json";

import { UserDO, withSimplerAuth } from "./x-oauth-client-provider";

export { UserDO, MCPProviders };

export interface Env extends MCPOAuthEnv {
  UserDO: DurableObjectNamespace<UserDO>;
  CLIENT_ID: string;
  CLIENT_SECRET: string;
}

export default {
  fetch: withSimplerAuth(async (request, env, ctx) => {
    const url = new URL(request.url);

    // Handle MCP OAuth routes first
    if (url.pathname.startsWith("/mcp/")) {
      if (!ctx.user) {
        return new Response("Unauthorized", { status: 401 });
      }

      const mcpHandler = createMCPOAuthHandler({
        userId: ctx.user.x_user_id,
        baseUrl: url.origin,
      });

      const mcpResponse = await mcpHandler(request, env, ctx);
      if (mcpResponse) {
        return mcpResponse;
      }
    }

    // Redirect to login if no user for protected routes
    if (!ctx.user) {
      return new Response(null, {
        status: 302,
        headers: { Location: "/authorize" },
      });
    }

    const { user } = ctx;

    if (url.pathname === "/") {
      return handleLandingPage(user, env, url.origin);
    }

    if (url.pathname === "/directory") {
      return handleDirectory();
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

async function handleLandingPage(user: any, env: Env, origin: string) {
  let html = homepage;

  if (user) {
    // Get user's MCP providers using the new package
    const providers = await getMCPProviders(env, user.x_user_id);

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

function generateCurlExample(providers: MCPProvider[]) {
  const mcpServers = providers.map((provider) => {
    const server = {
      type: "url",
      url: provider.mcp_url,
      name: provider.name,
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
      server_label: provider.name,
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

  return `curl https://api.anthropic.com/v1/messages \\
  -H "Content-Type: application/json" \\
  -H "X-API-Key: $ANTHROPIC_API_KEY" \\
  -H "anthropic-version: 2023-06-01" \\
  -H "anthropic-beta: mcp-client-2025-04-04" \\
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
  
curl https://api.openai.com/v1/responses \\
  -H "Content-Type: application/json" \\
  -H "Authorization: Bearer $OPENAI_API_KEY" \\
  -d '{
  "model": "gpt-5",
  "tools": ${stringify(tools)},
  "input": "What transport protocols are supported in the 2025-03-26 version of the MCP spec?"
}'
`;
}
