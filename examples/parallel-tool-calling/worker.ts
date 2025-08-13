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

import { UserDO, withSimplerAuth } from "x-oauth-client-provider";

interface UserContext<T = { [key: string]: any }> extends ExecutionContext {
  /** Should contain authenticated X User */
  user:
    | {
        id: string;
        name: string;
        username: string;
        profile_image_url?: string;
        verified?: boolean;
      }
    | undefined;
  /** X Access token */
  xAccessToken: string | undefined;
  /** Access token. Can be decrypted with client secret to retrieve X access token */
  accessToken: string | undefined;
  registered: boolean;
  getMetadata?: () => Promise<T>;
  setMetadata?: (metadata: T) => Promise<void>;
}
export { UserDO, MCPProviders };

export interface Env extends MCPOAuthEnv {
  UserDO: DurableObjectNamespace<UserDO>;
  CLIENT_ID: string;
  CLIENT_SECRET: string;
}

export default {
  fetch: withSimplerAuth(async (request, env, ctx: UserContext) => {
    const url = new URL(request.url);

    // Handle MCP OAuth routes first
    if (url.pathname.startsWith("/mcp/")) {
      if (!ctx.user) {
        return new Response("Unauthorized", { status: 401 });
      }

      const mcpHandler = createMCPOAuthHandler({
        userId: ctx.user.id,
        baseUrl: url.origin,
      });

      const mcpResponse = await mcpHandler(request, env, ctx);
      if (mcpResponse) {
        return mcpResponse;
      }
    }

    // Handle API key endpoint
    if (url.pathname === "/set-api-key" && request.method === "POST") {
      if (!ctx.user) {
        return new Response("Unauthorized", { status: 401 });
      }

      const body = (await request.json()) as { apiKey: string };
      const metadata = (await ctx.getMetadata?.()) || {};
      metadata.parallelApiKey = body.apiKey;
      await ctx.setMetadata?.(metadata);

      return new Response(JSON.stringify({ success: true }), {
        headers: { "Content-Type": "application/json" },
      });
    }

    // Handle task creation endpoint
    if (url.pathname === "/task" && request.method === "POST") {
      if (!ctx.user) {
        return new Response("Unauthorized", { status: 401 });
      }

      const metadata = (await ctx.getMetadata?.()) || {};
      const apiKey = metadata.parallelApiKey;

      if (!apiKey) {
        return new Response(JSON.stringify({ error: "No API key set" }), {
          status: 400,
          headers: { "Content-Type": "application/json" },
        });
      }

      const body = (await request.json()) as {
        mcpUrls: string[];
        input: string;
      };

      // Get user's MCP providers
      const allProviders = await getMCPProviders(env, ctx.user.id);
      const requestedProviders = allProviders.filter((p) =>
        body.mcpUrls.includes(p.mcp_url)
      );

      // Build MCP servers array for Parallel API
      const mcpServers = requestedProviders.map((provider) => {
        const server: any = {
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

      // Call Parallel API
      const parallelResponse = await fetch(
        "https://api.parallel.ai/v1/tasks/runs",
        {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            "x-api-key": apiKey,
            "parallel-beta": "mcp-server-2025-07-17",
          },
          body: JSON.stringify({
            input: body.input,
            processor: "base",
            mcp_servers: mcpServers,
          }),
        }
      );

      if (!parallelResponse.ok) {
        const error = await parallelResponse.text();
        return new Response(
          JSON.stringify({ error: `Parallel API error: ${error}` }),
          {
            status: parallelResponse.status,
            headers: { "Content-Type": "application/json" },
          }
        );
      }

      const result = await parallelResponse.json();

      return new Response(null, {
        status: 302,
        headers: { Location: `/poll?id=${result.run_id}` },
      });
    }

    // Handle polling endpoint
    if (url.pathname === "/poll") {
      if (!ctx.user) {
        return new Response("Unauthorized", { status: 401 });
      }

      const runId = url.searchParams.get("id");
      if (!runId) {
        return new Response("Missing run ID", { status: 400 });
      }

      const metadata = (await ctx.getMetadata?.()) || {};
      const apiKey = metadata.parallelApiKey;

      if (!apiKey) {
        return new Response("No API key set", { status: 400 });
      }

      // Call Parallel API to get result
      const parallelResponse = await fetch(
        `https://api.parallel.ai/v1/tasks/runs/${runId}/result?timeout=600`,
        {
          method: "GET",
          headers: {
            "x-api-key": apiKey,
          },
        }
      );

      if (!parallelResponse.ok) {
        const error = await parallelResponse.text();
        return new Response(`Parallel API error: ${error}`, {
          status: parallelResponse.status,
        });
      }

      const result = await parallelResponse.json();

      return new Response(JSON.stringify(result, null, 2), {
        headers: { "Content-Type": "application/json" },
      });
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
      return handleLandingPage(user, env, url.origin, ctx);
    }

    return new Response("Not found", { status: 404 });
  }),
} satisfies ExportedHandler<Env>;

async function handleLandingPage(
  user: UserContext["user"],
  env: Env,
  origin: string,
  ctx: UserContext
) {
  let html = homepage;

  if (user) {
    // Get user's MCP providers using the new package
    const providers = await getMCPProviders(env, user.id);
    const metadata = (await ctx.getMetadata?.()) || {};

    const userData = {
      user,
      providers,
      hasApiKey: !!metadata.parallelApiKey,
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
