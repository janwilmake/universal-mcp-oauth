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
export { MCPProviders };
import { withSimplerAuth, UserContext } from "simplerauth-client";

interface Env extends MCPOAuthEnv {
  PARALLEL_TASKS_MCP_KV: KVNamespace;
}

interface UserConfig {
  parallelApiKey?: string;
}

class UserDataInjector {
  constructor(private userData: any) {}

  element(element: Element) {
    if (element.tagName === "head") {
      element.append(
        `<script>window.userData = ${JSON.stringify(this.userData)
          .replace(/</g, "\\u003c")
          .replace(/>/g, "\\u003e")};</script>`,
        { html: true }
      );
    }
  }
}

export default {
  fetch: withSimplerAuth<Env>(async (request, env, ctx) => {
    const url = new URL(request.url);

    // Handle MCP OAuth routes first
    if (url.pathname.startsWith("/mcp/")) {
      if (!ctx.user) {
        return new Response("Unauthorized", { status: 401 });
      }

      const { getProviders, middleware, refreshProviders, removeMcp } =
        createMCPOAuthHandler(
          {
            userId: ctx.user.id,
            baseUrl: url.origin,
            clientInfo: {
              name: "Parallel Tasks",
              title: "Task Execution with MCPs",
              version: "1.0.0",
            },
          },
          env
        );

      const mcpResponse = await middleware(request, env, ctx);
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

      // Get existing config or create new one
      const configKey = `config:${ctx.user.id}`;
      const existingConfigJson = await env.PARALLEL_TASKS_MCP_KV.get(configKey);
      const existingConfig: UserConfig = existingConfigJson
        ? JSON.parse(existingConfigJson)
        : {};

      // Update with new API key
      const updatedConfig: UserConfig = {
        ...existingConfig,
        parallelApiKey: body.apiKey,
      };

      // Store updated config
      await env.PARALLEL_TASKS_MCP_KV.put(
        configKey,
        JSON.stringify(updatedConfig)
      );

      return new Response(JSON.stringify({ success: true }), {
        headers: { "Content-Type": "application/json" },
      });
    }

    // Handle task creation endpoint
    if (url.pathname === "/task" && request.method === "POST") {
      if (!ctx.user) {
        return new Response("Unauthorized", { status: 401 });
      }

      // Get API key from KV
      const configKey = `config:${ctx.user.id}`;
      const configJson = await env.PARALLEL_TASKS_MCP_KV.get(configKey);
      const config: UserConfig = configJson ? JSON.parse(configJson) : {};
      const apiKey = config.parallelApiKey;

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

      if (requestedProviders.length === 0) {
        return new Response(
          JSON.stringify({
            error: "Providers weren't found in users available providers",
          }),
          {
            status: 400,
            headers: { "Content-Type": "application/json" },
          }
        );
      }

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

      const json = {
        input: body.input,
        processor: "pro",
        mcp_servers: mcpServers,
      };

      console.log("json", json);
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
          body: JSON.stringify(json),
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

      // Get API key from KV
      const configKey = `config:${ctx.user.id}`;
      const configJson = await env.PARALLEL_TASKS_MCP_KV.get(configKey);
      const config: UserConfig = configJson ? JSON.parse(configJson) : {};
      const apiKey = config.parallelApiKey;

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

    const { user } = ctx;

    if (url.pathname === "/") {
      return handleLandingPage(user, env);
    }

    return new Response("Not found", { status: 404 });
  }),
};

async function handleLandingPage(
  user: UserContext["user"] | undefined,
  env: Env
) {
  const response = new Response(homepage, {
    headers: { "Content-Type": "text/html" },
  });

  if (user) {
    // Get user's MCP providers using the new package
    const providers = await getMCPProviders(env, user.id);

    // Get API key from KV
    const configKey = `config:${user.id}`;
    const configJson = await env.PARALLEL_TASKS_MCP_KV.get(configKey);
    const config: UserConfig = configJson ? JSON.parse(configJson) : {};
    const apiKey = config.parallelApiKey;

    const userData = { user, providers, apiKey };

    // Use HTMLRewriter to safely inject user data
    return new HTMLRewriter()
      .on("head", new UserDataInjector(userData))
      .transform(response);
  }

  return response;
}
