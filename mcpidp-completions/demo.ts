import { OpenAI } from "openai";
import { withSimplerAuth } from "simplerauth-client";
import {
  ChatCompletionRequest,
  chatCompletionsMiddleware,
  MCPProviders,
} from "./user-chat-completion";

import { createMCPOAuthHandler, MCPOAuthEnv } from "universal-mcp-oauth";
import { ChatCompletionTool } from "openai/resources/index.mjs";
export { MCPProviders };

export default {
  fetch: withSimplerAuth(
    async (request, env, ctx) => {
      const url = new URL(request.url);

      if (url.pathname.startsWith("/mcp/")) {
        const mcpOAuthHandler = createMCPOAuthHandler({
          userId: ctx.user.id,
          clientInfo: {
            name: "MCP Chat Proxy",
            title: "MCP Chat Completions Proxy",
            version: "1.0.0",
          },
          baseUrl: url.origin,
        });

        const mcpResponse = await mcpOAuthHandler(
          request,
          env as MCPOAuthEnv,
          ctx
        );

        if (mcpResponse) {
          return mcpResponse;
        }
      }

      // Parse hostname and path
      const pathSegments = url.pathname.split("/").filter(Boolean);

      if (pathSegments.length < 2) {
        return new Response(
          "Path should be /{hostnameAndPrefix}/chat/completions",
          { status: 400 }
        );
      }

      const targetHostname = pathSegments[0];
      const remainingPath = "/" + pathSegments.slice(1).join("/");

      if (!remainingPath.endsWith("/chat/completions")) {
        return new Response("Only /chat/completions endpoints are supported", {
          status: 404,
        });
      }

      if (request.method !== "POST") {
        return new Response("Method Not Allowed", { status: 405 });
      }

      const llmApiKey = request.headers.get("X-LLM-API-KEY");
      if (!llmApiKey) {
        return new Response("x-llm-api-key not provided", { status: 400 });
      }

      const llmEndpoint = `https://${targetHostname}${remainingPath}`;
      const body: ChatCompletionRequest = await request.json();
      const userId = ctx.user.id;

      const headers = {
        Authorization: `Bearer ${llmApiKey}`,
        "Content-Type": "application/json",
      };

      if (!userId) {
        return new Response("Missing required user field in request body", {
          status: 400,
        });
      }

      return chatCompletionsMiddleware(request, env, ctx, {
        body,
        userId,
        llmEndpoint,
        headers,
      });
    },
    { isLoginRequired: true }
  ),
};
