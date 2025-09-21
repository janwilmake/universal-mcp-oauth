import { type MCPOAuthEnv, MCPProviders } from "universal-mcp-oauth";
import { withSimplerAuth } from "simplerauth-client";
export { MCPProviders };
import {
  ChatCompletionRequest,
  userChatCompletion,
} from "./user-chat-completion";

export default {
  fetch: withSimplerAuth<MCPOAuthEnv>(
    async (request, env, ctx) => {
      const url = new URL(request.url);
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

      const targetUrl = `https://${targetHostname}${remainingPath}`;
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

      return userChatCompletion(
        request,
        env,
        ctx,
        {
          name: "MCP Chat Proxy",
          title: "MCP Chat Completions Proxy",
          version: "1.0.0",
        },
        headers,
        body,
        userId,
        targetUrl
      );
    },
    { isLoginRequired: true }
  ),
};
