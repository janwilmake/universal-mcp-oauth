// how to use this as a package, basically with any userId provided on backend too?
import {
  createMCPOAuthHandler,
  getMCPProviders,
  getAuthorization,
  type MCPOAuthEnv,
  MCPProviders,
} from "universal-mcp-oauth";
import { withSimplerAuth } from "simplerauth-client";
export { MCPProviders };
import {
  ChatCompletionRequest,
  userChatCompletion,
} from "./user-chat-completion";

export default {
  async fetch(
    request: Request,
    env: MCPOAuthEnv,
    ctx: ExecutionContext
  ): Promise<Response> {
    const url = new URL(request.url);

    // Handle MCP OAuth flows first
    if (!url.pathname.endsWith("/chat/completions")) {
      const handler = withSimplerAuth<MCPOAuthEnv>(
        async (request, env, ctx) => {
          const mcpOAuthHandler = createMCPOAuthHandler({
            userId: ctx.user.id,
            clientInfo: {
              name: "MCP Chat Proxy",
              title: "MCP Chat Completions Proxy",
              version: "1.0.0",
            },
            baseUrl: url.origin,
          });

          const mcpResponse = await mcpOAuthHandler(request, env, ctx);
          if (mcpResponse) {
            return mcpResponse;
          }

          return new Response("Not found", { status: 404 });
        },
        { isLoginRequired: true }
      );

      return handler(request, env, ctx);
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

    const targetUrl = `https://${targetHostname}${remainingPath}`;
    const body: ChatCompletionRequest = await request.json();
    const userId = body.user;

    const headers = {
      Authorization: request.headers.get("Authorization"),
      "Content-Type": "application/json",
    };

    return userChatCompletion(
      env,
      headers,
      url.origin,
      body,
      userId,
      targetUrl
    );
  },
};
