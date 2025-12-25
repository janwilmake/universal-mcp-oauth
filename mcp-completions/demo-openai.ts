import { chatCompletionsProxy, OAuthProviders } from "./mcp-completions";
import { OpenAI } from "openai";

// Export DO for Cloudflare Workers
export { OAuthProviders };

export default {
  fetch: async (
    request: Request,
    env: { OPENAI_API_KEY: string },
    ctx: ExecutionContext,
  ) => {
    const { fetchProxy, idpMiddleware, getProviders, removeMcp } =
      chatCompletionsProxy(env, {
        baseUrl: new URL(request.url).origin,
        userId: "admin", // Your user ID from your auth system
        clientInfo: {
          name: "My App",
          title: "My App",
          version: "1.0.0",
        },
      });

    const url = new URL(request.url);
    if (url.pathname === "/providers") {
      const providers = await getProviders();
      return new Response(JSON.stringify(providers, null, 2));
    }

    // Handle OAuth callbacks
    const middlewareResponse = await idpMiddleware(request, env, ctx);
    if (middlewareResponse) {
      return middlewareResponse;
    }

    const client = new OpenAI({
      baseURL: "https://api.openai.com/v1",
      apiKey: env.OPENAI_API_KEY,
      fetch: fetchProxy,
    });

    const stream = await client.chat.completions.create({
      messages: [{ role: "user", content: "What tools do you have?" }],
      stream: true,
      stream_options: { include_usage: true },
      model: "gpt-5",
      tools: [
        // MCP servers with OAuth
        { type: "mcp", server_url: "https://mcp.notion.com/mcp" },
        // URL context - fetches URLs from messages with stored auth
        // { type: "url_context", max_urls: 10 },
      ] as any,
    });

    return new Response(stream.toReadableStream(), {
      headers: { "content-type": "text/event-stream;charset=utf8" },
    });
  },
};
