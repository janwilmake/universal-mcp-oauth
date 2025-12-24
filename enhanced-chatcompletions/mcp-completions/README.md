# MCP Completions

Add MCP-Tool calling and tool execution **with authentication** to any LLM via a simple fetch-proxy.

## Features

- **Universal OAuth**: Automatically handles OAuth2 authentication for any API that returns 401 with proper `WWW-Authenticate` headers
- **MCP Support**: Full support for MCP (Model Context Protocol) servers with tool discovery and execution
- **URL Context**: Automatically fetches content from URLs in user messages, with authentication support
- **Provider Matching**: Stores authentication at the most generic resource level and matches to more specific URLs

## Usage

```ts
import { chatCompletionsProxy, OAuthProviders } from "mcp-completions";
import { OpenAI } from "openai";

// Export DO for Cloudflare Workers
export { OAuthProviders };

export default {
  fetch: async (request, env, ctx) => {
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
      model: "gpt-4",
      tools: [
        // MCP servers with OAuth
        { type: "mcp", server_url: "https://mcp.notion.com/mcp" },
        // URL context - fetches URLs from messages with stored auth
        { type: "url_context", max_urls: 10 },
      ] as any,
    });

    return new Response(stream.toReadableStream(), {
      headers: { "content-type": "text/event-stream;charset=utf8" },
    });
  },
};
```

## How Authentication Works

1. When a request returns 401, the library parses the `WWW-Authenticate` header
2. Discovers the authorization server via protected resource metadata or `.well-known`
3. Performs dynamic client registration
4. Redirects user to authorize
5. Stores tokens at the **most generic resource URL** that makes sense

For example, if you authenticate with `https://api.example.com/v1/users`, the token might be stored at `https://api.example.com` (depending on the resource server's configuration). This way, subsequent requests to `https://api.example.com/v1/posts` will automatically use the same credentials.

## URL Context Tool

The `url_context` tool automatically:

1. Extracts URLs from user messages
2. Fetches their content with stored authentication
3. Prepends the content as context for the LLM

This works great with the universal OAuth - if you've authenticated with an API before, the URL context fetcher will automatically use those credentials.

## Architecture

- `universal-oauth.ts` - Generic OAuth2 handling for any protected resource
- `mcp-oauth.ts` - MCP-specific layer using universal OAuth
- `mcp-completions.ts` - Chat completions proxy with tool execution

Demo: https://demo.connectconnector.com
