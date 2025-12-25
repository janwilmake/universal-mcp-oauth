# MCP Completions

Add MCP tool calling with OAuth authentication to any OpenAI-compatible LLM via a fetch proxy.

> **Note**: This library requires Cloudflare Workers with Durable Objects.

## Quick Start

```ts
import { chatCompletionsProxy, OAuthProviders } from "mcp-completions";
import { OpenAI } from "openai";

export { OAuthProviders };

export default {
  fetch: async (request, env, ctx) => {
    const { fetchProxy, idpMiddleware } = chatCompletionsProxy(env, {
      baseUrl: new URL(request.url).origin,
      userId: "your-user-id",
      clientInfo: { name: "My App", title: "My App", version: "1.0.0" },
    });

    // Handle OAuth callbacks
    const oauthResponse = await idpMiddleware(request, env, ctx);
    if (oauthResponse) return oauthResponse;

    const client = new OpenAI({
      apiKey: env.OPENAI_API_KEY,
      fetch: fetchProxy,
    });

    const stream = await client.chat.completions.create({
      model: "gpt-4o",
      stream: true,
      stream_options: { include_usage: true },
      messages: [{ role: "user", content: "What tools do you have?" }],
      tools: [
        { type: "mcp", server_url: "https://mcp.notion.com/mcp" },
        { type: "url_context", max_urls: 10 },
      ],
    });

    return new Response(stream.toReadableStream(), {
      headers: { "content-type": "text/event-stream" },
    });
  },
};
```

## Features

- **MCP Tools**: Discover and execute tools from any MCP server
- **Universal OAuth**: Automatic OAuth2 for APIs returning 401 with `WWW-Authenticate`
- **URL Context**: Fetch content from URLs in messages with stored auth
- **Shadow URLs**: Replace hostnames for better access (e.g., `github.com` → `uithub.com`)
- **Extract Fallback**: Convert HTML/PDF via configurable extract service
- **Cost Tracking**: Track additional costs in usage stats

## Configuration

```ts
chatCompletionsProxy(env, {
  baseUrl: "https://your-app.com",
  userId: "user-123",
  clientInfo: { name: "App", title: "App", version: "1.0.0" },

  // Optional: Replace hostnames for better content access
  shadowUrls: {
    "github.com": "uithub.com",
    "x.com": "xymake.com",
  },

  // Optional: Extract service for HTML/PDF
  extractUrl: {
    url: "https://extract.example.com",
    bearerToken: "your-api-key",
  },
});
```

## Wrangler Setup

```jsonc
{
  "durable_objects": {
    "bindings": [{ "name": "OAuthProviders", "class_name": "OAuthProviders" }]
  },
  "migrations": [{ "tag": "v1", "new_sqlite_classes": ["OAuthProviders"] }]
}
```

## Tool Types

### MCP Server

```ts
{ type: "mcp", server_url: "https://mcp.notion.com/mcp", require_approval: "never" }
```

### URL Context

```ts
{ type: "url_context", max_urls: 10, max_context_length: 1048576 }
```

## Documentation

- **[SDK Integrations](./docs/integrations.md)** - OpenAI, OpenRouter, Cloudflare AI Gateway, and more
- **[Creating a Shadow Site](./docs/creating-a-shadow-site.md)** - Build URL proxies with OAuth
- **[Creating an MCP Server](./docs/creating-an-mcp.md)** - Build MCP servers with compatible auth

## How It Works

1. Request with MCP tools hits the proxy
2. Proxy checks for stored OAuth tokens
3. If missing, returns login links in the stream
4. Once authenticated, discovers tools and translates to OpenAI functions
5. Executes tool calls and streams results back

## Demo

https://demo.connectconnector.com
