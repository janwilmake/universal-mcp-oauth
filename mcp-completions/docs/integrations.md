# SDK Integrations

> **Important**: This library is designed for Cloudflare Workers and requires Cloudflare's Durable Objects for OAuth state management.

The `mcp-completions` package provides a fetch proxy that intercepts chat completion requests and adds MCP tool support with OAuth authentication. This proxy can be used with any SDK that allows custom fetch implementations.

## OpenAI SDK

The OpenAI SDK supports a custom `fetch` option, making integration straightforward:

```ts
import { chatCompletionsProxy, OAuthProviders } from "mcp-completions";
import { OpenAI } from "openai";

export { OAuthProviders };

export default {
  fetch: async (request: Request, env: Env, ctx: ExecutionContext) => {
    const { fetchProxy, idpMiddleware } = chatCompletionsProxy(env, {
      baseUrl: new URL(request.url).origin,
      userId: "your-user-id",
      clientInfo: {
        name: "My App",
        title: "My App",
        version: "1.0.0",
      },
    });

    // Handle OAuth callbacks first
    const oauthResponse = await idpMiddleware(request, env, ctx);
    if (oauthResponse) return oauthResponse;

    // Create OpenAI client with proxy
    const client = new OpenAI({
      baseURL: "https://api.openai.com/v1",
      apiKey: env.OPENAI_API_KEY,
      fetch: fetchProxy, // Use the proxy fetch
    });

    const stream = await client.chat.completions.create({
      model: "gpt-4o",
      stream: true,
      stream_options: { include_usage: true },
      messages: [{ role: "user", content: "Hello!" }],
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

## OpenRouter

OpenRouter uses an OpenAI-compatible API, so integration is identical:

```ts
import { chatCompletionsProxy, OAuthProviders } from "mcp-completions";
import { OpenAI } from "openai";

export { OAuthProviders };

export default {
  fetch: async (request: Request, env: Env, ctx: ExecutionContext) => {
    const { fetchProxy, idpMiddleware } = chatCompletionsProxy(env, {
      baseUrl: new URL(request.url).origin,
      userId: "your-user-id",
      clientInfo: {
        name: "My App",
        title: "My App",
        version: "1.0.0",
      },
    });

    const oauthResponse = await idpMiddleware(request, env, ctx);
    if (oauthResponse) return oauthResponse;

    // Use OpenRouter's base URL
    const client = new OpenAI({
      baseURL: "https://openrouter.ai/api/v1",
      apiKey: env.OPENROUTER_API_KEY,
      fetch: fetchProxy,
      defaultHeaders: {
        "HTTP-Referer": "https://your-site.com",
        "X-Title": "Your App Name",
      },
    });

    const stream = await client.chat.completions.create({
      model: "anthropic/claude-3.5-sonnet",
      stream: true,
      stream_options: { include_usage: true },
      messages: [{ role: "user", content: "Hello!" }],
      tools: [{ type: "mcp", server_url: "https://mcp.linear.app/mcp" }],
    });

    return new Response(stream.toReadableStream(), {
      headers: { "content-type": "text/event-stream" },
    });
  },
};
```

## Cloudflare AI Gateway

Cloudflare AI Gateway can proxy requests to various LLM providers. Use the gateway URL as your base URL:

```ts
import { chatCompletionsProxy, OAuthProviders } from "mcp-completions";
import { OpenAI } from "openai";

export { OAuthProviders };

export default {
  fetch: async (request: Request, env: Env, ctx: ExecutionContext) => {
    const { fetchProxy, idpMiddleware } = chatCompletionsProxy(env, {
      baseUrl: new URL(request.url).origin,
      userId: "your-user-id",
      clientInfo: {
        name: "My App",
        title: "My App",
        version: "1.0.0",
      },
    });

    const oauthResponse = await idpMiddleware(request, env, ctx);
    if (oauthResponse) return oauthResponse;

    // Use Cloudflare AI Gateway URL
    // Format: https://gateway.ai.cloudflare.com/v1/{account_id}/{gateway_slug}/openai
    const client = new OpenAI({
      baseURL: `https://gateway.ai.cloudflare.com/v1/${env.CF_ACCOUNT_ID}/${env.CF_GATEWAY_SLUG}/openai`,
      apiKey: env.OPENAI_API_KEY,
      fetch: fetchProxy,
    });

    const stream = await client.chat.completions.create({
      model: "gpt-4o",
      stream: true,
      stream_options: { include_usage: true },
      messages: [{ role: "user", content: "Hello!" }],
      tools: [{ type: "mcp", server_url: "https://task-mcp.parallel.ai/mcp" }],
    });

    return new Response(stream.toReadableStream(), {
      headers: { "content-type": "text/event-stream" },
    });
  },
};
```

## Direct Fetch Usage

You can also use the proxy directly without an SDK:

```ts
import { chatCompletionsProxy, OAuthProviders } from "mcp-completions";

export { OAuthProviders };

export default {
  fetch: async (request: Request, env: Env, ctx: ExecutionContext) => {
    const { fetchProxy, idpMiddleware } = chatCompletionsProxy(env, {
      baseUrl: new URL(request.url).origin,
      userId: "your-user-id",
      clientInfo: {
        name: "My App",
        title: "My App",
        version: "1.0.0",
      },
    });

    const oauthResponse = await idpMiddleware(request, env, ctx);
    if (oauthResponse) return oauthResponse;

    // Use fetchProxy directly
    return fetchProxy("https://api.openai.com/v1/chat/completions", {
      method: "POST",
      headers: {
        Authorization: `Bearer ${env.OPENAI_API_KEY}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        model: "gpt-4o",
        stream: true,
        stream_options: { include_usage: true },
        messages: [{ role: "user", content: "Hello!" }],
        tools: [{ type: "mcp", server_url: "https://mcp.notion.com/mcp" }],
      }),
    });
  },
};
```

## Any OpenAI-Compatible Provider

The proxy works with any provider that implements the OpenAI chat completions API:

- **Groq**: `https://api.groq.com/openai/v1`
- **Together AI**: `https://api.together.xyz/v1`
- **Anyscale**: `https://api.endpoints.anyscale.com/v1`
- **Perplexity**: `https://api.perplexity.ai`
- **Fireworks**: `https://api.fireworks.ai/inference/v1`

Simply change the `baseURL` to point to your preferred provider.

## Requirements

This library requires:

1. **Cloudflare Workers** runtime environment
2. **Durable Objects** binding for OAuth state (`OAuthProviders`)
3. **Stream mode** must be enabled (`stream: true`)

### Wrangler Configuration

```jsonc
// wrangler.jsonc
{
  "durable_objects": {
    "bindings": [{ "name": "OAuthProviders", "class_name": "OAuthProviders" }]
  },
  "migrations": [
    {
      "tag": "v1",
      "new_sqlite_classes": ["OAuthProviders"]
    }
  ]
}
```