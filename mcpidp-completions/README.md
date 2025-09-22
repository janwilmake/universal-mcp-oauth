Add MCP-Tool calling with authentication to any LLM.

# Installation & Usage

```
npm i mcpidp-completions
```

Usage

```ts
// or use any other authentication mechanism!
import { withSimplerAuth } from "simplerauth-client";
import {
  ChatCompletionRequest,
  MCPIDPMiddleware,
  MCPProviders,
} from "mcpidp-completions";
// export durable object
export { MCPProviders };

export default {
  fetch: withSimplerAuth(
    async (request, env, ctx) => {
      return MCPIDPMiddleware(request, env, ctx, {
        body: {
          messages: [{ role: "user", content: "Hi!" }],
        },
        userId: ctx.user.id,
        llmEndpoint: `https://api.openai.com/v1/chat/completions`,
        headers: {
          Authorization: `Bearer ${env.LLM_API_KEY}`,
          "Content-Type": "application/json",
        },
        clientInfo: {
          name: "MCP Chat Proxy",
          title: "MCP Chat Completions Proxy",
          version: "1.0.0",
        },
      });
    },
    { isLoginRequired: true }
  ),
};
```

# Example

Demo live at: https://completions.mcpidp.com

Here's a curl command to test:

```bash
curl -X POST "https://completions.mcpidp.com/api.openai.com/v1/chat/completions" \
  -H "Content-Type: application/json" \
  -H "X-LLM-API-KEY: YOUR_OPENAI_API_KEY" \
  -d '{
    "model": "gpt-4.1-2025-04-14",
    "stream": true,
    "messages": [
      {
        "role": "user",
        "content": "Search for information about Cloudflare Workers"
      }
    ],
    "tools": [
      {
        "type": "mcp",
        "server_url": "https://search-mcp.parallel.ai/mcp"
      }
    ]
  }'
```

Replace `YOUR_OPENAI_API_KEY` with your actual OpenAI API key.

This will:

1. Route to `completions.mcpidp.com` with hostname `api.openai.com`
2. Use `test-user-123` as the stable user ID for MCP authentication
3. Include the MCP tool for the search server
4. Stream the response with automatic tool execution converted to markdown

If the MCP server requires authentication, you should get a response with a markdown login link. Once authenticated, the tools will execute automatically and their results will appear as markdown in the assistant's response stream.

```ts
type Tool = {
  /**The type of the MCP tool. Always mcp.*/
  type: "mcp";
  /** The URL for the MCP server. */
  server_url: string;
  allowed_tools?: { tool_names: string[] };
  require_approval?: "never";
};
```

# TODO

- Create a way for users to manage their logged in MCPs so they can also re-scope it (not part of the middleware though, just provide as easy documented APIs)
- Add in token refresh functionality into `universal-mcp-oauth` and refresh tokens asynchronously when starting the stream.
- Ensure the Oauth Callback page is set to a success page that says "You've authorized using this MCP" or something.

🤔 How to host this? Should it always used as hosted worker, or can `/chat/completions` be a fetch proxy function? Is hosted good since it allows using OpenAI SDK?

```ts
export default {
  fetch: async (request, env, ctx) => {
    // Just use mcps without auth and it'll just work!
    const { fetchProxy, middleware } = await chatCompletionsProxy(
      request,
      env,
      ctx
    );

    const middlewareResponse = await middleware(request, env, ctx);
    if (middlewareResponse) {
      return middlewareResponse;
    }

    const client = new OpenAI({ fetch: fetchProxy });
    const result = await client.chat.completions.create({
      messages: [],
      model: "gpt-5",
      tools: [{ type: "mcp", url: "https://mcp.notion.com/mcp" }] as any,
    });
  },
};
```

- Instruct users to use `const client = new OpenAI({fetch,basePath,apiKey})` with `const mcpToolProxy

🤔 Is this the right abstraction, or is it more useful to have a separate resource idp (maybe even protocol agnostic, just oauth2.1) and then automatically provide and keep up-to-date the access tokens before calling the MCP endpoint?

🤔 Look how long MCP init takes when immediately breaking up and when not. If it's useful/possible, reuse the session from the discovery to speed things up!

# Other useful exploration

- Allow simplifying the response into text-only (reduce from reasoning, error messages, tool data, etc etc)
- Build a CLI that has the frontmatter
- A tool to search MCPs and continue the chat with different MCPs

## Stateful chat completions with callbacks

- Allow for long-running MCP tools (in the same way as [this SEP](https://github.com/modelcontextprotocol/modelcontextprotocol/issues/1391)) - this makes this stateful though so may need to be done in a different place!
- Ability to hold running the API waiting for a human to authorize, then continue fulfilling the request after that's solved. Potentially, a parameter `authorizationRequestCallback:URL` could be added, which would send the authorization request (just an url and message) to that endpoint, with the same secret. That endpoint could then send email, wapp, or notify in UI.
- Expose chat completions as async MCP tool with oauth (basically a sub-agent!)
