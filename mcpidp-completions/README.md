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

- ✅ Create a simple HTML frontend.
- 🤔 The API can only be used when we have the same X User ID as what the user gets when logging in here for a tool and this is NOT guaranteed, unless we actually teach developers of this API to use the oauth provider first to get the X user ID. IDK if this is the preferred way of doing things. ✅ make it a cloudflare middleware that works with any oauth!
- ✅ Do not support any `require_approval` other than `never`
- ✅ Do not succeed if `stream:true` not provided
- ✅ Better logging when MCP doesn't succeed and has error.
- ✅ Fix why linear/notion don't work
- 🤔 It was very slow because we kept the SSE Stream open. Should be closed after receiving response!
- ✅ Much faster now!
- Chat completions response stream should add event with MCP details (see if this is standardized or not)
- Create a way for users to manage their logged in MCPs so they can also re-scope it (not part of the middleware though, just provide as easy documented APIs)
- Ensure the Oauth Callback page is set to a success page that says "You've authorized using this MCP" or something.
- Explore the best way to provide the tool response event. Ideally it's not in the markdown, but more details are provided in a standardized way.
- Improve the API.

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
