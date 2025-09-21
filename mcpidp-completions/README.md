Here's a curl command to test your MCP chat proxy:

```bash
curl -X POST "https://completions.mcpidp.com/api.openai.com/v1/chat/completions" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer YOUR_OPENAI_API_KEY" \
  -d '{
    "model": "gpt-4.1-2025-04-14",
    "user": "your X userID",
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

# TODO

- ✅ Create a simple HTML frontend.
- 🤔 The API can only be used when we have the same X User ID as what the user gets when logging in here for a tool and this is NOT guaranteed, unless we actually teach developers of this API to use the oauth provider first to get the X user ID. IDK if this is the preferred way of doing things.
- Ensure the Oauth Callback page is set to a success page that says "You've authorized using this MCP" or something.

# IDEA

Thought:

The main thing that the chat-completions IDP proxy should have is the ability to hold running the API waiting for a human to authorize, then continue fulfilling the request after that's solved. Potentially, a parameter `authorizationRequestCallback:URL` could be added, which would send the authorization request (just an url and message) to that endpoint, with the same secret. That endpoint could then send email, wapp, or notify in ui.

# Moonshot: IdP-chat-completions proxy!!!

- oauth client & provider with X Login and usage-based stripe balance
- regular `/chat/completions with { tools: {type:"mcp",url:"MCP URL"}[], user: "stable-user-id" }`
- proxy to provider that supports MCP
- `/mcp` that responds with markdown result
- This server manages auth of users. If a tool requires auth, chat-completions endpoint would return 401 with message and custom header. MCP would respond with login info markdown in the response directly.

This is huge because it allows any app using `/chat/completions` to use infinite MCPs. A bonus would be to provide a configuration to allow specifying the MCPs as part of the input message! Same goes for URLs inside of the input message, ultimately that should also be possible.

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

# Get this in lmpify

Blocked by:

- Chat completions IDP Proxy
- Ability to make results private (or just make URL longer if mcps were used!)

# MCP Use

I can now already turn https://flaredream.com/system.md into an MCP, albeit with manual auth. Post about it?

First MCPs I want:

- **Iterate Agent** `deploy` tool at the end: `deploy.flaredream.com/download.flaredream.com/id` for Flaredreams initial generation, using `deploy` tool after it's done (deploy tool must have access to intermediate result)
- **Feedback agent** for Testing a flaredream deployment (`test(evaloncloudID,request,criteria)=>feedback` tool that processes request into feedback, and `final_feedback(feedback, replace_feedback:boolean, status: "ok"|"fail"|"retry")` will end the agent)

This is a great first milestone having the 2 MCPs separately. With this I can verify manually if this works. After that, a looping agent can use both in a loop!

Tools:

```ts
type Tool = {
  /**The type of the MCP tool. Always mcp.*/
  type: "mcp";
  /** A label for this MCP server, used to identify it in tool calls. */
  server_label: string;
  /** The URL for the MCP server. */
  server_url: string;
  allowed_tools?: { tool_names: string[] };
  /** Optional HTTP headers to send to the MCP server. Use for authentication or other purposes.*/
  headers?: { [key: string]: string };
  require_approval?:
    | "always"
    | "never"
    | { always?: { tool_names?: string[] }; never?: { tool_names?: string[] } };
  server_description?: string;
};
```

MCP implementations that are already there:

- https://docs.anthropic.com/en/api/messages#body-mcp-servers
- https://platform.openai.com/docs/api-reference/responses/create#responses-create-tools

This means in order to add MCP support to LMPIFY, I could choose to do it for just the models that support it, rather than making my own tools to MCP adaptor. Another important question is: are generations always stored publicly, even if you use authenticated MCPs? This might be problematic.

It is assumable that there will be other aggregators that allow mcp execution for any provider. It is also assumable that more providers like groq and xai will follow with MCP as tool, and it's possible that openai will add mcp tools to /chat/completions.

However, I COULD also choose to implement the ability to pass MCP server(s) in a config, pass them as tools to the chat-completion endpoint, and execute them myself. This would need to be done for both /chat/completions as well as for the StreamDO.

Other scenarios that need work:

- Ability to configure MCP URL and perform OAuth from within UI where it stores auth on a per-url basis into localStorage. This requires making a POC first (possibly with dynamic client registration etc)
- Ability to configure MCP tools in /chat/completions with X-MCP-Authorization in header
- Ability to create a /chat/completions AND /mcp endpoint that uses an MCP as tools. The OAuth of it should perform 2 steps, gathering both the downstream MCP OAuth as well as the user itself

For now I decide to go for the simplest approach that directly allows for creating my agent without complex mappings, and use things just in Anthropic.

**[STEP 1]** Allow using Anthropic MCP functionality everywhere:

- Create `handleAnthropicAsChatCompletion` (maybe take from what I made before and add `tools[].type=mcp`)
- Create conversion from tools [type:mcp] property to the format of anthropic (https://docs.anthropic.com/en/api/messages#body-mcp-servers)
- Make sure `handleChatCompletions` uses the above for anthropic.
- Do not support any `require_approval` other than `never`
- Do not support for any provider that does not have `mcp:true`
- Use `handleChatCompletions` inside of the `StreamDO` to avoid code duplication.
- Do not support mcp tools icm with `store:true`

Now, I should be able to use an MCP server in the `/{id}/chat/completions` endpoint by passing mcp configs as tools. Test this first!

**[STEP 2]** MCP in Streamer

- Add `mcp_url` and `mcp_authorization` to POST FormData to allow a single MCP tool from there too.
- Ensure to properly handle MCP use responses in the StreamDO so it can be formatted into nice-looking markdown (using `>`)

**[STEP 3]** Deployment MCP

- ✅ Improve cloudflare provider, create `login-with-cloudflare` package.
- Use that in https://deploy.flaredream.com and make it an MCP using `withMcp`
- Use deploy.flaredream.com/mcp as MCP tool with flaredream LMPIFY FormData stream, from within flaredreams landingpage. This requires login with Cloudflare as well as my personal API key for LMPIFY (for now)

I should now be able to start the entire request from flaredream.com, and let users look into the response if they want to (but not require that). I can now just add XMoney to flaredream and use XYText as interface.

Idea - allow context of the generation to include MCP urls! This way the tools used become part of the definition. Logical! Imagine having a tweet MCP, all it'd take would be something like this:

```md
https://xymake.com/mcp

Hey, this is a tweet. It can literally just be understood one on one
```

# Lay-out & UX

✅ It seems that the UI doesn't always properly handle errors. E.g. when claude is down sometimes, I'm getting just a blank screen, rather than a red error.

Does it make sense to allow setting the model with frontmatter, overwriting whatever state is in lmpify? Would be cool! Should

E.g.

```
---
model: lmpify/flaredream
tools: https://deploy.flaredream.com/mcp
---
```

Frontmatter, if present, would always be removed from the prompt. It could also allow for tools this way (running it would first redirect to login if mcp isn't authenticated yet)
