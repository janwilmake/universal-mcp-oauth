Add MCP-Tool calling and tool execution **with authentication** to any LLM via a simple fetch-proxy

```ts
const result = await new OpenAI({ fetch: fetchProxy }).chat.completions.create({
  // magically will ensure mcps are authenticated!
  tools: [{ type: "mcp", url: "https://mcp.notion.com/mcp" }] as any,
  // other stuff
});
```

If the MCP server requires authentication, you should get a response with a markdown login link. Once authenticated, the tools will execute automatically and their results will appear as markdown in the assistant's response stream.

# Installation & Usage

```
npm i mcpidp-completions
```

Usage:

> [!TIP]
> Don't rely on this yet, breaking changes imminent!

See [demo.ts](demo.ts)

Demo live at: https://completions.mcpidp.com

# TODO

🤔 Is this the right abstraction, or is it more useful to have a separate resource idp (maybe even protocol agnostic, just oauth2.1) and then automatically provide and keep up-to-date the access tokens before calling the MCP endpoint?

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

    const result = await new OpenAI({
      fetch: fetchProxy,
      apiKey,
    }).chat.completions.create({
      messages: [
        // stuff
      ],
      model: "gpt-5",
      tools: [{ type: "mcp", url: "https://mcp.notion.com/mcp" }] as any,
    });
  },
};
```

- Instruct users to use `const client = new OpenAI({fetch,basePath,apiKey})`

# Other useful exploration

- Allow simplifying the response into text-only (reduce from reasoning, error messages, tool data, etc etc)
- Build a CLI that has the frontmatter
- A tool to search MCPs and continue the chat with different MCPs

## Stateful chat completions with callbacks

- Allow for long-running MCP tools (in the same way as [this SEP](https://github.com/modelcontextprotocol/modelcontextprotocol/issues/1391)) - this makes this stateful though so may need to be done in a different place!
- Ability to hold running the API waiting for a human to authorize, then continue fulfilling the request after that's solved. Potentially, a parameter `authorizationRequestCallback:URL` could be added, which would send the authorization request (just an url and message) to that endpoint, with the same secret. That endpoint could then send email, wapp, or notify in UI.
- Expose chat completions as async MCP tool with oauth (basically a sub-agent!)
