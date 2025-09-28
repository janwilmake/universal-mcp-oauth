Add MCP-Tool calling and tool execution **with authentication** to any LLM via a simple fetch-proxy

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

    const client = new OpenAI({
      basePath: "https://api.openai.com/v1",
      fetch: fetchProxy,
      apiKey,
    });
    const result = await client.chat.completions.create({
      messages: [
        // stuff
      ],
      model: "gpt-5",
      tools: [{ type: "mcp", url: "https://mcp.notion.com/mcp" }] as any,
    });
  },
};
```

If the MCP server requires authentication, you should get a response with a markdown login link. Once authenticated, the tools will execute automatically and their results will appear as markdown in the assistant's response stream.

# Installation & Usage

```
npm i mcp-completions
```

Usage:

> [!TIP]
> Don't rely on this yet, breaking changes imminent!

See [demo.ts](../mcp-completions-demo/demo.ts)

Demo live at: https://completions.mcpidp.com

# TODO

## 1) Add this to LMPIFY:

- ✅ Deploy as package `mcp-completions`
- Test and confirm that usage event works properly
- For anthropic, use https://docs.claude.com/en/api/openai-sdk
- Make URL longer when tools are defined (32 random characters, yet, still public!)
- Use frontmatter syntax to define MCPs to use and optional profile (used as suffix to user-id)

<!-- If I have this, it's becomes the best new way to easily test new MCPs. -->

## 2) Stateful chat completions with callbacks

<!-- Valuable research/preparation for Parallel. Also needed to separate auth UI from model response. Separating UI from model response opens the door for CLIs, MCP QA Testing & Monitoring, MarkdownOps, and much more! -->

- Allow for long-running MCP tools (in the same way as [this SEP](https://github.com/modelcontextprotocol/modelcontextprotocol/issues/1391)) - this makes this stateful though so may need to be done in a different place!
- Ability to hold running the API waiting for a human to authorize, then continue fulfilling the request after that's solved. Potentially, a parameter `onUserMessage:(details)=>Promise<void>` could be added, which would send the authorization request (just an url and message) to that endpoint, with the same secret. That function could then send email, w'app, or notify in UI. Anything.
- Expose chat completions as async MCP tool with oauth (basically a sub-agent!)

## openrouter demo

- Duplicates https://openrouter.ai/chat but only minimal features of selecting models
- Adds modal to add MCPs

## Other useful exploration

- Build in the same url expansion with different configuration (all urls or urls with prefix @) and IDP.
- Allow simplifying the response into text-only (reduce from reasoning, error messages, tool data, etc etc)
- Build a CLI that has the frontmatter
- A tool to search MCPs and continue the chat with different MCPs

## Skill router

This may not need to be something fully chained to the chat completions endpoint, but definitely a great thing to offer as well. A company should be able to list all their tools centrally so all employees can use all tools every prompt. A pre-selector prompt can do this.

Questions:

- How do we create a platform in which it's easy for companies to assign which users are their employees?
  - X: See X company and who got added (expensive, not everyone has it)
  - Email: see if people use company email (e.g. `@parallel.ai`)
  - Slack: everyone who's in Slack arguably is inside of the org.
- Do we need to let users be approved/invited into an org, or can the skill routing configuration be made public? May be more POC to be public. Also has benefits.

TODO:

- Create a super simple template for parallel

## Parallel:

- Create Integration-friendly Task API with MCP IDP built-in (by passing stable `user: string` ID) that instantly responds with a markdown-URL and JSON-URL on which the result will be able to be found without auth (`store:true` indefinitely, `store:false` for 24 hours)
- Create task API as chat completions endpoint.
