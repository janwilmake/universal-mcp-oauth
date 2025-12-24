This demo exposes an MCP that uses X as OAuth Provider without having to configure any environment variables, and without having to pre-register any clients. In other words, this allows **secretless authorizable MCP servers**.

![](demo.drawio.png)

It can be tested locally:

- In `x-oauth-provider`, run `wrangler dev --env localhost` (exposes x oauth provider proxy on port 8787)
- Here, run `wrangler dev` to expose the MCP at http://localhost:3000/mcp
- In a third terminal, run `npx @modelcontextprotocol/inspector` to open the MCP inspector.
- To demonstrate our registration flow is functional as well, you can test [html-client](../html-client/) using `wrangler dev` (exposes browser-client on 3001 that performs oauth flow)

Remotely, it should work the same:

- fill in https://mcpdemo.wilmake.com/mcp at https://mcp.agent-friendly.com

DEMO:

![](small.gif)
