This demo exposes an MCP that uses X as OAuth Provider.

It can be tested locally:

- In `x-oauth-provider`, run `wrangler dev --env localhost` (exposes x oauth provider proxy on port 8787)
- Here, run `wrangler dev` to expose the MCP at http://localhost:3000/mcp
- In a third terminal, run `npx @modelcontextprotocol/inspector` to open the MCP inspector.

![](demo.drawio.png)

DEMO:

![](demo.gif)
