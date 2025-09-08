# Next time universal-mcp-oauth

- Fix selection of tools to actually make a different cURL.

https://cookbook.openai.com/examples/agents_sdk/app_assistant_voice_agents

After it works, start testing tasks with MCPs and start talking about it!

- Add refresh token rotation. figure out the best way to do this
  - maybe adding a proxy (/mcp/proxy/{url}) that performs refresh if token is expired will be best?
  - maybe just expose a function `refreshTokenIfNeeded(provider)` or even `stub.getFreshProviders(mcpUrls:string[]):Promise<MCPProvider[]>`
- Understand problems with current implementation (https://letmeprompt.com/httpsmodelcontext-o5keiu0)
- Create Integration-friendly Task API with MCP IDP built-in (by passing stable `user: string` ID) that instantly responds with a markdown-URL and JSON-URL on which the result will be able to be found without auth (`store:true` indefinitely, `store:false` for 24 hours)

Interesting to read: https://blog.cloudflare.com/zero-trust-mcp-server-portals/ (shared by https://x.com/G4brym/status/1960654316781306069)
