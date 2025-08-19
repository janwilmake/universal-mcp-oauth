# August 13, 2025

- ✅ Exchange https://github.com/janwilmake/simplerauth-provider-test with https://github.com/janwilmake/x-oauth-client-provider
- ✅ Test adding servers, see if it works here too
- ✅ Create a separate HTML with a directory of supported MCPs so we can use click-to-login, not having to fill the url per-se
- ✅ Ensure removing the provider again works too
- ✅ Researched and found the proper flow for mcp oauth (which can also be used for regular oauth!)
- ✅ Improve this by adopting https://uithub.com/janwilmake/universal-mcp-oauth/tree/main/mcp-client-server-registration
- ✅ Find a way to make `universal-mcp-oauth` very pluggable so people can make apps with this pattern more easily.
- ✅ Create parallel recipe for tasks that use MCPs ([parallel-tool-calling](examples/parallel-tool-calling/))
- ✅ Test for examples, fix 404: `Token exchange failed: MCP server request failed: 404`. Update README about limitations

# TODO

- Update the discovery mechanism to draft: https://letmeprompt.com/current-httpsmod-v4jrsv0.
- Client needs additional check to `.well-known` if www-authenticate wasn't provided: https://github.com/modelcontextprotocol/modelcontextprotocol/issues/985
- See why it's slow, potentially since we don't close the initialization automatically after the first message got back.
- Add refresh mechanism for a token (if needed).
- Test against anthropic MCP api
- Test task creation with frontend polling. Fix errors - `{"type":"error","error":{"ref_id":"51f78b52-913c-4198-ad65-eeb176ad6972","message":"Run failed.","detail":null}}`
- After it works, start testing tasks with MCPs and start talking about it!
- Understand problems with current implementation (https://letmeprompt.com/httpsmodelcontext-o5keiu0)
  - Add token audience validation
  - Add refresh token rotation. figure out the best way to do this
    - maybe adding a proxy (/mcp/proxy/{url}) that performs refresh if token is expired will be best?
    - maybe just expose a function `refreshTokenIfNeeded(provider)` or even `stub.getFreshProviders(mcpUrls:string[]):Promise<MCPProvider[]>`
- Add tool indexation to providers table
- Allow user to set specificity when doing a task
- Create Integration-friendly Task API with MCP IDP built-in
