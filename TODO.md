# TODO

- ✅ Exchange https://github.com/janwilmake/simplerauth-provider with https://github.com/janwilmake/x-oauth-client-provider
- ✅ Test adding servers, see if it works here too
- ✅ Create a separate HTML with a directory of supported MCPs so we can use click-to-login, not having to fill the url per-se
- ✅ Ensure removing the provider again works too
- ✅ Researched and found the proper flow for mcp oauth (which can also be used for regular oauth!)
- ✅ Improve this by adopting https://uithub.com/janwilmake/universal-mcp-oauth/tree/main/mcp-client-server-registration
- ✅ Find a way to make `universal-mcp-oauth` very pluggable so people can make apps with this pattern more easily.
- Understand problems with current implementation (https://letmeprompt.com/httpsmodelcontext-o5keiu0)
  - add token audience validation
  - add refresh token rotation. figure out the best way to do this
    - maybe adding a proxy (/mcp/proxy/{url}) that performs refresh if token is expired will be best?
    - maybe just expose a function `refreshTokenIfNeeded(provider)` or even `stub.getFreshProviders(mcpUrls:string[]):Promise<MCPProvider[]>`
- Create parallel recipe for MCP tasks ([parallel-tool-calling](../parallel-tool-calling/))
