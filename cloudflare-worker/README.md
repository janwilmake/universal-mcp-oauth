If you pass any URL, we need to use the MCP-standardized way of discovering oauth. If possible, direct user to signup/login with client. Credentials should be stored in central store. This in itself is super valuable and should be plugable into any website.

https://universal.simplerauth.com

# TODO

- ✅ Exchange https://github.com/janwilmake/simplerauth-provider with https://github.com/janwilmake/x-oauth-client-provider
- ✅ Test adding servers, see if it works here too
- ✅ Create a separate HTML with a directory of supported MCPs so we can use click-to-login, not having to fill the url per-se
- ✅ Ensure removing the provider again works too
- In `handleMCPLogin`, perform "initialization" request: https://letmeprompt.com/rules-httpsuithu-xupwz10?key=result
- After that, combine it with a allowing for non-authenticated MCP servers too; we should be able to connect with HTTP and see if connection could be established.
- Find a way to make `universal-mcp-oauth` very pluggable so people can make apps with this pattern more easily
- Where I want it the most: in LMPIFY with XYText interface! And to be able to toolcall.

# Use AI SDK?

Q: How does the AI SDK spec work and compare to other specs? might learn a lot from looking at custom providers

https://uithub.com/vercel/ai/tree/main/packages/provider/src/language-model/v2?lines=false
https://ai-sdk.dev/docs/foundations/providers-and-models

This could be a great integration.
