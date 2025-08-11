If you pass any URL, we need to use the MCP-standardized way of discovering oauth. If possible, direct user to signup/login with client. Credentials should be stored in central store. This in itself is super valuable and should be plugable into any website.

https://universal.simplerauth.com

# TODO

- ✅ Exchange https://github.com/janwilmake/simplerauth-provider with https://github.com/janwilmake/x-oauth-client-provider
- ✅ Test adding servers, see if it works here too
- ✅ Create a separate HTML with a directory of supported MCPs so we can use click-to-login, not having to fill the url per-se
- ✅ Ensure removing the provider again works too
- ✅ Researched and found the proper flow for mcp oauth (which can also be used for regular oauth!)
- Improve this by adopting https://github.com/janwilmake/universal-mcp-oauth/tree/main/mcp-client-server-registration
- Find a way to make `universal-mcp-oauth` very pluggable so people can make apps with this pattern more easily

# Use AI SDK?

Q: How does the AI SDK spec work and compare to other specs? might learn a lot from looking at custom providers

https://uithub.com/vercel/ai/tree/main/packages/provider/src/language-model/v2?lines=false
https://ai-sdk.dev/docs/foundations/providers-and-models

This could be a great integration.
