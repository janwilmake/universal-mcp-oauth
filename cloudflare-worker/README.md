If you pass any URL, we need to use the MCP-standardized way of discovering oauth. If possible, direct user to signup/login with client. Credentials should be stored in central store. This in itself is super valuable and should be plugable into any website.

https://universal.simplerauth.com

# TODO

- ✅ Exchange https://github.com/janwilmake/simplerauth-provider with https://github.com/janwilmake/x-oauth-client-provider
- ✅ Test adding servers, see if it works here too
- Create a separate HTML with a directory of supported MCPs so we can use click-to-login, not having to fill the url per-se
- Retrieve MCP server metadata (tools, logo, title, description). If this couldn't be done after successful login, have a way to log error
- Ensure removing the provider again works too
- After that, combine it with a allowing for non-authenticated MCP servers too; we should be able to connect with HTTP and see if connection could be established.
- This whole thing should be included by default into my boilerplate (but using `xmoney-provider`) and never need .env anymore for anything - instead, user logs in into any paid APIs. At least, this must be a possibility.

Q: How does the AI SDK spec work and compare to other specs? might learn a lot from looking at custom providers

https://uithub.com/vercel/ai/tree/main/packages/provider/src/language-model/v2?lines=false
https://ai-sdk.dev/docs/foundations/providers-and-models

This could be a great integration.
