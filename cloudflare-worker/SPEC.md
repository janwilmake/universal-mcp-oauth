RULES:
https://uithub.com/janwilmake/gists/tree/main/named-codeblocks.md

PROMPT:
https://uithub.com/janwilmake/universal-mcp-oauth?lines=false
https://uithub.com/janwilmake/simplerauth-provider?lines=false
https://flaredream.com/system-ts.md
See this html implementation of universal-mcp-oauth. now, I want it in a Cloudflare Worker where I use provider.ts (import from other file) to get a logged in user, the user can then provide any MCP server URL to /login?url={url} after which he'll be redirected to the appropriate authorization. the callback is received at /callback/{hostname} which would perform the token exchange and put the mcp_url, hostname, access_token for the provider in a providers db table (use a durable object instance for each unique user).

Also create a utility function getAuthorization(env, url) to retrieve the authorization for any URL (looks up the provider if available in the user-db)

The landingpage / should return a simple html with a example curl for a task creation call as in https://docs.parallel.ai/features/mcp-tool-call.md that has all the logged in servers, and it should have a tiny form to fill in a mcp url and then login

is that all clear?

<!-- https://letmeprompt.com/rules-httpsuithu-xtjor90 -->
