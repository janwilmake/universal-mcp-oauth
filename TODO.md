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

# August 19, 2025

- ✅ Improved UI of https://mcp.p0web.com, a lot

# Late August 2025

- ✅ `universal-mcp-oauth`
  - ✅ Update discovery mechanism to draft: https://letmeprompt.com/current-httpsmod-v4jrsv0?key=result
  - ✅ Client needs additional check to `.well-known` if www-authenticate wasn't provided: https://letmeprompt.com/can-you-summarize-wh-8mi4ai0?key=result
  - ✅ For text/event-streams, close the initialization automatically after the required message came back, don't wait for more. Same goes for `tools/list`.
  - ✅ `tools/list` function: https://letmeprompt.com/httpsmodelcontext-ap04440?key=result
  - ✅ Upon authorization, list all tools and store these into the DB as well, and return along with servers from the getProviders function. NB: tools can just be a JSON blob, no table needed
- ✅ `worker.ts & homepage.html`
  - ✅ In HTML, when selecting MCPs, allow deselecting tools as well (all selected by default). the tools are available in the providers.
  - ✅ Put the curl generation in frontend (selection mechanism should update curl)
  - ✅ make curl for anthropic messages API as well (uses mcp_servers prop) (make that secondary curl upon selection)
  - ✅ Allow choosing processor and output text or auto (for simplicity, for now) - see https://docs.parallel.ai/api-reference/task-api-v1/create-task-run.md
  - ✅ ensure to adopt userData.apiKey (remove userData.hasApiKey)

# Goal This Weekend - Fix MCP login

✅ Added ability to develop `simplerauth-client` + `x-oauth-provider` on localhost (refactor secure flag and url.origin)

🤔 Now, simplerauth-client successfully works as client, but also must be a valid provider for an MCP server! This part is still untested and we must be able to test this **fully locally**. The provider will be at http://localhost:3000

Successfully go through Entire OAuth flow with SimplerAuth Client, be able to have the Claude.ai client log into Markdownfeed MCP, Curl MCP, OpenAPI MCP Server. Host these all!

❗️ Now, I'm getting: `{"error":"invalid_token","error_description":"Token not found or expired"}` for `/authorize` if done from https://mcp.p0web.com. Am I calling the endpoint correctly? Go over the code here.

Let's look in the database if things are done correctly and if every error is logged.

Use latest X OAuth provider at `markdownfeed`. Confirm `x-oauth-provider` is complete and functional now. Test it with `npx @modelcontextprotocol/inspector` and https://mcp.agent-friendly.com

🔥🔥🔥🔥 After I have this.... I can finally ship MCPs with login. Add `withMcp` to `flaredream-user-worker` and start shipping `agent-friendly` workers. 🔥🔥🔥🔥

# Create X MCP?

Using [live search](https://docs.x.ai/docs/guides/live-search) is possible: https://x.com/janwilmake/status/1964663032631431556?

Otherwise, we're stuck with $200/month limit and may need to discontinue that at a later point due to excessive cost.

Other option is go down the path of https://twitterapi.io

Other option is https://scrapecreators.com/twitter-api but only returns top 100 most popular tweets it says

Other option is using SERPER and date filters.

OR FIND BETTER REDDIT MCP.

# Next time

- Fix selection of tools to actually make a different cURL.

https://cookbook.openai.com/examples/agents_sdk/app_assistant_voice_agents

After it works, start testing tasks with MCPs and start talking about it!

- Add refresh token rotation. figure out the best way to do this
  - maybe adding a proxy (/mcp/proxy/{url}) that performs refresh if token is expired will be best?
  - maybe just expose a function `refreshTokenIfNeeded(provider)` or even `stub.getFreshProviders(mcpUrls:string[]):Promise<MCPProvider[]>`
- Understand problems with current implementation (https://letmeprompt.com/httpsmodelcontext-o5keiu0)
- Create Integration-friendly Task API with MCP IDP built-in (by passing stable `user: string` ID) that instantly responds with a markdown-URL and JSON-URL on which the result will be able to be found without auth (`store:true` indefinitely, `store:false` for 24 hours)

Interesting to read: https://blog.cloudflare.com/zero-trust-mcp-server-portals/ (shared by https://x.com/G4brym/status/1960654316781306069)
