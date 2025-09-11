# ADR

## Parallel OAuth provider

1. I can use any third-party oauth providers to get a verified email from the user.
2. I can use the accounts-service (see `openapi.json` and chat Mv) to turn an email into an access token, after which I can create/find an org and onboard the user to. This gives me the available access tokens and ability to create another.
3. After the third-party OAuth flow, my parallel oauth provider should allow the user to select an API key or create a new one. This is the preferred flow for developer flows. Besides this, there could also be a quick action "Use custom key for {hostname}" to create or select the api key with a label that matches the client hostname..

Context - https://github.com/janwilmake/simplerauth-provider

# Faster intermediate way to do it (that doesn't require internal access - meaning it can be a fully community-based provider)

- Get verified X user
- Just like Cloudflare Simplerauth, have dialog to to select or add API key, which will provide it back there.

# TODO

Work towards parallel oauth provider

- Ensure `github-oauth-provider` works with `simplerauth-client` in the same way as `x-oauth-provider`. The spec must be exactly the same. Extrahere `simplerauth-provider-specification.md` document that summarizes it in RFC-style, and also turn that into an `simplerauth-provider.openapi.json`.
- If that works, do the same for `parallel-oauth-provider`. Here, maybe, we want to host the `github-oauth-provider` ourselves too (custom client), at `gh.p0web.com`. Then, 'login with Parallel' is fully Parallel branded. To make it fully trustworthy, `parallel-web` needs to be the one creating the OAuth Client.

✅ IDEA: No github oauth needed at all! Just a super minimal oauth flow that asks to fill in an API key and links/instructs to where to get one. It can just store the key in localStorage and show date, and allow naming it (optional). The /token endpoint directly passes back the provided API key. This allows using Parallel MCP anywhere. Since this doesn't rely on github, DO THIS FIRST.

First usecase for this would be to have the same parallel search mcp but with oauth: mcp-with-oauth.parallel.ai. This results in parallel search MCP to be able to be submitted to all kinds of directories that require oauth.
