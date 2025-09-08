## Parallel OAuth provider

1. I can use any third-party oauth providers to get a verified email from the user.
2. I can use the accounts-service (see `openapi.json` and chat Mv) to turn an email into an access token, after which I can create/find an org and onboard the user to. This gives me the available access tokens and ability to create another.
3. After the third-party OAuth flow, my parallel oauth provider should allow the user to select an API key or create a new one. This is the preferred flow for developer flows. Besides this, there could also be a quick action "Use custom key for {hostname}" to create or select the api key with a label that matches the client hostname..

Context - https://github.com/janwilmake/simplerauth-provider

# Faster intermediate way to do it (that doesn't require internal access - meaning it can be a fully community-based provider)

- Get verified X user
- Just like Cloudflare Simplerauth, have dialog to to select or add API key, which will provide it back there.
