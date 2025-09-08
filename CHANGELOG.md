# Changelog

## 2025-06-27

Initial implementation based on GitHub OAuth client-provider pattern.

- ✅ Add `withSimplerAuth(handler,config?:{scope?:string})` fetch wrapper to have a one-liner that logs in if unauthenticated and passes user simple user-do access to ctx.
- ✅ Create minimal demo `withSimplerAuth`
- ✅ X OAuth 2.0 PKCE flow implementation
- ✅ Domain-based client identification (no registration required)
- ✅ MCP-compliant OAuth 2.0 server metadata endpoints
- ✅ Encrypted access token storage using Durable Objects
- ✅ Support for both direct login and OAuth provider flows

## 2025-08-15

- ✅ Turn users into a table
- ✅ Add multistub and queryable-object and enable admin login

## 2025-08-16

- 🤔 Figure out if we should require a unique access_token per client-id (since we may wanna reuse it directly for api calls, it makes sense) **yes we do**
- ✅ Improved structure and README of this repo. A lot.
- ✅ Make admin truly read-only
- ✅ Create a new table `logins` that holds the access_token. Store x_access_token on the users, but access_token on the logins.
- ✅ Update datastructure
  - Create a new table `logins` that holds the access_token. Store x_access_token on the users, but access_token on the logins.
  - Ensure the access-token encodes and encrypts `user_id` as well as the `client_id` plus the x access token.
  - access*token format is of format `simple*{encrypted_data}` where the decrypted is in format`user_id:client_id:token`to keep it short. encrypted with `env.X_CLIENT_SECRET`. Now, each client has a different access tokens for each user, and there can be as many as required.
  - For all DO functions that affect either the logins or users table, use `user:${user_id}` for DO name. we can decrypt the access token to know the user_id
  - no backwards compatibility required
- ✅ Every new login would create a new unique login! To not overwrite other devices.
- ✅ Keep track of created at, updated at, and request_count in logins!!! Super valueable stats. The logic should be as follows:
  - upon /callback, set last_active_at.
  - when calling /me, if last_active_at is more than an hour old but less than 4 hours old, only update last_active_at. if last_active_at is more than 4 hours old, increment session_count (there was inactivity for >3 hours)
- ✅ Client needs `withSimplerAuth` implementation that uses arbitrary address for token exchange, not X.
- ✅ Change registered scopes in `simplerauth-client` to just `profile` (standard)

# 2025-08-18

- ✅ Change to use `simplerauth-client` in `universal-oauth-provider`
- ✅ Improve `simplerauth-client` so localhost development 'just works' (But is this secure to open up?) `Invalid client_id: must be a valid domain`. For localhost, getting invalid grant. Test `basedpeople` locally.
  - ✅ Added check to `env.PORT` and header check to see if ip is localhost loopback ip
  - ✅ Fixed client to set temporary cookies for redirect_uri and redirect_to to ensure we can send them to the token endpoint
- 🤔 Specifically for basedpeople, doing a request to `ctx.user` every time makes this worker twice as expensive. Kinda wasteful, but is that important? Maybe, a cache to `/me` can be made configurable? Seems exessive to fetch it every time **Skip for now since this also tracks the user, which is something we want**
- ✅ Create `@wilmakesystems` account with more subtle profile picture, and align the logo with that, so login comes over more trustworthy. **Actually it wasn't needed since it doesn't change anything, but it's good to have a separate account for login so it won't get banned easily. I can now get 'basic' on janwilmake and experiment on that account while keeping this stable**

# 2025-08-19

AMBITION - SOLVE OAUTH ONCE AND FOR ALL! Use this by default unless specificaly disabled (flaredream).

- ✅ If it's easy enough, change to use this login in `markdownfeed`
- ✅ Add configuration `allowedClients` to restrict which clients can authorize.
- ✅ Test markdownfeed MCP with https://mcp.p0web.com. The problem now is that I don't hit 401 because the initialize endpoint is public. How do I tell `withMcp` that authorization is required? Is there a way in MCP authorization to make it optional? How should clients implement optional oauth? **Not possible** there seems no way currently to have an optional oauth requirement. You either make the server public or authenticated!
  - ✅ Make `withMcp` config to respond with 401 with `www-authorize` by proxying the response to a provided endpoint, e.g. `/me`. This one should be compliant, moving the auth compliance one level down.
  - ✅ Confirm new `withMcp` works in markdownfeed
- ✅ Confirm it's secure and complies with https://modelcontextprotocol.io/specification/draft/basic/authorization.
  - ✅ Added PCKE check and resource check to client, making it work with localhost too
  - ✅ Fix resource audience validation in provider: https://letmeprompt.com/rules-httpsuithu-nwbujx0
  - ✅ Also hold my implementation against https://modelcontextprotocol.io/specification/2025-06-18/basic/security_best_practices
  - ✅ Put a LMPIFY prompt in readme that shows it's all good.

# 2025-08-31

_Hostname-as-Client-ID Principle Discussion_

https://tailscale.com/blog/dynamic-client-registration-dcr-for-mcp-ai

Proposal to have separate domain-hosted document with client information - https://github.com/modelcontextprotocol/modelcontextprotocol/issues/991

✅ Submitted discussion about DCR security: https://github.com/modelcontextprotocol/modelcontextprotocol/discussions/1405

_Create MCP-compatible OAuth Flow Test_

✅ It'd be great to have a UI myself too for this as part of `universal-mcp-oauth`. Similarly, can be all purely front-end. Let's host it at https://mcp.agent-friendly.com.

If I'm not logged in at https://login.wilmake.com, the flow at https://login.wilmake.com works fine, https://markdownfeed.com works fine as well, but from any MCP client using `universal-mcp-oauth`, it will show `You weren’t able to give access to the App. Go back and try logging in again.`. What is the difference here? The login flow from a client in `simplerauth-client` doesn't work it seems.

FINE https://x.com/i/oauth2/authorize?response_type=code&client_id=MWlyVUFQWm5fN01qWTlnaVlBbmY6MTpjaQ&redirect_uri=https%3A%2F%2Flogin.wilmake.com%2Fcallback&scope=users.read+tweet.read+offline.access&state=eyJyZWRpcmVjdFRvIjoiL2F1dGhvcml6ZT9jbGllbnRfaWQ9bWFya2Rvd25mZWVkLmNvbSZyZWRpcmVjdF91cmk9aHR0cHMlM0ElMkYlMkZtYXJrZG93bmZlZWQuY29tJTJGY2FsbGJhY2smcmVzcG9uc2VfdHlwZT1jb2RlJnNjb3BlPXByb2ZpbGUmcmVzb3VyY2U9aHR0cHMlM0ElMkYlMkZtYXJrZG93bmZlZWQuY29tJmNvZGVfY2hhbGxlbmdlPWsyUFJ6Vi1BR2NIRVBmYWQ2MmwyRWZmM3phUVZPdkswQmZIN1cyMWppQlUmY29kZV9jaGFsbGVuZ2VfbWV0aG9kPVMyNTYiLCJjb2RlVmVyaWZpZXIiOiI4RWhFNE90YXpWeTJlQW9PTHp1OUg3a1JkWlRqWllBNUI3YUNIREQ1YXdZIiwicmVzb3VyY2UiOiJodHRwczovL21hcmtkb3duZmVlZC5jb20ifQ%3D%3D&code_challenge=wAdD9_ORfPEtsjYc0q3vDEc3O1XC6xnGs8SI7ZCT2so&code_challenge_method=S256

(<500)

NOT FINE https://x.com/i/oauth2/authorize?response_type=code&client_id=MWlyVUFQWm5fN01qWTlnaVlBbmY6MTpjaQ&redirect_uri=https%3A%2F%2Flogin.wilmake.com%2Fcallback&scope=users.read+tweet.read+offline.access&state=eyJyZWRpcmVjdFRvIjoiL2F1dGhvcml6ZT9yZXNwb25zZV90eXBlPWNvZGUmY2xpZW50X2lkPW1jcC5wMHdlYi5jb20mcmVkaXJlY3RfdXJpPWh0dHBzJTNBJTJGJTJGbWNwLnAwd2ViLmNvbSUyRm1jcCUyRmNhbGxiYWNrJTJGbWFya2Rvd25mZWVkLmNvbSZyZXNvdXJjZT1odHRwcyUzQSUyRiUyRm1hcmtkb3duZmVlZC5jb20lMkZtY3AmY29kZV9jaGFsbGVuZ2U9d1VSeTVIQ0tHSUVrUDN4dDdxZzBJNlZrVHVDa0xBcDI2VGRsaFQyRk9fOCZjb2RlX2NoYWxsZW5nZV9tZXRob2Q9UzI1NiZzdGF0ZT16Y2dpUFVocVVBUVhocFBVc05Oc0dBIiwiY29kZVZlcmlmaWVyIjoieWdULWtmM0xXNmRXalZTLWRqYk5EcWxlT2VZUWVXc09fR1hCcEM4VGpBVSIsInJlc291cmNlIjoiaHR0cHM6Ly9tYXJrZG93bmZlZWQuY29tL21jcCJ9&code_challenge=8cYhMFdEomiziZFriv_ib7Ugi5smJYs9sSrGeCQRMv8&code_challenge_method=S256

(>500 characters)

The problem seems to be that there's a max length of 500 characters to the state param.

✅ Solved by removing redirect_to from encoded state and putting that in a cookie instead
