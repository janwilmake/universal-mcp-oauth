I want to create a similar oauth provider as the parallel-oauth-provider that makes it fully MCP compliant. I will host it at openrouter.simplerauth.com. this will allow any mcp to get an open router api key with a budget.

openrouter oauth provider:
https://openrouter.ai/docs/use-cases/oauth-pkce.md
https://openrouter.ai/docs/api-reference/authentication/exchange-authorization-code-for-api-key.md
https://openrouter.ai/docs/api-reference/api-keys/get-current-api-key.md

https://uithub.com/janwilmake/parallel-mcp/tree/main/parallel-oauth-provider

unlike the parallel-oauth-provider, this provider should redirect to open router and provide the created key 1:1. the budget is already handled by open routers provider flow. there needs not be any UI, since the open router provider is sufficient , we just proxy to it and add the required endpoints for MCP
