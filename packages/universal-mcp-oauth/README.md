Usage in any cloudflare project:

```ts
import { createMCPOAuthHandler, MCPProviders } from "universal-mcp-oauth";
export { MCPProviders } from "universal-mcp-oauth";
// In your worker
const mcpHandler = createMCPOAuthHandler({ userId: "user123" });
const response = await mcpHandler(request, env, ctx);
```
