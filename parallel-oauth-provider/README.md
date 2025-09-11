This minimal OAuth provider:

1. **Stateless except for temporary KV storage** - Only stores the API key for 10 minutes in KV during the auth flow
2. **Uses localStorage** - Saves the API key in the browser for convenience on repeat visits
3. **Simple flow**:
   - `/authorize` shows a clean form asking for API key
   - User enters API key, it gets stored in KV with a temporary auth code
   - `/token` exchanges the auth code for the API key and deletes it from KV
4. **Proper OAuth compliance** - Includes all the required metadata endpoints
5. **Clean UI** - Minimal, focused design with the Parallel logo and proper styling

To use it in your Cloudflare Worker:

```
npm i parallel-oauth-provider
```

```js
import { parallelOauthProvider } from "parallel-oauth-provider";

export default {
  async fetch(request, env) {
    const oauthResponse = await parallelOauthProvider(request, env.KV);
    if (oauthResponse) return oauthResponse;

    // Your other routes...
  },
};
```

See [demo](demo.ts) in combination with [index.html](index.html)

The user just needs to get their API key from the Parallel dashboard and enter it once - it'll be remembered in localStorage for future use.

# TODO

- Ensure kv doesn't create eventual consistency problems. If so, switch to DO.
- It may be easier to host this at `mcp-oauth.parallel.ai` and use in conjunction with `simplerauth-client`. This way, it's just a matter of switching the oauthHost to `mcp-oauth.parallel.ai`.
- Get it to work with mcp.agent-friendly.com (now having problem with cache)
- Get it to work with `npx @modelcontextprotocol/inspector`
