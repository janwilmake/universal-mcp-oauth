# Goals

1. Specify required implementation for MCP-compatible Dynamic client regiration
2. With that, Create a generic package that can easily be added to any Cloudflare Worker to allow the user to login to any website that supports this protocol.
3. Follow best practices of MCP [Authorization](https://modelcontextprotocol.io/specification/2025-06-18/basic/authorization#dynamic-client-registration) and [Security](https://modelcontextprotocol.io/specification/2025-06-18/basic/security_best_practices)

Example usecases include:

- A MCP client where the user can add an MCP by URL that then redirects the user to login (if needed).
- A URL-based context editor that allows any URL, but if URL hosts allow for login, instruct user to login
- Any other client where you want to support thousands of integrations without any maintenance.

Discuss

- https://x.com/janwilmake/status/1954128444758864160
- https://x.com/janwilmake/status/1953858441740513390

# Required Context

Any implementation should leverage rfc8414 and rfc7591 to

1. Find info about if and how to oauth
2. Register a client to get a client_id (and maybe secret)
3. Since getting a logo, name, and description of the provider its not part of these specs, the implementation should fetch root of the same hostname, with accept text/html, and then, parse html to get title, icon and meta description

Spec used:

- `/.well-known/oauth-authorization-server`: https://www.rfc-editor.org/rfc/rfc8414.txt
- `/register`: https://www.rfc-editor.org/rfc/rfc7591.txt

Not used:

- `/.well-known/oauth-protected-resource`: https://www.rfc-editor.org/rfc/rfc9728.txt

Prompts:

- HTML Client implementation: https://letmeprompt.com/rules-httpsuithu-6btu890
- Cloudflare Worker implementation: https://letmeprompt.com/rules-httpsuithu-xtjor90

# Implementations

- [html client](index.html)
- [cloudflare worker client with DO storage](cloudflare-worker)

# Related work

- https://github.com/janwilmake/xmoney-provider
- https://github.com/janwilmake/simplerauth-provider (for any hostname, we should be able to check whether or not we can register with dynamic client registration, and what the authorize URL is)
