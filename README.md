> [!WARNING]
> Please note: This repo consists of many smaller modules that can be used independently
>
> Be advised: While some are stable and of high-quality, others are in active development and may still be buggy.
>
> Truly experimental modules and community modules are not part of this repo but are kept track of in [this list](https://github.com/stars/janwilmake/lists/simpler-auth). Please [DM Me](https://x.com/janwilmake) if you have built a new Simpler Auth Module so I can add it!

# What is this?

This library lets your users login with any arbitrary MCP server trhough discovery, dynamic registration, authentication, authorization, and credential management.

# Goals

1. Specify required implementation for MCP-compatible Dynamic client registration that follows best practices of MCP [Authorization](https://modelcontextprotocol.io/specification/2025-06-18/basic/authorization#dynamic-client-registration) and [Security](https://modelcontextprotocol.io/specification/2025-06-18/basic/security_best_practices)

2. With that, Create a generic package that can easily be added to any Cloudflare Worker to allow the user to login to any website that supports this protocol.

Example usecases include:

- A MCP client where the user can add an MCP by URL that then redirects the user to login (if needed).
- A URL-based context editor that allows any URL, but if URL hosts allow for login, instruct user to login
- Any other client where you want to support thousands of integrations without any maintenance.

Discuss

- https://x.com/janwilmake/status/1954128444758864160
- https://x.com/janwilmake/status/1953858441740513390

# About CORS

The MCP Spec doesn't say anything about CORS implementation. Because of this, some MCP servers won't allow all origins, limiting browser implementations from functioning. Implementations like [Claude.ai](https://claude.ai) require frontend-based discoverability, but it's unclear if the registration should also be able to be done from browser-based clients. In the [HTML Client](examples/html-client/) example, I assume the well known files as well as DCR are able to be performed through the browser. Some servers won't allow for this, and it's not clear if this is intended. For a backend-based implementation (that does not encounter this problem) check [Cloudflare Worker Client](examples/cloudflare-worker/)

For more info, see https://letmeprompt.com/specs-well-known-9nx2ll0

# Used Context

Any implementation should leverage rfc8414 and rfc7591 to:

1. Find info about if and how to oauth
2. Register a client to get a client_id (and maybe secret)

Specs:

- `/.well-known/oauth-authorization-server`: https://www.rfc-editor.org/rfc/rfc8414.txt
- `/.well-known/oauth-protected-resource`: https://www.rfc-editor.org/rfc/rfc9728.txt
- `/register`: https://www.rfc-editor.org/rfc/rfc7591.txt
- MCP: https://uithub.com/modelcontextprotocol/modelcontextprotocol/blob/main/schema/2025-06-18/schema.ts
- MCP Authorization https://modelcontextprotocol.io/specification/2025-06-18/basic/authorization.md
- MCP Security https://modelcontextprotocol.io/specification/2025-06-18/basic/security_best_practices.md

Prompts:

- HTML Client implementation: https://letmeprompt.com/rules-httpsuithu-6btu890
- Cloudflare Worker implementation: https://letmeprompt.com/rules-httpsuithu-xtjor90
- Initialization request: https://letmeprompt.com/rules-httpsuithu-xupwz10
