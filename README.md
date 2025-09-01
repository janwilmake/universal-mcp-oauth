> [!WARNING]
> Work in Progress. Not fully spec-compliant yet!

# What is this?

This library lets your users login with any arbitrary MCP server trhough discovery, dynamic registration, authentication, authorization, and credential management.

# Goals

1. Specify required implementation for MCP-compatible Dynamic client registration that follows best practices of MCP [Authorization](https://modelcontextprotocol.io/specification/2025-06-18/basic/authorization#dynamic-client-registration) and [Security](https://modelcontextprotocol.io/specification/2025-06-18/basic/security_best_practices)

2. With that, Create a generic package that can easily be added to any Cloudflare Worker to allow the user to login to any website that supports this protocol.

Example usecases include:

- A MCP client where the user can add an MCP by URL that then redirects the user to login (if needed).
- A URL-based context editor that allows any URL, but if URL hosts allow for login, instruct user to login
- Any other client where you want to support thousands of integrations without any maintenance.

# Table of Contents

Packages

- [mcp-client-server-registration](packages/mcp-client-server-registration/)
- [universal-mcp-oauth](packages/universal-mcp-oauth/)

Examples

- [HTML Client](examples/html-client/) (Live at https://mcp.agent-friendly.com)
- [Cloudflare Worker Client](examples/cloudflare-worker/) (Live at https://universal.simplerauth.com)
- [Parallel Tool Calling with MCP](examples/parallel-tool-calling/) (Live at https://mcp.p0web.com)

Dependencies to examples

- [x-oauth-client-provider](https://github.com/janwilmake/x-oauth-client-provider)

Discuss

- https://x.com/janwilmake/status/1954128444758864160
- https://x.com/janwilmake/status/1953858441740513390

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
