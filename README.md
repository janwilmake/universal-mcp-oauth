# Goals

1. Specify required implementation for MCP-compatible Dynamic client regiration
2. With that, Create a generic package that can easily be added to any Cloudflare Worker to allow the user to login to any website that supports this protocol.

Example usecases include:

- A MCP client where the user can add an MCP by URL that then redirects the user to login (if needed).
- A URL-based context editor that allows any URL, but if URL hosts allow for login, instruct user to login
- Any other client where you want to support thousands of integrations without any maintenance.

# Domain-based oauth

Domain-based OAuth -> Will allow using different MCPs with easy sign-in, but also URL fetching.

If you pass any URL, we need to use the MCP-standardized way of discovering oauth. If possible, direct user to signup/login with client. Credentials should be stored in central store. This in itself is super valuable and should be plugable into any website.
