# Moonshot: IdP-chat-completions proxy!!!

- oauth client & provider with X Login and usage-based stripe balance
- regular `/chat/completions with { tools: {type:"mcp",url:"MCP URL"}[], user: "stable-user-id" }`
- proxy to provider that supports MCP
- `/mcp` that responds with markdown result
- This server manages auth of users. If a tool requires auth, chat-completions endpoint would return 401 with message and custom header. MCP would respond with login info markdown in the response directly.

This is huge because it allows any app using `/chat/completions` to use infinite MCPs. A bonus would be to provide a configuration to allow specifying the MCPs as part of the input message! Same goes for URLs inside of the input message, ultimately that should also be possible.
